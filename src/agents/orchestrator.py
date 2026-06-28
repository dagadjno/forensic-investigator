"""Orchestrator: the lead-queue engine.

Seeds leads (questions + coverage), then pops the highest-priority lead and spawns a
sub-agent, repeating until the queue drains and every present bucket is examined.
Run-to-completion, but with progress invariants (dedup, force-closed coverage,
depth/total caps in the tools) so it terminates.

The pick order here is a simple priority sort; an LLM override hook can slot in later.
"""
from __future__ import annotations

import time
from pathlib import Path

from ..llm.client import LLMClient
from ..store.case_db import CaseDB
from ..ui import EMOJI, c
from . import subagent

# Lead priority. Order matters for correlation: "source" buckets (where the compromise
# narrative originates, e.g. what the user typed) should run BEFORE corroborating ones
# (event logs), so later sub-agents can see earlier findings via list_findings.
_PARSED_PRIORITY = 80
_UNPARSED_PRIORITY = 30
_QUESTION_PRIORITY = 70
_BUCKET_PRIORITY = {
    # Source narrative — what the user/attacker actually did (run first).
    "Psh": 95,   # PowerShell history — what the user actually typed
    "Brw": 88,   # browser history/downloads
    # Execution & persistence.
    "Reg": 78,   # registry: persistence + user activity (part source, part corroborating)
    "Arn": 76,   # amcache: program-execution evidence
    "Sch": 74,   # scheduled tasks (persistence)
    "Ranprog": 72,  # prefetch / run-program (execution)
    # File-system & usage activity (parsed corroboration — curated rather than the 80
    # parsed-fallback, so they slot just below persistence and above raw event logs).
    "Lnk": 68,   # LNK shortcuts — files/shares opened
    "RawData": 66,  # USN journal — file create/delete/rename timeline
    "Sys": 64,   # SRUM — app + network usage history
    # Event-log corroboration — run after source buckets so earlier findings exist to tie to.
    "Evt": 55,
    # Memory — expensive on-demand Volatility (vol_run). Deliberately LAST in open-ended /
    # no-question mode so disk leads already exist to target plugins; when questions are
    # given the LLM router overrides this entirely.
    "MemDump": 25,
}


def seed(case: CaseDB, only: set[str] | None = None,
         priority_overrides: dict[str, int] | None = None) -> None:
    # Question-driven leads (primary mode).
    for q in case.questions():
        case.add_lead(title=f"Answer: {q['text']}", source="question",
                      question_id=q["id"], priority=_QUESTION_PRIORITY)
    # Coverage-driven leads — guarantee every present bucket gets a look.
    # `only` scopes which buckets are seeded; `priority_overrides` (from the question-
    # driven ranker) sets order, falling back to the static per-bucket heuristic.
    for c in case.coverage_rows():
        if not c["present"]:
            continue
        if only is not None and c["artifact"] not in only:
            continue
        if priority_overrides and c["artifact"] in priority_overrides:
            pri = priority_overrides[c["artifact"]]
        else:
            pri = _BUCKET_PRIORITY.get(c["artifact"],
                                       _PARSED_PRIORITY if c["parser"] else _UNPARSED_PRIORITY)
        case.add_lead(title=f"Explore the {c['artifact']} ({c['type']}) artifacts",
                      source="coverage", artifact=c["artifact"], priority=pri)


def run(llm: LLMClient, case: CaseDB, artifact_root: Path, kb_dir: Path,
        host: str, budgets: dict, only: set[str] | None = None,
        priority_overrides: dict[str, int] | None = None) -> None:
    reopened = case.reset_in_progress_leads()   # recover leads stuck by a prior crash
    if reopened:
        print(f"    resumed: re-opened {reopened} in-progress lead(s)", flush=True)
    seed(case, only, priority_overrides)
    safety_cap = budgets.get("max_total_leads", 60) + 50
    ceiling_s = budgets.get("max_host_minutes", 0) * 60   # 0 = no wall-clock ceiling
    t0 = time.time()
    processed = 0

    while processed < safety_cap:
        if ceiling_s and (time.time() - t0) > ceiling_s:
            print(f"  {EMOJI['clock']} {c('time ceiling reached', 'yellow', 'bold')} "
                  f"({budgets['max_host_minutes']} min); stopping with results so far "
                  f"(answers are already saved)", flush=True)
            break
        lead = case.next_lead()
        if lead is None:
            break
        case.set_lead_status(lead["id"], "in_progress")
        src_color = {"question": "yellow", "coverage": "blue", "agent": "magenta"}.get(
            lead["source"], "gray")
        print(f"  {EMOJI['lead']} {c('lead #' + str(lead['id']), 'cyan', 'bold')} "
              f"{c('[' + lead['source'] + ']', src_color)} {lead['title']}", flush=True)
        subagent.run(llm, case, artifact_root, kb_dir, lead, host, budgets)
        case.set_lead_status(lead["id"], "closed")
        # Progress invariant: a coverage lead's bucket is examined once visited.
        if lead["source"] == "coverage" and lead["artifact"]:
            case.set_coverage_status(lead["artifact"], "analyzed")
        processed += 1

    if processed >= safety_cap:
        print(f"  {EMOJI['warn']} {c('safety cap reached', 'yellow', 'bold')}; stopping "
              f"(check for runaway lead generation)")
