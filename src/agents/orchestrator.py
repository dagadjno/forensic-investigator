"""Orchestrator: the lead-queue engine.

Seeds leads (questions + coverage), then pops the highest-priority lead and spawns a
sub-agent, repeating until the queue drains and every present bucket is examined.
Run-to-completion, but with progress invariants (dedup, force-closed coverage,
depth/total caps in the tools) so it terminates.

The pick order here is a simple priority sort; an LLM override hook can slot in later.
"""
from __future__ import annotations

from pathlib import Path

from ..llm.client import LLMClient
from ..store.case_db import CaseDB
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
    safety_cap = budgets.get("max_total_leads", 200) + 50
    processed = 0

    while processed < safety_cap:
        lead = case.next_lead()
        if lead is None:
            break
        case.set_lead_status(lead["id"], "in_progress")
        print(f"  -> lead #{lead['id']} [{lead['source']}] {lead['title']}", flush=True)
        subagent.run(llm, case, artifact_root, kb_dir, lead, host, budgets)
        case.set_lead_status(lead["id"], "closed")
        # Progress invariant: a coverage lead's bucket is examined once visited.
        if lead["source"] == "coverage" and lead["artifact"]:
            case.set_coverage_status(lead["artifact"], "analyzed")
        processed += 1

    if processed >= safety_cap:
        print("  ! safety cap reached; stopping (check for runaway lead generation)")
