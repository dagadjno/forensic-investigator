"""Generic sub-agent: runs one lead to a conclusion in its own context.

It eats raw tool output here so the orchestrator never has to. It writes cited
findings/answers and may file new leads. Specialization is by the playbook it's
pointed at, not by code (plus a future special-cased memory agent).
"""
from __future__ import annotations

from pathlib import Path

from ..llm import pricing
from ..llm.base import neutral_user
from ..llm.client import LLMClient
from ..store.case_db import CaseDB
from ..tools.registry import TOOL_SCHEMAS, ToolContext, dispatch
from ..ui import c

_RULES = """You are a digital-forensics sub-agent investigating one host's triage collection.

Hard rules:
- Answer or point — NEVER guess. Every finding and every "answered" question must cite a
  locator that a tool returned to you. If you cannot read where the answer lives (an image,
  a binary), use answer_question with status="pointer" and nominate candidate files.
- Exact tokens win: when a question asks for a filename, command, path, hash, ID, or address,
  answer with the EXACT verbatim string from the artifact — keep the file extension, the full
  command line, the full path. Do not paraphrase, normalize, abbreviate, or de-alias it.
- Multiple matches → rank, don't cherry-pick: when a question targets a TIME, a COUNT, or
  "which one" and several events plausibly qualify, do NOT silently commit to the first you
  find. Enumerate the candidates, then record the best-supported one as the primary answer
  (confidence="high" ONLY if the evidence uniquely points to it; otherwise "medium"/"low"),
  and record the other strong candidates as ADDITIONAL answer_question calls (each citing its
  own event locator). Distinct values are kept, not treated as duplicates — let the analyst
  disambiguate from a ranked set rather than guessing for them.
- "First / earliest / initial / last" → sort by TIME, not by how bad it looks: enumerate ALL
  qualifying events and order them by timestamp; "first" is the EARLIEST, "last" the LATEST —
  never the one that merely looks most malicious. The real first event (e.g. a C2 download)
  can precede the showiest one by seconds.
- Attribute to the named entity; beware decoys: when a question names an account / host / file,
  prefer the value tied to THAT entity (e.g. a credential cached via `cmdkey /add:DOMAIN\\user`,
  a logon naming the user) over a bare `$password=` / string that merely appears nearby or on a
  different host. If two plausible answers exist, record BOTH (ranked by confidence) and note the
  likely decoy — do not confidently pick the planted one.
- "First THREAT-ACTOR activity" = first attributable indicator, not first anomaly: anchor it to a
  TA-attributable event (a C2 domain/IP, a malicious binary, the attacker account), NOT to agent/
  EDR installs, system services, or routine baseline. Do not assume "earlier timestamp = baseline":
  attackers can dwell — classify by indicator, not by date distance.
- Don't blame the collector's own tools: the acquisition itself installs DFIR tooling (WinPmem /
  `pmem`, the AChoir/AChoirX collector, etc.), usually at/after collection time. Exclude these from
  "what did the ATTACKER install/run" answers — see kb_read('playbooks/acquisition_log.md') for the
  known-collector list. Only treat a tool as collector-introduced when its timing matches the
  acquisition, not the incident window.
- CTF flag markers: call find_flags early — it deterministically scans every artifact for
  planted markers (`FL4G{...}`, `btv{...}`, `flag{...}`). The text inside the braces is very
  likely the intended answer; record it via answer_question (cite the locator it returns), in
  addition to anything else you concluded. Also watch for such markers in anything you read.
- Pull only what you need (query_timeline / grep_artifact); read_file for context.
- Read the relevant playbook with kb_read before digging in.
- Before recording, call list_findings to see what other sub-agents already found. If your
  observation is already covered, add your evidence to it (same ATT&CK technique) or move on —
  do not duplicate an existing finding.
- When you have enough to act, act. Record findings/answers, then stop. Do not over-explore.
- If you spot a separate thread worth pursuing, file_lead it rather than chasing it now.
- For a coverage lead (explore an artifact bucket), examine it, record anything notable,
  resolve any questions it answers, then call mark_examined on that bucket."""


# dir-code -> playbook filename (without .md) to point the sub-agent at.
_PLAYBOOKS = {"Psh": "powershell_history", "Evt": "event_logs", "Reg": "registry",
              "Brw": "browser", "Lnk": "lnk", "RawData": "usn", "Sys": "srum",
              "MemDump": "memory", "Arn": "amcache", "Conn": "network",
              "Sch": "scheduled_tasks", "Proc": "process_listings",
              "Ranprog": "prefetch", "Rcy": "recycle_bin", "WMI": "wmi",
              "Logs": "acquisition_log",
              # stock-AChoirX dir-code aliases / new buckets (validated on AChoirX 2026)
              "Prf": "prefetch", "SYS": "srum", "ASEP": "amcache",
              "RanProg": "prefetch", "PCA": "pca"}

# Tools that count as "searching" — summarized into an auto-unresolved note if a question
# lead ends without recording any answer.
_SEARCH_TOOLS = {"query_timeline", "grep_artifact", "read_file", "list_files",
                 "mft_lookup", "vol_run", "get_raw_event"}


def _system(case: CaseDB, host: str, kb_dir: Path) -> str:
    pb_dir = kb_dir / "playbooks"
    pbs = sorted(p.stem for p in pb_dir.glob("*.md")) if pb_dir.is_dir() else []
    pb_block = (f"\nAvailable playbooks (the ONLY ones — organized by ARTIFACT, not attack "
                f"technique): kb_read('playbooks/<name>.md') where <name> is one of: "
                f"{', '.join(pbs)}.\n") if pbs else ""
    qs = case.questions()
    if qs:
        lines = []
        for q in qs:
            cur = case.question_resolved(q["id"])
            if cur:
                lines.append(f"  [{q['id']}] {q['text']}\n      current answer: {cur} "
                             f"(do NOT restate; only add a DIFFERENT or better-supported answer)")
            else:
                lines.append(f"  [{q['id']}] {q['text']}  (unanswered)")
        q_block = ("\nQuestions for this case — resolve any this lead bears on via answer_question:\n"
                   + "\n".join(lines) + "\n")
    else:
        q_block = "\nNo specific questions provided; surface anything notable as findings.\n"
    return f"{_RULES}\n\nHost: {host}\n{pb_block}{q_block}"


def run(llm: LLMClient, case: CaseDB, artifact_root: Path, kb_dir: Path,
        lead, host: str, budgets: dict) -> dict:
    ctx = ToolContext(case, artifact_root, kb_dir, lead_depth=lead["depth"], budgets=budgets,
                      origin_qid=lead["question_id"])
    system = _system(case, host, kb_dir)

    task = f"LEAD: {lead['title']}"
    if lead["reason"]:
        task += f"\nWhy: {lead['reason']}"
    if lead["source"] == "coverage" and lead["artifact"]:
        task += (f"\nThis is a coverage lead for the '{lead['artifact']}' bucket. "
                 f"Examine it and call mark_examined('{lead['artifact']}') when done.")
        pb = _PLAYBOOKS.get(lead["artifact"])
        if pb:
            task += f"\nStart by reading kb_read('playbooks/{pb}.md')."
    if lead["source"] == "question" and lead["question_id"]:
        task += f"\nFocus on resolving question [{lead['question_id']}]."

    history = [neutral_user(task)]
    max_steps = budgets.get("max_subagent_steps", 20)
    searches: list[str] = []   # what this lead actually looked at (for an honest unresolved)
    usage = pricing.blank()    # token usage accumulated across this lead's LLM calls
    aborted = False
    steps_done = 0

    for step in range(1, max_steps + 1):
        steps_done = step
        try:
            resp = llm.complete("subagent", system, history, tools=TOOL_SCHEMAS)
        except Exception as e:
            # Don't let one lead's API failure kill the whole run; conclude this lead.
            print(f"       {c('lead #' + str(lead['id']) + ' aborted', 'red')} after API error: "
                  f"{type(e).__name__}: {e}", flush=True)
            aborted = True
            break
        pricing.accumulate(usage, resp.usage)
        history.append(resp.assistant_turn)
        if resp.stop_reason != "tool_use":
            break
        results = []
        for call in resp.tool_calls:
            out, is_err = dispatch(ctx, call.name, call.input)
            tag = (c("ERR", "red", "bold") + " ") if is_err else ""
            # answer_question stands out in reddish pink; other tools stay cyan.
            name_styles = ("pink", "bold") if call.name == "answer_question" else ("cyan",)
            print(f"       {c('step ' + str(step), 'gray')}: {tag}{c(call.name, *name_styles)}"
                  f"({_brief(call.input)})", flush=True)
            if call.name in _SEARCH_TOOLS and not is_err:
                searches.append(f"{call.name}({_brief(call.input)})")
            results.append({"type": "tool_result", "tool_use_id": call.id,
                            "content": out, "is_error": is_err})
        history.append(neutral_user(results))

    _conclude_unresolved(case, lead, searches, steps_done, max_steps, aborted)
    print(f"       {c('lead #' + str(lead['id']) + ' cost', 'gray')}: "
          f"{pricing.summary(llm.model_for('subagent'), usage)}", flush=True)
    return {"lead_id": lead["id"], "usage": usage}


def _conclude_unresolved(case, lead, searches, steps_done, max_steps, aborted):
    """Safety net: a QUESTION lead that ended without recording ANY answer gets an honest
    'unresolved' (with what it searched) instead of silently going blank — so an empty
    result is distinguishable from a crashed lead."""
    qid = lead["question_id"]
    if lead["source"] != "question" or not qid or case.answers_for(qid):
        return
    if aborted:
        reason = f"Investigation aborted by an API error after {steps_done} step(s)."
    elif steps_done >= max_steps:
        reason = f"Step budget exhausted ({max_steps} steps) with no matching evidence found."
    else:
        reason = f"Concluded after {steps_done} step(s) with no matching evidence found."
    if searches:
        reason += " Searched: " + "; ".join(searches[:10])
    case.add_answer(qid, "unresolved", reasoning=reason[:1200])
    print(f"       {c('auto-unresolved', 'yellow')}: no answer recorded; logged what was searched",
          flush=True)


def _brief(args: dict) -> str:
    parts = []
    for k, v in args.items():
        s = str(v)
        parts.append(f"{k}={s[:40] + '…' if len(s) > 40 else s}")
    return ", ".join(parts)[:120]
