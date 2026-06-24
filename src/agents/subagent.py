"""Generic sub-agent: runs one lead to a conclusion in its own context.

It eats raw tool output here so the orchestrator never has to. It writes cited
findings/answers and may file new leads. Specialization is by the playbook it's
pointed at, not by code (plus a future special-cased memory agent).
"""
from __future__ import annotations

from pathlib import Path

from ..llm.base import neutral_user
from ..llm.client import LLMClient
from ..store.case_db import CaseDB
from ..tools.registry import TOOL_SCHEMAS, ToolContext, dispatch

_RULES = """You are a digital-forensics sub-agent investigating one host's triage collection.

Hard rules:
- Answer or point — NEVER guess. Every finding and every "answered" question must cite a
  locator that a tool returned to you. If you cannot read where the answer lives (an image,
  a binary), use answer_question with status="pointer" and nominate candidate files.
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
_PLAYBOOKS = {"Psh": "powershell_history", "Evt": "event_logs", "Reg": "registry"}


def _system(case: CaseDB, host: str) -> str:
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
    return f"{_RULES}\n\nHost: {host}\n{q_block}"


def run(llm: LLMClient, case: CaseDB, artifact_root: Path, kb_dir: Path,
        lead, host: str, budgets: dict) -> dict:
    ctx = ToolContext(case, artifact_root, kb_dir, lead_depth=lead["depth"], budgets=budgets)
    system = _system(case, host)

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
    max_steps = budgets.get("max_subagent_steps", 25)

    for step in range(1, max_steps + 1):
        try:
            resp = llm.complete("subagent", system, history, tools=TOOL_SCHEMAS)
        except Exception as e:
            # Don't let one lead's API failure kill the whole run; conclude this lead.
            print(f"       lead #{lead['id']} aborted after API error: {type(e).__name__}: {e}",
                  flush=True)
            break
        history.append(resp.assistant_turn)
        if resp.stop_reason != "tool_use":
            break
        results = []
        for call in resp.tool_calls:
            out, is_err = dispatch(ctx, call.name, call.input)
            flag = "ERR " if is_err else ""
            print(f"       step {step}: {flag}{call.name}({_brief(call.input)})", flush=True)
            results.append({"type": "tool_result", "tool_use_id": call.id,
                            "content": out, "is_error": is_err})
        history.append(neutral_user(results))

    return {"lead_id": lead["id"]}


def _brief(args: dict) -> str:
    parts = []
    for k, v in args.items():
        s = str(v)
        parts.append(f"{k}={s[:40] + '…' if len(s) > 40 else s}")
    return ", ".join(parts)[:120]
