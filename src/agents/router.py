"""Orchestrator routing/ranking gate.

Given the investigation objective (the CTF questions, or a generic "find evidence of
compromise" goal) and the buckets present, an LLM ranks the buckets by relevance,
most-relevant first. That ranking drives two things:

- lead PRIORITY — when questions are present, ranked order sets which buckets a default
  run examines first (coverage guarantee preserved: every bucket is still examined).
- bucket SELECTION — under --relevant-only, only the ranked buckets are examined.

With no questions and no --relevant-only, this gate isn't used and the static per-bucket
priority in the orchestrator applies.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..llm.base import neutral_user

_SYS = ("You are the routing step of a forensic investigator. Given the artifact buckets "
        "present in a Windows triage collection and the investigation objective, RANK the "
        "buckets by how likely each is to help, most relevant first. Include every bucket "
        "that could plausibly matter; you may drop ones clearly irrelevant to the objective. "
        "Reply with ONLY a JSON array of dir-codes in priority order.")


def rank_buckets(llm, questions, buckets: list[tuple[str, str]], kb_dir: Path) -> list[str]:
    """buckets: list of (dir_code, type). Returns dir-codes ordered most-relevant-first
    (subset of those present)."""
    present = [code for code, _ in buckets]
    bucket_lines = "\n".join(f"- {code}: {typ}" for code, typ in buckets)
    if questions:
        objective = "Questions to answer:\n" + "\n".join(
            f"  [{q['id']}] {q['text']}" for q in questions)
    else:
        objective = "Objective: find evidence of compromise or otherwise noteworthy activity."

    ref = ""
    ref_path = kb_dir / "artifact_map.md"
    if ref_path.exists():
        ref = "\n\nReference — where answers tend to hide:\n" + ref_path.read_text(encoding="utf-8")

    prompt = (f"Artifact buckets present (dir-code: type):\n{bucket_lines}{ref}\n\n{objective}\n\n"
              'Return a JSON array of dir-codes in priority order (most relevant first). '
              'Example: ["Psh","Evt","Brw"]')

    resp = llm.complete("orchestrator", _SYS, [neutral_user(prompt)])
    return _parse_ranked(resp.text, present)


def _parse_ranked(text: str, present: list[str]) -> list[str]:
    present_set = set(present)
    ordered: list[str] = []
    m = re.search(r"\[.*?\]", text, re.S)
    if m:
        try:
            for x in json.loads(m.group(0)):
                s = str(x).strip()
                if s in present_set and s not in ordered:
                    ordered.append(s)
        except (json.JSONDecodeError, TypeError):
            ordered = []
    if not ordered:  # fallback: dir-codes in order of first appearance in the reply
        for mm in re.finditer(r"\b([A-Za-z]+)\b", text):
            c = mm.group(1)
            if c in present_set and c not in ordered:
                ordered.append(c)
    return ordered
