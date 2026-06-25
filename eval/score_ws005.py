#!/usr/bin/env python
"""Focused scorer for the namtws005 single-host eval.

Compares the answers recorded in a case.db against eval/answers.json, but only
for the 16 questions in eval/q_ws005/all16.txt. Substring match (case-insensitive),
honoring expected / expected_any. Prints a per-question verdict table.

  python eval/score_ws005.py output/ws005-all/case.db
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).parent


def qid(text: str) -> str:
    norm = " ".join(text.lower().split())
    return "q" + hashlib.sha1(norm.encode("utf-8")).hexdigest()[:8]


def main() -> int:
    db = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / "output/ws005-all/case.db"
    key = {e["question"]: e for e in json.loads((HERE / "answers.json").read_text(encoding="utf-8"))}
    picks = [q.strip() for q in (HERE / "q_ws005/all16.txt").read_text(encoding="utf-8").splitlines() if q.strip()]

    conn = sqlite3.connect(db)
    ans: dict[str, list[tuple[str, str]]] = {}
    for qid_, status, answer in conn.execute("SELECT question_id,status,answer FROM answers"):
        ans.setdefault(qid_, []).append((status, answer or ""))

    hits = 0
    rows = []
    for i, q in enumerate(picks, 1):
        e = key[q]
        accept = e.get("expected_any") or [e["expected"]]
        recorded = ans.get(qid(q), [])
        got = " || ".join(a for _, a in recorded) or "(none)"
        statuses = {s for s, _ in recorded}
        verdict = "UNRESOLVED" if not recorded else "WRONG"
        if any(acc.lower() in a.lower() for acc in accept for _, a in recorded):
            verdict = "HIT"
            hits += 1
        elif recorded and statuses == {"unresolved"}:
            verdict = "UNRESOLVED"
        rows.append((f"q{i:02d}", verdict, accept[0], got))

    w = max(len(r[3]) for r in rows)
    print(f"\n  HIT {hits}/{len(picks)}  ({100*hits//len(picks)}%)   db={db}\n")
    print(f"  {'#':3} {'verdict':10} {'expected':45} got")
    print("  " + "-" * (62 + min(w, 80)))
    for tag, verdict, exp, got in rows:
        print(f"  {tag:3} {verdict:10} {exp[:43]:45} {got[:80]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
