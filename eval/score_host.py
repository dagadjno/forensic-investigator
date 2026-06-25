#!/usr/bin/env python
"""Focused scorer for a single-host eval slice.

Compares answers recorded in a case.db against eval/answers.json, but only for the
questions in a given questions-file (one per line). Substring match
(case-insensitive), honoring expected / expected_any. Prints a per-question table.

  python eval/score_host.py output/ws003-all/case.db eval/q_ws003/all.txt
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
    if len(sys.argv) < 3:
        return print("usage: score_host.py <case.db> <questions-file>") or 2
    db = Path(sys.argv[1])
    qfile = Path(sys.argv[2])
    key = {e["question"]: e for e in json.loads((HERE / "answers.json").read_text(encoding="utf-8"))}
    picks = [q.strip() for q in qfile.read_text(encoding="utf-8").splitlines() if q.strip()]

    conn = sqlite3.connect(db)
    ans: dict[str, list[tuple[str, str]]] = {}
    for qid_, status, answer in conn.execute("SELECT question_id,status,answer FROM answers"):
        ans.setdefault(qid_, []).append((status, answer or ""))

    hits, rows = 0, []
    for i, q in enumerate(picks, 1):
        e = key.get(q)
        if e is None:
            rows.append((f"q{i:02d}", "NO_KEY", "(question not in answers.json)", q[:70]))
            continue
        accept = e.get("expected_any") or [e["expected"]]
        recorded = ans.get(qid(q), [])
        got = " || ".join(a for _, a in recorded) or "(none)"
        statuses = {s for s, _ in recorded}
        if any(acc.lower() in a.lower() for acc in accept for _, a in recorded):
            verdict = "HIT"; hits += 1
        elif not recorded or statuses == {"unresolved"}:
            verdict = "UNRESOLVED"
        else:
            verdict = "WRONG"
        rows.append((f"q{i:02d}", verdict, accept[0], got))

    print(f"\n  HIT {hits}/{len(picks)}  ({100*hits//len(picks)}%)   db={db}\n")
    print(f"  {'#':3} {'verdict':10} {'expected':45} got")
    print("  " + "-" * 140)
    for tag, verdict, exp, got in rows:
        print(f"  {tag:3} {verdict:10} {exp[:43]:45} {got[:80]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
