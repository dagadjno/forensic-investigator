#!/usr/bin/env python
"""Scoring harness: compare the investigator's answer sheets against an answer key.

Two modes:

  # 1. Generate a questions file from the answer key (so question text matches exactly):
  python eval/score.py emit-questions --key eval/answers.json --out questions.txt

  # 2. After running the investigator on one or more hosts, score the results:
  python eval/score.py score --key eval/answers.json --cases output

`--cases` is a directory (scans <dir>/*/case.db) or a glob of case.db paths. Because the
tool is single-host, run each host's collection with the full questions file, then score
across all of them — a question counts as covered if ANY host answered it correctly.

Answer-key format (JSON list); each entry needs a question and at least one acceptable
answer string (matched case-insensitively as a substring of the tool's answer):

  [
    {"question": "What is the C2 IP address?", "expected": "13.58.222.12"},
    {"question": "What account was added to Administrators?",
     "expected_any": ["ssm-user", "ssm_user"]}
  ]
"""
from __future__ import annotations

import argparse
import glob
import json
import sqlite3
from pathlib import Path


def _norm(s: str) -> str:
    return " ".join((s or "").lower().split())


def _load_key(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for item in data:
        accept = []
        if item.get("expected"):
            accept.append(str(item["expected"]))
        accept += [str(x) for x in item.get("expected_any", [])]
        out.append({"question": item["question"], "accept": accept})
    return out


def _case_paths(cases: str) -> list[str]:
    p = Path(cases)
    if p.is_dir():
        return sorted(str(x) for x in p.glob("*/case.db"))
    return sorted(glob.glob(cases))


def cmd_emit_questions(args) -> int:
    key = _load_key(args.key)
    lines = [k["question"] for k in key]
    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(lines)} questions to {args.out}")
    return 0


def _gather(case_paths: list[str]) -> list[dict]:
    rows = []
    for p in case_paths:
        host = Path(p).parent.name
        con = sqlite3.connect(p)
        con.row_factory = sqlite3.Row
        try:
            qs = {r["id"]: r["text"] for r in con.execute("SELECT id, text FROM questions")}
            for a in con.execute("SELECT id, question_id, status, answer, reasoning FROM answers"):
                cands = [c["path"] for c in con.execute(
                    "SELECT path FROM answer_candidates WHERE answer_id=?", (a["id"],))]
                rows.append({"host": host, "qnorm": _norm(qs.get(a["question_id"], "")),
                             "status": a["status"], "answer": a["answer"] or "",
                             "reasoning": a["reasoning"] or "", "candidates": cands})
        finally:
            con.close()
    return rows


def cmd_score(args) -> int:
    key = _load_key(args.key)
    paths = _case_paths(args.cases)
    if not paths:
        print(f"no case.db files found under {args.cases!r}")
        return 2
    print(f"scoring against {len(paths)} case file(s): {[Path(p).parent.name for p in paths]}\n")
    answers = _gather(paths)
    by_q: dict[str, list[dict]] = {}
    for a in answers:
        by_q.setdefault(a["qnorm"], []).append(a)

    counts = {"HIT": 0, "WRONG": 0, "POINTER": 0, "UNRESOLVED": 0, "NOT_ASKED": 0, "REVIEW": 0}
    lines = []
    for k in key:
        cand = by_q.get(_norm(k["question"]), [])
        verdict, where, got = "NOT_ASKED", "", ""
        # a HIT if any host's answer/candidates contain an accepted string
        hit = None
        for a in cand:
            blob = _norm(a["answer"] + " " + " ".join(a["candidates"]))
            if k["accept"] and any(_norm(x) in blob for x in k["accept"]):
                hit = a
                break
        if hit:
            verdict, where, got = "HIT", hit["host"], hit["answer"][:80]
        elif cand:
            answered = [a for a in cand if a["status"] == "answered"]
            ptr = [a for a in cand if a["status"] == "pointer"]
            if not k["accept"]:
                verdict = "REVIEW"  # no acceptable strings to auto-match against
                best = (answered or cand)[-1]
                where, got = best["host"], best["answer"][:80]
            elif answered:
                verdict, where, got = "WRONG", answered[-1]["host"], answered[-1]["answer"][:80]
            elif ptr:
                verdict, where = "POINTER", ptr[-1]["host"]
                got = "; ".join(ptr[-1]["candidates"])[:80]
            else:
                verdict, where = "UNRESOLVED", cand[-1]["host"]
        counts[verdict] += 1
        lines.append((verdict, k["question"], where, got))

    width = max((len(q) for _, q, _, _ in lines), default=20)
    for verdict, q, where, got in lines:
        print(f"  {verdict:10} | {q[:width].ljust(width)} | {where:14} | {got}")

    total = len(key)
    hits = counts["HIT"]
    print("\n--- summary ---")
    for v in ("HIT", "WRONG", "POINTER", "UNRESOLVED", "NOT_ASKED", "REVIEW"):
        print(f"  {v:10}: {counts[v]}")
    print(f"\n  auto-scored coverage (HIT): {hits}/{total} = {100*hits/total:.0f}%")
    print("  (POINTER and REVIEW need manual confirmation; WRONG/UNRESOLVED/NOT_ASKED are gaps)")

    if args.out:
        rep = ["# Eval results\n", f"Coverage (HIT): {hits}/{total} = {100*hits/total:.0f}%\n",
               "\n| Verdict | Question | Host | Answer/Candidates |",
               "|---|---|---|---|"]
        for verdict, q, where, got in lines:
            rep.append(f"| {verdict} | {q.replace('|', '/')} | {where} | {got.replace('|', '/')} |")
        Path(args.out).write_text("\n".join(rep) + "\n", encoding="utf-8")
        print(f"\nwrote report to {args.out}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="score", description="score investigator answers vs an answer key")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("emit-questions", help="write a questions.txt from the answer key")
    e.add_argument("--key", required=True)
    e.add_argument("--out", required=True)
    e.set_defaults(func=cmd_emit_questions)
    s = sub.add_parser("score", help="score case.db answer sheets against the key")
    s.add_argument("--key", required=True)
    s.add_argument("--cases", required=True, help="dir containing <case>/case.db, or a glob")
    s.add_argument("--out", help="optional path to write a Markdown report")
    s.set_defaults(func=cmd_score)
    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
