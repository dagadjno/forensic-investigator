#!/usr/bin/env python
"""Combine per-host answer sheets into ONE cross-host answer sheet.

After a broad multi-host run (e.g. `run_hosts.py ".../ACQ-IR-*" --questions q.txt`), every
host has its own `output/<host>/case.db`. This collates them: for each question it shows
**which host(s) answered and the answer(s)** — so you don't have to open 11 reports to find
the owner. A question is "answered" if ANY host answered it (union).

Read-only, no AI, no cost. Safe to re-run anytime after investigations finish.

    python scripts/aggregate.py                    # -> output/_combined/answer_sheet.md
    python scripts/aggregate.py --print            # also echo to stdout
    python scripts/aggregate.py --root output --out output/_combined/answer_sheet.md
    python scripts/aggregate.py --glob "output/ACQ-IR-*/case.db"
"""
from __future__ import annotations

import argparse
import glob
import sqlite3
import sys
from pathlib import Path


_CONF_RANK = {"high": 3, "medium": 2, "low": 1, "": 0}


def _norm(s: str) -> str:
    return " ".join((s or "").lower().split())


def _read_host(db: str) -> tuple[str, list, dict]:
    """Return (host, ordered [(qid,text)], {qid: [answer-dict,...]}) for one case.db."""
    host = Path(db).parent.name
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    qs, answers = [], {}
    try:
        qs = [(r["id"], r["text"]) for r in
              con.execute("SELECT id, text FROM questions ORDER BY rowid")]
        for a in con.execute("SELECT id, question_id, status, answer, confidence, reasoning "
                             "FROM answers"):
            ev = [r["locator"] for r in con.execute(
                "SELECT locator FROM answer_evidence WHERE answer_id=?", (a["id"],))]
            cand = [(r["path"], r["reason"]) for r in con.execute(
                "SELECT path, reason FROM answer_candidates WHERE answer_id=?", (a["id"],))]
            answers.setdefault(a["question_id"], []).append({
                "host": host, "status": a["status"], "answer": a["answer"] or "",
                "confidence": a["confidence"] or "", "reasoning": a["reasoning"] or "",
                "evidence": ev, "candidates": cand})
    except sqlite3.Error:
        pass  # partial/empty db — skip what we can't read
    con.close()
    return host, qs, answers


def build(dbs: list[str]) -> str:
    # Union the question set (preserve first-seen order) and merge answers per question.
    order: list[str] = []
    text: dict[str, str] = {}
    merged: dict[str, list] = {}
    hosts: list[str] = []
    for db in dbs:
        host, qs, answers = _read_host(db)
        hosts.append(host)
        for qid, t in qs:
            if qid not in text:
                order.append(qid)
            if t:
                text.setdefault(qid, t)
        for qid, alist in answers.items():
            if qid not in text:        # answer to a question this host alone carried
                order.append(qid)
            merged.setdefault(qid, []).extend(alist)

    L: list[str] = []
    L.append("# Cross-host combined answer sheet\n")
    answered_qs = sum(1 for q in order if any(a["status"] == "answered"
                                              for a in merged.get(q, [])))
    L.append(f"_{len(hosts)} host(s): {', '.join(hosts)}_\n\n")
    L.append(f"**{answered_qs}/{len(order)} questions answered by at least one host.**\n")

    # Quick routing table: question -> host(s) that answered.
    L.append("\n## Routing — who answered what\n\n")
    L.append("| Question | Answered by |\n|---|---|\n")
    for qid in order:
        who = sorted({a["host"] for a in merged.get(qid, []) if a["status"] == "answered"})
        short = (text.get(qid, qid) or qid)[:60]
        L.append(f"| {short} | {', '.join(who) if who else '—'} |\n")

    # Full per-question detail.
    L.append("\n## Answers\n")
    for qid in order:
        L.append(f"\n### {text.get(qid, qid)}\n")
        alist = merged.get(qid, [])
        answered = [a for a in alist if a["status"] == "answered"]
        pointers = [a for a in alist if a["status"] == "pointer"]

        if answered:
            # Dedup identical answers across hosts; keep host attribution + best confidence.
            groups: dict[str, dict] = {}
            for a in answered:
                g = groups.setdefault(_norm(a["answer"]), {"text": a["answer"], "hosts": [],
                                                            "conf": "", "evidence": []})
                g["hosts"].append(a["host"])
                if _CONF_RANK.get(a["confidence"].lower(), 0) > _CONF_RANK.get(g["conf"].lower(), 0):
                    g["conf"] = a["confidence"]
                g["evidence"] += [f"{a['host']} :: {loc}" for loc in a["evidence"]]
            multi = len(groups) > 1
            if multi:
                L.append("- **ANSWERED — candidates differ across hosts (analyst to choose):**\n")
            for g in groups.values():
                where = ", ".join(sorted(set(g["hosts"])))
                conf = f" _(confidence: {g['conf']})_" if g["conf"] else ""
                bullet = "  - " if multi else "- **ANSWERED:** "
                L.append(f"{bullet}{g['text']}  — _{where}_{conf}\n")
                for loc in g["evidence"][:4]:
                    L.append(f"    - `{loc}`\n")
        elif pointers:
            L.append("- **POINTER** — no host answered; candidate files to inspect by hand:\n")
            seen = set()
            for a in pointers:
                for path, reason in a["candidates"]:
                    key = (a["host"], path)
                    if key in seen:
                        continue
                    seen.add(key)
                    why = f" — {reason}" if reason else ""
                    L.append(f"  - `{a['host']} :: {path}`{why}\n")
        else:
            n = len({a["host"] for a in alist})
            L.append(f"- **UNRESOLVED** — no host answered "
                     f"({n or 'no'} host(s) recorded a search for it).\n")
    return "".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default="output", help="results dir holding <host>/case.db")
    ap.add_argument("--glob", dest="pattern", default=None,
                    help="explicit glob for case.db files (overrides --root)")
    ap.add_argument("--out", default=None,
                    help="output path (default: <root>/_combined/answer_sheet.md)")
    ap.add_argument("--print", dest="echo", action="store_true", help="also print to stdout")
    args = ap.parse_args()

    pattern = args.pattern or str(Path(args.root) / "*" / "case.db")
    # Skip helper dirs like output/_combined or output/_memcache.
    dbs = sorted(d for d in glob.glob(pattern) if not Path(d).parent.name.startswith("_"))
    if not dbs:
        sys.exit(f"no case.db found under {pattern!r} — run investigations first.")

    md = build(dbs)
    out = Path(args.out) if args.out else Path(args.root) / "_combined" / "answer_sheet.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(f"wrote {out}  ({len(dbs)} host(s))")
    if args.echo:
        print("\n" + md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
