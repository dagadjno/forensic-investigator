#!/usr/bin/env python
"""List which host answered (or pointed at / left unresolved) each question.

Whichever host *answered* a question is, by definition, the host that question is about.
Run it after an investigation pass. By default it shows only ANSWERED resolutions; use
--status to widen, or --question to filter to questions matching a substring.

    python scripts/whoanswered.py
    python scripts/whoanswered.py --root output
    python scripts/whoanswered.py --status any
    python scripts/whoanswered.py --question kerberos
"""
from __future__ import annotations

import argparse
import glob
import sqlite3
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default="output",
                    help="results dir holding <host>/case.db (default: output)")
    ap.add_argument("--glob", dest="pattern", default=None,
                    help="explicit glob for case.db files (overrides --root)")
    ap.add_argument("--status", default="answered",
                    choices=["answered", "pointer", "unresolved", "any"],
                    help="which resolutions to show (default: answered)")
    ap.add_argument("--question", default=None,
                    help="only show questions whose text contains this substring")
    args = ap.parse_args()

    pattern = args.pattern or str(Path(args.root) / "*" / "case.db")
    dbs = sorted(glob.glob(pattern))
    if not dbs:
        sys.exit(f"no case.db found under {pattern!r} — run an investigation first.")

    sql = ("SELECT q.text t, a.status s, a.answer a FROM answers a "
           "JOIN questions q ON q.id = a.question_id")
    params: list[str] = []
    clauses = []
    if args.status != "any":
        clauses.append("a.status = ?")
        params.append(args.status)
    if args.question:
        clauses.append("q.text LIKE ? COLLATE NOCASE")
        params.append(f"%{args.question}%")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)

    shown = 0
    for db in dbs:
        host = Path(db).parent.name
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            con.row_factory = sqlite3.Row
            rows = con.execute(sql, params).fetchall()
        except sqlite3.Error:
            continue  # partial/empty db — skip
        for r in rows:
            tag = "" if args.status != "any" else f"[{r['s']}] "
            val = (r["a"] or "").replace("\n", " ")[:60]
            print(f"{host:40} | {tag}{r['t'][:55]} -> {val}")
            shown += 1

    if not shown:
        print(f"no {args.status} resolutions found across {len(dbs)} db(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
