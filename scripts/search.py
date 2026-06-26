#!/usr/bin/env python
"""Rank hosts that mention a term — to find which host owns a question.

Counts how often a term appears in each host's parsed timeline (events.summary) and
file catalog (files.path), then prints hosts most-hits-first. Run it after the
`--ingest-only` parse step. Matching is case-insensitive.

    python scripts/search.py olivia.parker
    python scripts/search.py 13.58.222.12 --root output
    python scripts/search.py AdFind.exe --glob "output/*/case.db"

The host with the most hits is almost always the one the question is about.
"""
from __future__ import annotations

import argparse
import glob
import sqlite3
import sys
from pathlib import Path


def _count(db: str, term: str) -> int:
    like = f"%{term}%"
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    except sqlite3.Error:
        return 0
    n = 0
    for table, col in (("events", "summary"), ("files", "path")):
        try:
            n += con.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {col} LIKE ? COLLATE NOCASE", (like,)
            ).fetchone()[0]
        except sqlite3.Error:
            pass  # table/column may not exist in a partial db — skip it
    con.close()
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("term", help="text to search for (username, IP, filename, tool, …)")
    ap.add_argument("--root", default="output",
                    help="results dir holding <host>/case.db (default: output)")
    ap.add_argument("--glob", dest="pattern", default=None,
                    help="explicit glob for case.db files (overrides --root)")
    args = ap.parse_args()

    pattern = args.pattern or str(Path(args.root) / "*" / "case.db")
    dbs = sorted(glob.glob(pattern))
    if not dbs:
        sys.exit(f"no case.db found under {pattern!r} — run the --ingest-only parse first.")

    results = [(_count(db, args.term), Path(db).parent.name) for db in dbs]
    hits = [(n, host) for n, host in results if n]
    if not hits:
        print(f"no host mentions {args.term!r} ({len(dbs)} db(s) searched).")
        return 0

    print(f"hosts mentioning {args.term!r} (most first):\n")
    for n, host in sorted(hits, reverse=True):
        print(f"{n:7}  {host}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
