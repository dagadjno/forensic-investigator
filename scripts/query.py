#!/usr/bin/env python
"""Run an arbitrary SQL query against a case.db (read-only).

The database path is a parameter — point it at any host's case.db. With no SQL it
lists the tables and their row counts so you can see what's there.

    python scripts/query.py output/ws001/case.db
    python scripts/query.py output/ws001/case.db "SELECT severity, title FROM findings"
    python scripts/query.py output/ws001/case.db "SELECT * FROM answers" --limit 5

The connection is opened read-only, so a stray UPDATE/DELETE can never touch evidence.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path


def _connect_ro(db: Path) -> sqlite3.Connection:
    if not db.exists():
        sys.exit(f"error: no such database: {db}")
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _list_tables(con: sqlite3.Connection) -> int:
    rows = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    if not rows:
        print("(no tables)")
        return 0
    print(f"{'table':<24} rows")
    print("-" * 32)
    for r in rows:
        try:
            n = con.execute(f"SELECT COUNT(*) FROM \"{r['name']}\"").fetchone()[0]
        except sqlite3.Error:
            n = "?"
        print(f"{r['name']:<24} {n}")
    print("\nPass a SQL string as the 2nd argument to query a table.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("db", type=Path, help="path to a case.db (e.g. output/ws001/case.db)")
    ap.add_argument("sql", nargs="?", help="SQL to run; omit to list tables + row counts")
    ap.add_argument("--limit", type=int, default=0,
                    help="cap rows printed (0 = no cap; ignored if your SQL has LIMIT)")
    args = ap.parse_args()

    con = _connect_ro(args.db)
    if not args.sql:
        return _list_tables(con)

    try:
        cur = con.execute(args.sql)
    except sqlite3.Error as e:
        sys.exit(f"SQL error: {e}")

    n = 0
    for row in cur:
        print(dict(row))
        n += 1
        if args.limit and n >= args.limit:
            print(f"... (stopped at --limit {args.limit})")
            break
    print(f"\n{n} row(s).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
