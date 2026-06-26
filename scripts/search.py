#!/usr/bin/env python
"""Rank hosts that mention one or more terms — to find which host owns a question.

Counts how often each term appears in a host's parsed timeline (events.summary) and file
catalog (files.path), then prints matching hosts most-hits-first. Run it after the
`--ingest-only` parse step. Matching is case-insensitive; quote multi-word terms.

  AND (default) — host must mention EVERY term (terms may be in different rows):
    python scripts/search.py olivia.parker mimikatz        # the host involving both
    python scripts/search.py "olivia parker" 13.58.222.12

  OR (--any) — host mentions ANY term; ranked by total hits:
    python scripts/search.py --any AdFind.exe SharpHound.exe BloodHound

    python scripts/search.py olivia.parker --root output --glob "output/*/case.db"

The top host is almost always the one the question is about. Per-term hit counts are shown
so you can see which terms landed where.
"""
from __future__ import annotations

import argparse
import glob
import sqlite3
import sys
from pathlib import Path


def _counts(db: str, terms: list[str]) -> dict[str, int]:
    """Per-term hit count (events.summary + files.path) for one case.db."""
    res = {t: 0 for t in terms}
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    except sqlite3.Error:
        return res
    for t in terms:
        like = f"%{t}%"
        for table, col in (("events", "summary"), ("files", "path")):
            try:
                res[t] += con.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {col} LIKE ? COLLATE NOCASE", (like,)
                ).fetchone()[0]
            except sqlite3.Error:
                pass  # table/column may not exist in a partial db — skip it
    con.close()
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("terms", nargs="+", metavar="TERM",
                    help="one or more keywords (username, IP, filename, tool, …)")
    ap.add_argument("--any", dest="any_", action="store_true",
                    help="OR: match hosts mentioning ANY term (default: AND — all terms)")
    ap.add_argument("--root", default="output",
                    help="results dir holding <host>/case.db (default: output)")
    ap.add_argument("--glob", dest="pattern", default=None,
                    help="explicit glob for case.db files (overrides --root)")
    args = ap.parse_args()

    pattern = args.pattern or str(Path(args.root) / "*" / "case.db")
    dbs = sorted(glob.glob(pattern))
    if not dbs:
        sys.exit(f"no case.db found under {pattern!r} — run the --ingest-only parse first.")

    hits = []  # (total_hits, host, per-term counts)
    for db in dbs:
        counts = _counts(db, args.terms)
        n_matched = sum(1 for v in counts.values() if v)
        total = sum(counts.values())
        keep = (n_matched > 0) if args.any_ else (n_matched == len(args.terms))
        if keep:
            hits.append((total, Path(db).parent.name, counts))

    joiner = "ANY" if args.any_ else "ALL"
    if not hits:
        print(f"no host mentions {joiner} of {args.terms} ({len(dbs)} db(s) searched).")
        return 0

    print(f"hosts mentioning {joiner} of {args.terms} (most hits first):\n")
    for total, host, counts in sorted(hits, key=lambda x: x[0], reverse=True):
        breakdown = "  ".join(f"{t}={counts[t]}" for t in args.terms)
        print(f"{total:7}  {host:42}  {breakdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
