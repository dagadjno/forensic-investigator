#!/usr/bin/env python
"""Search the parsed timeline + file catalog across hosts for one or more terms.

Runs over each host's `output/<host>/case.db` (after the `--ingest-only` parse step).
Matching is case-insensitive; quote multi-word terms.

  AND (default) — hosts with an ENTRY where a SINGLE row contains EVERY term (per-host
  counts only; add --show to print the matching entries with their locators):
    python scripts/search.py olivia.parker mimikatz             # which host(s), how many
    python scripts/search.py olivia.parker 13.58.222.12 --show  # the exact rows + locators
  Use this to pinpoint the exact event/file tying two things together.

  OR (--any) — rank HOSTS that mention ANY term (per-term breakdown), to find which
  host owns a question:
    python scripts/search.py --any AdFind.exe SharpHound.exe BloodHound

    python scripts/search.py olivia.parker --glob "output/*/case.db" --limit 20
"""
from __future__ import annotations

import argparse
import glob
import sqlite3
import sys
from collections import Counter
from pathlib import Path

# (table, text column searched, bucket column, extra columns to display for context).
_SOURCES = (("events", "summary", "source_artifact", "ts, summary, locator"),
            ("files", "path", "artifact", "path"))


def _connect(db: str):
    try:
        return sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    except sqlite3.Error:
        return None


def _and_entries(db: str, terms: list[str], limit: int):
    """Rows whose ONE text field contains ALL terms. Returns (total, sample_rows, buckets)
    where each sample is (source, text, locator, ts) and buckets is a Counter of which bucket
    the matches came from (events by source name; files tagged 'file:<dir-code>')."""
    con = _connect(db)
    if con is None:
        return 0, [], Counter()
    likes = [f"%{t}%" for t in terms]
    total, samples, buckets = 0, [], Counter()
    for table, col, bucket_col, cols in _SOURCES:
        clause = " AND ".join(f"{col} LIKE ? COLLATE NOCASE" for _ in terms)
        # Bucket tally via GROUP BY — cheap, and runs even in counts-only mode.
        try:
            for b, n in con.execute(
                    f"SELECT {bucket_col}, COUNT(*) FROM {table} WHERE {clause} "
                    f"GROUP BY {bucket_col}", likes):
                label = (b or "?") if table == "events" else f"file:{b or '?'}"
                buckets[label] += n
                total += n
        except sqlite3.Error:
            continue  # table/column may be absent in a partial db — skip it
        # Sample rows only when some are still wanted (limit==0 in counts-only mode).
        if len(samples) < limit:
            try:
                cur = con.execute(f"SELECT {cols} FROM {table} WHERE {clause} LIMIT ?",
                                  likes + [limit - len(samples)])
                for r in cur:
                    if table == "events":
                        ts, summary, loc = r
                        samples.append(("event", summary, loc, ts or ""))
                    else:
                        samples.append(("file", r[0], r[0], ""))
            except sqlite3.Error:
                pass
    con.close()
    return total, samples, buckets


def _or_counts(db: str, terms: list[str]) -> dict[str, int]:
    """Per-term hit count (any row) for one case.db — used for OR host ranking."""
    res = {t: 0 for t in terms}
    con = _connect(db)
    if con is None:
        return res
    for t in terms:
        like = f"%{t}%"
        for table, col, _ in _SOURCES:
            try:
                res[t] += con.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {col} LIKE ? COLLATE NOCASE", (like,)
                ).fetchone()[0]
            except sqlite3.Error:
                pass
    con.close()
    return res


def _run_and(dbs: list[str], terms: list[str], limit: int, show: bool) -> int:
    # (entry_count, host, samples) per host that has at least one all-terms row.
    hits = []
    for db in dbs:
        total, samples, buckets = _and_entries(db, terms, limit if show else 0)
        if total:
            hits.append((total, Path(db).parent.name, samples, buckets))
    if not hits:
        print(f"no single entry contains ALL of {terms} ({len(dbs)} db(s) searched).")
        return 0

    grand = sum(h[0] for h in hits)
    print(f"entries containing ALL of {terms}: {grand} across {len(hits)} host(s) "
          f"(most first):\n")
    for total, host, samples, buckets in sorted(hits, key=lambda x: x[0], reverse=True):
        breakdown = "  ".join(f"{b}={n}" for b, n in buckets.most_common())
        if not show:                       # default: per-host tally + bucket breakdown
            print(f"{total:7}  {host:42}  {breakdown}")
            continue
        more = f"  (+{total - len(samples)} more)" if total > len(samples) else ""
        print(f"{host}  -  {total} entr{'y' if total == 1 else 'ies'}{more}   [{breakdown}]")
        for source, text, loc, ts in samples:
            head = f"   {source:5} "
            head += f"{ts[:19]}  " if ts else ""
            print(f"{head}{text[:150]}")
            if source == "event":
                print(f"          {loc}")
        print()
    if not show:
        print(f"\n(pass --show to print the matching entries.)")
    return 0


def _run_or(dbs: list[str], terms: list[str]) -> int:
    hits = []  # (total_hits, host, per-term counts)
    for db in dbs:
        counts = _or_counts(db, terms)
        if any(counts.values()):
            hits.append((sum(counts.values()), Path(db).parent.name, counts))
    if not hits:
        print(f"no host mentions ANY of {terms} ({len(dbs)} db(s) searched).")
        return 0
    print(f"hosts mentioning ANY of {terms} (most hits first):\n")
    for total, host, counts in sorted(hits, key=lambda x: x[0], reverse=True):
        breakdown = "  ".join(f"{t}={counts[t]}" for t in terms)
        print(f"{total:7}  {host:42}  {breakdown}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("terms", nargs="+", metavar="TERM",
                    help="one or more keywords (username, IP, filename, tool, …)")
    ap.add_argument("--any", dest="any_", action="store_true",
                    help="OR: rank hosts mentioning ANY term (default: AND — one entry with all terms)")
    ap.add_argument("--root", default="output",
                    help="results dir holding <host>/case.db (default: output)")
    ap.add_argument("--glob", dest="pattern", default=None,
                    help="explicit glob for case.db files (overrides --root)")
    ap.add_argument("--show", action="store_true",
                    help="AND mode: print the matching entries (text + locator), not just the "
                         "per-host counts")
    ap.add_argument("--limit", type=int, default=10,
                    help="with --show, max matching entries printed per host (default 10)")
    args = ap.parse_args()

    pattern = args.pattern or str(Path(args.root) / "*" / "case.db")
    dbs = sorted(glob.glob(pattern))
    if not dbs:
        sys.exit(f"no case.db found under {pattern!r} — run the --ingest-only parse first.")

    return _run_or(dbs, args.terms) if args.any_ else _run_and(dbs, args.terms, args.limit, args.show)


if __name__ == "__main__":
    raise SystemExit(main())
