"""Parser: browser history & downloads (`Brw`).

The collection exports browser data as CSV (NirSoft BrowsingHistoryView /
BrowserDownloadsView). We parse those into the normalized timeline as
`source="browser"`, one event per history visit / download. Pure stdlib (csv).

Following the EVTX/registry pattern, each row keeps a short summary PLUS the full CSV
row stored as JSON in `events.raw` (fetchable via get_raw_event), with a
`[+N more fields — get_raw_event]` marker when the summary omitted columns.

Locator: `browser:<relpath>:<rownum>`.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from ..store.case_db import CaseDB

SOURCE = "browser"
_MAX_ROWS = 5000  # per file, safety bound


def _get(row: dict, *candidates: str) -> str:
    """First non-empty value among candidate column names (case-insensitive)."""
    lower = {(k or "").lower(): v for k, v in row.items()}
    for c in candidates:
        v = lower.get(c.lower())
        if v and v.strip():
            return v.strip()
    return ""


def _user_from_paths(*paths: str) -> str:
    for p in paths:
        m = re.search(r"[\\/]Users[\\/]([^\\/]+)", p or "", re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def _classify(fieldnames: list[str], name: str) -> str:
    fns = {(f or "").lower() for f in fieldnames}
    if "visit time" in fns or "hist" in name.lower():
        return "history"
    if any("download" in f for f in fns) or "down" in name.lower():
        return "download"
    return "row"


def _emit(case: CaseDB, rel: str, rownum: int, category: str, summary: str,
          ts: str, user: str, row: dict) -> None:
    fields = {k: v for k, v in row.items() if k and v and str(v).strip()}
    summary = summary[:560]
    shown = sum(1 for v in fields.values() if v[:20] in summary)
    dropped = len(fields) - shown
    if dropped > 0:
        summary += f"  [+{dropped} more fields — get_raw_event]"
    case.add_event(source_artifact=SOURCE, summary=summary[:640],
                   locator=f"{SOURCE}:{rel}:{rownum}", ts=ts, user=user,
                   event_type=f"{SOURCE}:{category}", raw=json.dumps(fields))


def parse(case: CaseDB, root: Path, dir_code: str) -> None:
    base = root / dir_code
    total = 0
    for fp in base.rglob("*.csv"):
        if not fp.is_file():
            continue
        rel = fp.relative_to(root).as_posix()
        try:
            with fp.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
                reader = csv.DictReader(fh)
                kind = _classify(reader.fieldnames or [], fp.name)
                for i, row in enumerate(reader, start=1):
                    if i > _MAX_ROWS:
                        break
                    if kind == "history":
                        url = _get(row, "URL")
                        title = _get(row, "Title") or "(no title)"
                        vt = _get(row, "Visit Time")
                        summary = (f"[History] {title} | {url} | {vt} "
                                   f"visits={_get(row, 'Visit Count')} [{_get(row, 'Web Browser')}]")
                        _emit(case, rel, i, "history", summary, vt, _get(row, "User Profile"), row)
                    elif kind == "download":
                        fn = _get(row, "Filename")
                        du = _get(row, "Download URL 1", "Download URL", "URL")
                        saved = _get(row, "Full Path Filename")
                        st = _get(row, "Start Time")
                        summary = (f"[Download] {fn} <- {du} | saved={saved} "
                                   f"size={_get(row, 'Download Size', 'File Size')} {st} "
                                   f"[{_get(row, 'Web Browser')}]")
                        user = _user_from_paths(saved, _get(row, "Browser Profile Path"))
                        _emit(case, rel, i, "download", summary, st, user, row)
                    else:
                        vals = "; ".join(f"{k}={v}" for k, v in row.items() if v)[:300]
                        _emit(case, rel, i, "row", f"[Browser] {vals}", "", "", row)
                    total += 1
        except OSError as e:
            print(f"    [browser] could not read {rel}: {e}", flush=True)
    print(f"    [browser] emitted {total} browser events", flush=True)
