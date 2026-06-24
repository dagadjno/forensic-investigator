"""Parser: USN change journal (`RawData` — USNJrnl.csv export).

The USN journal logs filesystem changes (create / delete / rename / data writes). The
collection ships an ExtractUSNJrnl CSV export (USNJrnl.csv) with a metadata preamble
followed by ~hundreds of thousands of records — almost all of it noise (data
overwrite/extend/close churn on temp/state files).

So this is a CURATED parse, like the EVTX/registry allowlists: we emit only high-value
lifecycle events (file CREATE / DELETE / RENAME) for interesting file types
(executables, scripts, archives, docs, keys…), deduped per file and capped. USN records
the file *name* but not its directory (resolving the path needs the $MFT), so summaries
show the name + reason + timestamp.

Note: the full $MFT (often hundreds of MB / hundreds of thousands of files) is NOT
parsed — it would bury the timeline. USN covers the recent-change triage timeline.

Locator: `usn:<relpath>:<usn-number>`. Pure stdlib (csv). If USNJrnl.csv is absent, USN
is skipped gracefully.
"""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path

from ..store.case_db import CaseDB

SOURCE = "usn"
_MAX_EVENTS = 6000  # bound the curated output

_INTERESTING_EXT = {
    ".exe", ".dll", ".sys", ".msi", ".com", ".scr",            # executables
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe",  # scripts
    ".js", ".jse", ".wsf", ".hta",
    ".zip", ".7z", ".rar", ".gz", ".tar", ".iso", ".img", ".cab",  # archives/images
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".txt",  # docs
    ".key", ".pem", ".ppk", ".pfx", ".kirbi", ".dmp",          # creds / dumps
}


def _is_noise(name: str) -> bool:
    n = name.lower()
    return (n.startswith("__psscriptpolicytest")     # PowerShell policy-test temp files
            or ".filtertrie.intermediate" in n       # Windows Search indexer churn
            or n.startswith("mpcache-")              # Defender cache
            or n.startswith("~$"))                   # Office lock files


def parse(case: CaseDB, root: Path, dir_code: str) -> None:
    base = root / dir_code
    csvs = [fp for fp in base.rglob("*.csv") if "usn" in fp.name.lower()]
    if not csvs:
        print("    [usn] no USNJrnl.csv found; skipping", flush=True)
        return

    total = 0
    for fp in csvs:
        rel = fp.relative_to(root).as_posix()
        seen_create: set[str] = set()
        seen_delete: set[str] = set()
        try:
            with fp.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
                header = None
                for line in fh:                       # skip the metadata preamble
                    if line.startswith("Usn,"):
                        header = next(csv.reader([line]))
                        break
                if header is None:
                    print(f"    [usn] no CSV header in {rel}; skipping", flush=True)
                    continue
                reader = csv.DictReader(fh, fieldnames=header)
                for row in reader:
                    if total >= _MAX_EVENTS:
                        break
                    name = (row.get("File name") or "").strip()
                    if os.path.splitext(name)[1].lower() not in _INTERESTING_EXT:
                        continue
                    if _is_noise(name):
                        continue
                    reason = row.get("Reason") or ""
                    fid = row.get("File ID") or name
                    if "File create" in reason and fid not in seen_create:
                        seen_create.add(fid); action = "create"
                    elif "File delete" in reason and fid not in seen_delete:
                        seen_delete.add(fid); action = "delete"
                    elif "Rename new name" in reason:
                        action = "rename->"
                    else:
                        continue
                    ts = row.get("Time stamp") or ""
                    summary = (f"[USN {action}] {name} | {ts} "
                               f"attrs={row.get('File attributes', '')} reason={reason}")
                    fields = {k: v for k, v in row.items() if k and v and str(v).strip()}
                    summary = summary[:600] + "  [+more fields — get_raw_event]"
                    case.add_event(source_artifact=SOURCE, summary=summary,
                                   locator=f"{SOURCE}:{rel}:{row.get('Usn', total)}",
                                   ts=ts, user="", event_type=f"{SOURCE}:{action.rstrip('->')}",
                                   raw=json.dumps(fields))
                    total += 1
        except OSError as e:
            print(f"    [usn] could not read {rel}: {e}", flush=True)
        case.commit()
    note = " (capped)" if total >= _MAX_EVENTS else ""
    print(f"    [usn] emitted {total} curated USN events{note}", flush=True)
