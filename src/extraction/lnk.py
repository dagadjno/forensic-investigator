"""Parser: Windows shortcut / LNK files (`Lnk` — binary).

LNK files (especially under `Recent/`) record that a user opened a specific file or
folder, embedding the **target's full path, the target's MAC timestamps, size, and the
volume it lived on** (local / network / removable). We parse them into the timeline as
`source="lnk"`, one event per shortcut.

Following the established pattern, each row keeps a short summary PLUS the full parsed
LNK record stored as JSON in `events.raw` (fetchable via get_raw_event), with a
`[+more fields — get_raw_event]` marker.

Backend: LnkParse3 (pure Python). If it isn't installed, Lnk is skipped gracefully
(file catalog remains). Locator: `lnk:<relpath>`.
"""
from __future__ import annotations

import json
import warnings
from pathlib import Path

from ..store.case_db import CaseDB
from .progress import status, status_done
from ..ui import EMOJI, c

SOURCE = "lnk"


def _user_from_path(rel: str) -> str:
    parts = rel.split("/")
    if "Users" in parts:
        i = parts.index("Users")
        if i + 1 < len(parts):
            return parts[i + 1]
    return ""


def _fmt(dt) -> str:
    return str(dt) if dt else ""


def parse(case: CaseDB, root: Path, dir_code: str) -> None:
    try:
        import LnkParse3
    except ImportError:
        print("    [lnk] LnkParse3 not installed (pip install LnkParse3); skipping Lnk", flush=True)
        return

    base = root / dir_code
    total = 0
    for fp in base.rglob("*.lnk"):
        if not fp.is_file():
            continue
        rel = fp.relative_to(root).as_posix()
        try:
            # LnkParse3 emits UserWarnings for shell-item enum values it doesn't recognize
            # (e.g. "Not implemented sort_index_value …"). They're harmless — the fields we
            # use (target path, MAC times, args) still parse — and only clutter output, so
            # silence them locally around the parse.
            with fp.open("rb") as fh, warnings.catch_warnings():
                warnings.simplefilter("ignore")
                j = LnkParse3.lnk_file(fh).get_json()
        except Exception as e:
            print(f"    [lnk] could not parse {rel}: {type(e).__name__}: {e}", flush=True)
            continue

        hdr = j.get("header") or {}
        data = j.get("data") or {}
        li = j.get("link_info") or {}
        name = fp.stem  # what was opened
        target = li.get("local_base_path") or data.get("relative_path") or data.get("working_directory") or ""
        args = data.get("command_line_arguments") or ""
        drive = (li.get("location_info") or {}).get("drive_type") or li.get("location") or ""
        ctime, mtime = _fmt(hdr.get("creation_time")), _fmt(hdr.get("modified_time"))
        size = hdr.get("file_size", "")

        summary = f"[LNK] {name} -> {target}"
        if args:
            summary += f" args={args}"
        summary += f" | target C={ctime} M={mtime} size={size}"
        if drive:
            summary += f" drive={drive}"
        summary = summary[:600] + "  [+more fields — get_raw_event]"

        case.add_event(source_artifact=SOURCE, summary=summary,
                       locator=f"{SOURCE}:{rel}", ts=mtime, user=_user_from_path(rel),
                       event_type=f"{SOURCE}:shortcut", raw=json.dumps(j, default=str))
        total += 1
        case.commit()
        if total % 25 == 0:
            status(f"    [lnk] {total} shortcuts ...")
    status_done(f"    {EMOJI['ok']} {c('[lnk]', 'green', 'bold')} emitted {c(str(total), 'bold')} "
                f"shortcut events")
