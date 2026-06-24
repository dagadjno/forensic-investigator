"""Parser: PowerShell console history (`Psh`).

These are plain-text `ConsoleHost_history.txt` files, one command per line, stored
per user. We emit one timeline event per non-empty command line, with a stable
locator of the form `powershell_history:<path>:<lineno>`.
"""
from __future__ import annotations

from pathlib import Path

from ..store.case_db import CaseDB

SOURCE = "powershell_history"


def _user_from_path(rel: str) -> str:
    # .../Users/<user>/.../ConsoleHost_history.txt  -> <user>
    parts = rel.split("/")
    if "Users" in parts:
        i = parts.index("Users")
        if i + 1 < len(parts):
            return parts[i + 1]
    return ""


def parse(case: CaseDB, root: Path, dir_code: str) -> None:
    base = root / dir_code
    for fp in base.rglob("*"):
        if not fp.is_file():
            continue
        if "history" not in fp.name.lower() and fp.suffix.lower() != ".txt":
            continue
        rel = fp.relative_to(root).as_posix()
        user = _user_from_path(rel)
        try:
            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, start=1):
            cmd = line.strip()
            if not cmd:
                continue
            locator = f"{SOURCE}:{rel}:{n}"
            case.add_event(
                source_artifact=SOURCE, summary=cmd, locator=locator,
                user=user, event_type="ps_command", raw=line,
            )
    case.commit()
