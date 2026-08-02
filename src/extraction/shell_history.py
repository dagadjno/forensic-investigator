"""Parser: Linux shell history (`Home` — .bash_history / .zsh_history / …).

One event per non-empty command line — the operator's / attacker's typed commands (the Linux
analog of the Windows PowerShell-history parser). When `HISTTIMEFORMAT` is set, bash writes a
`#<epoch>` line before each command; those are consumed as the timestamp of the command that
follows. Otherwise commands are ordered but un-timed. source="shell_history".

Locator: `shell_history:<relpath>:<lineno>`.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..store.case_db import CaseDB
from ..textutil import read_text_auto
from .progress import status_done
from ..ui import EMOJI, c

SOURCE = "shell_history"
_HISTORY_NAMES = {".bash_history", ".zsh_history", ".sh_history", ".history",
                  ".python_history", ".mysql_history", ".psql_history", ".lesshst"}


def _user_from_path(rel: str) -> str:
    parts = rel.split("/")
    for anchor in ("home", "Home", "root", "Root"):
        if anchor in parts:
            i = parts.index(anchor)
            if i + 1 < len(parts):
                return parts[i + 1]
    return ""


def _ts(epoch: str) -> str:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return ""


def parse(case: CaseDB, root: Path, dir_code: str) -> None:
    base = root / dir_code
    total = files = 0
    for fp in sorted(base.rglob("*")):
        if not fp.is_file() or fp.name not in _HISTORY_NAMES:
            continue
        rel = fp.relative_to(root).as_posix()
        user = _user_from_path(rel)
        try:
            lines = read_text_auto(fp).splitlines()
        except OSError:
            continue
        files += 1
        pending_ts = ""
        for n, line in enumerate(lines, 1):
            # bash HISTTIMEFORMAT marker: `#1712345678` applies to the NEXT command
            if line.startswith("#") and line[1:].strip().isdigit():
                pending_ts = _ts(line[1:].strip())
                continue
            cmd = line.strip()
            if not cmd:
                continue
            case.add_event(source_artifact=SOURCE, summary=cmd[:600],
                           locator=f"{SOURCE}:{rel}:{n}", ts=pending_ts, user=user,
                           event_type="shell_command", raw=line)
            pending_ts = ""
            total += 1
    case.commit()
    status_done(f"    {EMOJI['ok']} {c('[shell]', 'green', 'bold')} emitted {c(str(total), 'bold')} "
                f"shell commands from {files} history file(s)")
