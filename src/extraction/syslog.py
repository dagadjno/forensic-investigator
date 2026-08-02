"""Parser: Linux syslog-format logs (`VarLog` — auth.log, syslog, secure, kern.log, …).

One event per matching line. Modern Ubuntu uses ISO-8601 timestamps; older/other distros use
the legacy `Mon DD HH:MM:SS` form (no year) — both handled. Only lines that match the syslog
shape are emitted, so package logs (dpkg.log) and block logs (apt history) that share the
folder are skipped — they have their own parser. `auth.log` is the priority: SSH logons
(sshd), sudo/su, password changes, session open/close — the core Linux intrusion trail.

Locator: `syslog:<relpath>:<lineno>`. source="syslog".
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..store.case_db import CaseDB
from ..textutil import read_text_auto
from .progress import status, status_done
from ..ui import EMOJI, c

SOURCE = "syslog"
_MAX = 12000

# ISO-8601:  2026-08-02T10:28:48.397691+00:00 host proc[pid]: msg
_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:?\d{2}|Z)?)\s+(\S+)\s+"
                  r"([^\s:\[]+)(?:\[(\d+)\])?:\s?(.*)$")
# legacy:    Aug  2 10:28:48 host proc[pid]: msg   (no year in the line)
_LEG = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+"
                  r"([^\s:\[]+)(?:\[(\d+)\])?:\s?(.*)$")
# who the auth event concerns, when the message states it
_USER_RX = re.compile(r"\bfor (?:invalid user )?([A-Za-z0-9._-]+)|user[=\s]+([A-Za-z0-9._-]+)"
                      r"|for user ([A-Za-z0-9._-]+)")


def _is_target(name: str) -> bool:
    n = name.lower()
    return (n == "auth.log" or n.startswith("auth.log.")
            or n == "syslog" or n.startswith("syslog.")
            or n in ("secure", "kern.log", "messages", "daemon.log", "user.log"))


def _iso_from_legacy(ts: str) -> str:
    """Legacy syslog lines carry no year; assume the current one (ordering is preserved)."""
    try:
        dt = datetime.strptime(ts, "%b %d %H:%M:%S")
        return dt.replace(year=datetime.now(timezone.utc).year, tzinfo=timezone.utc).isoformat()
    except ValueError:
        return ""


def _parse_line(line: str):
    m = _ISO.match(line)
    if m:
        return m.group(1), m.group(3), m.group(4), m.group(5)
    m = _LEG.match(line)
    if m:
        return _iso_from_legacy(m.group(1)), m.group(3), m.group(4), m.group(5)
    return None


def _user_of(msg: str) -> str:
    m = _USER_RX.search(msg)
    return next((g for g in (m.groups() if m else ()) if g), "") if m else ""


def parse(case: CaseDB, root: Path, dir_code: str) -> None:
    base = root / dir_code
    total = files = 0
    for fp in sorted(base.rglob("*")):
        if total >= _MAX:
            break
        if not fp.is_file() or not _is_target(fp.name):
            continue
        rel = fp.relative_to(root).as_posix()
        try:
            lines = read_text_auto(fp).splitlines()
        except OSError:
            continue
        matched = 0
        for n, line in enumerate(lines, 1):
            if total >= _MAX:
                break
            parsed = _parse_line(line)
            if not parsed:
                continue
            ts, prog, pid, msg = parsed
            label = f"{prog}[{pid}]" if pid else prog
            case.add_event(source_artifact=SOURCE, summary=f"[{label}] {msg}"[:600],
                           locator=f"{SOURCE}:{rel}:{n}", ts=ts, user=_user_of(msg),
                           event_type=f"syslog:{prog}", raw=line)
            total += 1
            matched += 1
        if matched:
            files += 1
            status(f"    [syslog] {files} log(s), {total} events ...")
    status_done(f"    {EMOJI['ok']} {c('[syslog]', 'green', 'bold')} emitted {c(str(total), 'bold')} "
                f"syslog events from {files} log(s)")
