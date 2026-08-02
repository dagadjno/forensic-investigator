"""Parser: Linux running-process snapshot (`Proc`).

Builds one event per process alive at collection time, correlating the /proc dumps by PID:
  - `proc-CommandLines.dat`  — `==> /proc/<PID>/cmdline <==` blocks → the full command line
  - `proc-Hashes.dat`        — `<sha1>  /proc/<PID>/exe` → executable SHA-1 (VT / allowlist)
  - `PSList.dat`             — `USER PID … START COMMAND` → owning user + start (and a fallback
                               command for kernel threads with an empty cmdline)
  - `proc-DelExecutables.dat` — processes whose on-disk **executable is deleted** while still
    running: a classic Linux malware tell (run-then-unlink / memfd exec). Those PIDs are flagged
    `event_type=process:deleted_exe`. (NB: `proc-DelFDLinks.dat` is deleted *file descriptors* —
    mostly benign memfd audio/IPC buffers — so it is NOT used for this flag, only DelExecutables.)

source="process". Locator: `process:Proc:<PID>` (a per-PID snapshot, not a per-line record).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..store.case_db import CaseDB
from ..textutil import read_text_auto
from .progress import status_done
from ..ui import EMOJI, c

SOURCE = "process"
_MAX = 6000
_CMD_HDR = re.compile(r"==>\s*/proc/(\d+)/cmdline\s*<==")
_PROC_PID = re.compile(r"/proc/(\d+)/")


def _read(base: Path, name: str) -> str:
    fp = base / name
    if not fp.is_file():
        # some collectors nest under a subdir; fall back to a recursive find
        found = next((p for p in base.rglob(name) if p.is_file()), None)
        fp = found or fp
    try:
        return read_text_auto(fp) if fp.is_file() else ""
    except OSError:
        return ""


def _clean(buf: list[str]) -> str:
    # /proc/<pid>/cmdline is NUL-separated; the .dat preserves literal NULs on the line. Turn
    # them into spaces (the human-readable command line) — embedded NULs otherwise corrupt the
    # summary (SQLite LIKE truncates at a NUL, hiding everything after it).
    return " ".join(" ".join(buf).replace("\x00", " ").split())


def _cmdlines(text: str) -> dict[str, str]:
    out, pid = {}, None
    buf: list[str] = []
    for line in text.splitlines():
        m = _CMD_HDR.search(line)
        if m:
            if pid is not None:
                out[pid] = _clean(buf)
            pid, buf = m.group(1), []
        elif pid is not None:
            buf.append(line)
    if pid is not None:
        out[pid] = _clean(buf)
    return out


def _hashes(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            m = _PROC_PID.search(parts[1])
            if m:
                out[m.group(1)] = parts[0]
    return out


def _pslist(text: str) -> dict[str, dict]:
    out = {}
    for line in text.splitlines():
        parts = line.split(None, 10)
        if len(parts) < 11 or not parts[1].isdigit():
            continue  # header / malformed
        out[parts[1]] = {"user": parts[0], "start": parts[8], "command": parts[10]}
    return out


def _deleted_pids(*texts: str) -> set[str]:
    pids: set[str] = set()
    for text in texts:
        for line in text.splitlines():
            if "(deleted)" in line or "/memfd:" in line:
                m = _PROC_PID.search(line)
                if m:
                    pids.add(m.group(1))
    return pids


def parse(case: CaseDB, root: Path, dir_code: str) -> None:
    base = root / dir_code
    cmds = _cmdlines(_read(base, "proc-CommandLines.dat"))
    hashes = _hashes(_read(base, "proc-Hashes.dat"))
    ps = _pslist(_read(base, "PSList.dat"))
    # ONLY DelExecutables (deleted running binary) — NOT DelFDLinks (benign memfd FDs).
    deleted = _deleted_pids(_read(base, "proc-DelExecutables.dat"))

    total = 0
    for pid in sorted(set(cmds) | set(ps), key=lambda x: int(x)):
        if total >= _MAX:
            break
        info = ps.get(pid, {})
        cmd = cmds.get(pid) or info.get("command", "")
        user = info.get("user", "")
        sha1 = hashes.get(pid, "")
        is_del = pid in deleted
        bits = [f"[pid {pid}]"]
        if user:
            bits.append(f"user={user}")
        bits.append(cmd or "(no cmdline — kernel thread?)")
        if sha1:
            bits.append(f"sha1={sha1}")
        if is_del:
            bits.append("DELETED-EXE(running from deleted/memfd binary)")
        case.add_event(source_artifact=SOURCE, summary=" ".join(bits)[:600],
                       locator=f"{SOURCE}:{dir_code}:{pid}", user=user,
                       event_type="process:deleted_exe" if is_del else "process",
                       raw=json.dumps({"pid": pid, "user": user, "cmdline": cmd,
                                       "sha1": sha1, "start": info.get("start", ""),
                                       "deleted_exe": is_del}))
        total += 1
    case.commit()
    status_done(f"    {EMOJI['ok']} {c('[process]', 'green', 'bold')} emitted {c(str(total), 'bold')} "
                f"process events" + (f" ({len(deleted)} with deleted exe)" if deleted else ""))
