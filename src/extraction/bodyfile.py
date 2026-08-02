"""Parser: Sleuthkit mactime bodyfile (`Disk/bodyfile.dat`) — the Linux filesystem MAC timeline.

Format (pipe-delimited): `MD5|path|inode|mode|UID|GID|size|atime|mtime|ctime|crtime` (epoch).
This is the Linux analog of the `$MFT`/USN timeline and is huge (100k+ files), so — like the
USN parser — it is **curated**: emit only files in attacker-relevant locations (`/tmp`,
`/dev/shm`, `/var/tmp`, `/home`, `/root`, `/usr/local`, `/opt`, `/run`, `/var/www`), plus any
**setuid/setgid** file anywhere (privilege-escalation planting). The bulk system tree
(`/usr`, `/lib`, `/snap`, `/proc`, `/sys`, `/boot`) is skipped so the timeline stays signal.

`mtime` is the event timestamp; `ctime` is surfaced too — a `ctime` later than `mtime` is a
classic **timestomp** tell (metadata touched after content). source="filesystem".
Locator: `filesystem:<relpath>:<inode>`.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..store.case_db import CaseDB
from ..textutil import read_text_auto
from .progress import status, status_done
from ..ui import EMOJI, c

SOURCE = "filesystem"
_MAX = 9000
_INTEREST = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/", "/usr/local/",
             "/opt/", "/run/", "/var/www/", "/srv/")


def _iso(epoch: str) -> str:
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return ""


def _interesting(path: str, mode: str) -> bool:
    if any(path.startswith(pfx) for pfx in _INTEREST):
        return True
    # setuid (owner-exec 's'/'S') or setgid (group-exec 's'/'S') anywhere = worth flagging
    return len(mode) >= 7 and (mode[3] in "sS" or mode[6] in "sS")


def parse(case: CaseDB, root: Path, dir_code: str) -> None:
    base = root / dir_code
    files = [fp for fp in base.rglob("*") if fp.is_file() and "bodyfile" in fp.name.lower()]
    total = scanned = 0
    for fp in files:
        rel = fp.relative_to(root).as_posix()
        try:
            lines = read_text_auto(fp).splitlines()
        except OSError:
            continue
        for line in lines:
            if total >= _MAX:
                break
            scanned += 1
            if scanned % 50000 == 0:
                status(f"    [bodyfile] {scanned:,} scanned, {total:,} kept ...")
            parts = line.split("|")
            if len(parts) < 11:
                continue
            # path may itself contain '|'; the trailing 9 fields are fixed.
            inode, mode, uid, gid, size, _atime, mtime, ctime, crtime = parts[-9:]
            path = "|".join(parts[1:-9])
            if not _interesting(path, mode):
                continue
            mtime_iso, ctime_iso = _iso(mtime), _iso(ctime)
            stomp = " TIMESTOMP?" if (ctime_iso and mtime_iso and ctime_iso < mtime_iso) else ""
            setid = " SETUID/SETGID" if (len(mode) >= 7 and (mode[3] in "sS" or mode[6] in "sS")) else ""
            summary = (f"[fs {mode}] {path} size={size} uid={uid} gid={gid} "
                       f"mtime={mtime_iso} ctime={ctime_iso}{setid}{stomp}")
            case.add_event(source_artifact=SOURCE, summary=summary[:600],
                           locator=f"{SOURCE}:{rel}:{inode}", ts=mtime_iso,
                           event_type="filesystem:setid" if setid else "filesystem:file",
                           raw=line)
            total += 1
    case.commit()
    status_done(f"    {EMOJI['ok']} {c('[bodyfile]', 'green', 'bold')} emitted {c(str(total), 'bold')} "
                f"curated filesystem events (of {scanned:,} scanned)")
