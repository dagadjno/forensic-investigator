"""On-demand $MFT lookup (targeted, not a full dump).

The full $MFT is huge (often hundreds of MB / ~500k records), so we never bulk-load it.
Instead this resolves SPECIFIC files by name when a lead needs a full path or the
$SI/$FN timestamps (e.g. resolving a USN filename, or checking for timestomping).

A minimal, dependency-free NTFS MFT parser: applies the fixup (update-sequence) array,
reads the $STANDARD_INFORMATION (0x10) and $FILE_NAME (0x30) attributes, and resolves
the full path by walking parent references. The record→(name,parent) index is built once
per $MFT file and cached in-process, so the first lookup pays the scan cost and later
ones are fast.

Powers the `mft_lookup` tool; results are materialized into the timeline as source="mft".
"""
from __future__ import annotations

import datetime
import struct
from pathlib import Path

_REC = 1024
_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
_NS_PRIORITY = {3: 3, 1: 2, 0: 1, 2: 0}  # prefer Win32&DOS / Win32 over POSIX / DOS-8.3

# mft_path -> {record_no: (name, parent_no, is_dir, in_use)}
_INDEX_CACHE: dict[str, dict] = {}


def _filetime(raw: bytes):
    val = struct.unpack("<Q", raw)[0]
    if not val:
        return None
    try:
        return (_EPOCH + datetime.timedelta(microseconds=val / 10)).isoformat()
    except (OverflowError, ValueError):
        return None


def _apply_fixup(rec: bytearray) -> bool:
    usa_off = struct.unpack_from("<H", rec, 4)[0]
    usa_cnt = struct.unpack_from("<H", rec, 6)[0]
    if not usa_off or usa_cnt < 2:
        return True
    for i in range(1, usa_cnt):
        pos = i * 512 - 2
        src = usa_off + i * 2
        if pos + 2 <= len(rec) and src + 2 <= len(rec):
            rec[pos:pos + 2] = rec[src:src + 2]
    return True


def _parse(rec: bytearray, full: bool = False):
    """Return a dict for an MFT record, or None if not a FILE record."""
    if rec[0:4] != b"FILE":
        return None
    flags = struct.unpack_from("<H", rec, 22)[0]
    in_use, is_dir = bool(flags & 1), bool(flags & 2)
    off = struct.unpack_from("<H", rec, 20)[0]
    name = ""
    parent = 0
    best = -1
    si = fn = None
    size = 0
    while off + 8 <= _REC:
        atype = struct.unpack_from("<I", rec, off)[0]
        if atype == 0xFFFFFFFF:
            break
        alen = struct.unpack_from("<I", rec, off + 4)[0]
        if alen == 0 or off + alen > _REC:
            break
        resident = rec[off + 8] == 0
        if atype == 0x10 and resident:
            c = off + struct.unpack_from("<H", rec, off + 0x14)[0]
            if full and c + 32 <= _REC:
                si = {"created": _filetime(rec[c:c + 8]), "modified": _filetime(rec[c + 8:c + 16]),
                      "mft_modified": _filetime(rec[c + 16:c + 24]), "accessed": _filetime(rec[c + 24:c + 32])}
        elif atype == 0x30 and resident:
            c = off + struct.unpack_from("<H", rec, off + 0x14)[0]
            if c + 0x42 <= _REC:
                pref = struct.unpack_from("<Q", rec, c)[0] & 0x0000FFFFFFFFFFFF
                nlen = rec[c + 0x40]
                ns = rec[c + 0x41]
                nm = rec[c + 0x42:c + 0x42 + nlen * 2].decode("utf-16-le", "replace")
                if _NS_PRIORITY.get(ns, 0) > best:
                    best = _NS_PRIORITY.get(ns, 0)
                    name, parent = nm, pref
                    size = struct.unpack_from("<Q", rec, c + 0x30)[0]
                    if full:
                        fn = {"created": _filetime(rec[c + 0x08:c + 0x10]),
                              "modified": _filetime(rec[c + 0x10:c + 0x18]),
                              "mft_modified": _filetime(rec[c + 0x18:c + 0x20]),
                              "accessed": _filetime(rec[c + 0x20:c + 0x28])}
        off += alen
    if not name:
        return None
    d = {"name": name, "parent": parent, "is_dir": is_dir, "in_use": in_use, "size": size}
    if full:
        d["si_times"], d["fn_times"] = si, fn
    return d


def _build_index(path: Path) -> dict:
    idx: dict[int, tuple] = {}
    with path.open("rb") as f:
        rec_no = 0
        while True:
            block = f.read(_REC * 1024)   # 1 MB at a time
            if not block:
                break
            for i in range(0, len(block) - _REC + 1, _REC):
                rec = bytearray(block[i:i + _REC])
                _apply_fixup(rec)
                p = _parse(rec, full=False)
                if p:
                    idx[rec_no] = (p["name"], p["parent"], p["is_dir"], p["in_use"])
                rec_no += 1
    return idx


def _resolve_path(idx: dict, rec_no: int) -> str:
    parts, cur, seen = [], rec_no, set()
    while cur in idx and cur != 5 and cur not in seen and len(parts) < 256:
        name, parent, _, _ = idx[cur]
        parts.append(name)
        seen.add(cur)
        cur = parent
    return "\\" + "\\".join(reversed(parts))


def _details(path: Path, rec_no: int) -> dict:
    with path.open("rb") as f:
        f.seek(rec_no * _REC)
        rec = bytearray(f.read(_REC))
    _apply_fixup(rec)
    return _parse(rec, full=True) or {}


def lookup(mft_path: str | Path, query: str, limit: int = 50) -> list[dict]:
    """Find MFT records whose filename contains `query` (case-insensitive); resolve full
    path + $SI/$FN timestamps for each."""
    path = Path(mft_path)
    key = str(path)
    if key not in _INDEX_CACHE:
        _INDEX_CACHE[key] = _build_index(path)
    idx = _INDEX_CACHE[key]
    q = query.lower()
    out = []
    for rec_no, (name, parent, is_dir, in_use) in idx.items():
        if q in name.lower():
            d = _details(path, rec_no)
            out.append({
                "record_no": rec_no,
                "path": _resolve_path(idx, rec_no),
                "name": name,
                "is_dir": is_dir,
                "deleted": not in_use,
                "size": d.get("size"),
                "si_times": d.get("si_times"),
                "fn_times": d.get("fn_times"),
            })
            if len(out) >= limit:
                break
    return out
