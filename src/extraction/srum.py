"""Parser: SRUM — System Resource Usage Monitor (`Sys` — SRUDB.dat, an ESE database).

SRUM records per-application resource usage and network connectivity over time. We parse
the high-value tables into the timeline as `source="srum"`:
  - Application Resource Usage — AGGREGATED per app (active window + disk I/O totals);
    the raw table has thousands of ~hourly rows, so a per-app rollup is the triage signal.
  - Network Connectivity — one event per connection record.
App/user IDs are resolved via SruDbIdMapTable.

Backend: dissect.esedb (pure Python). If it isn't installed, SRUM is skipped gracefully.
Locator: `srum:<relpath>:app:<i>` / `srum:<relpath>:net:<AutoIncId>`.
"""
from __future__ import annotations

import datetime
import json
import struct
from pathlib import Path

from ..store.case_db import CaseDB

SOURCE = "srum"
_UTC = datetime.timezone.utc
_OLE_EPOCH = datetime.datetime(1899, 12, 30, tzinfo=_UTC)
_FT_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=_UTC)
_APP_USAGE = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
_NET_CONN = "{DD6636C4-8929-4683-974E-22C046A43763}"


def _ole(val) -> str:
    """SRUM TimeStamp: an OLE-automation date (float64) stored in an int64 column."""
    if not val:
        return ""
    try:
        days = struct.unpack("<d", struct.pack("<q", int(val)))[0]
        return (_OLE_EPOCH + datetime.timedelta(days=days)).isoformat()
    except (struct.error, OverflowError, ValueError, OSError):
        return ""


def _filetime(val) -> str:
    if not val:
        return ""
    try:
        return (_FT_EPOCH + datetime.timedelta(microseconds=int(val) / 10)).isoformat()
    except (OverflowError, ValueError):
        return ""


def _sid(blob: bytes) -> str:
    try:
        if len(blob) < 8:
            return ""
        rev, subcount = blob[0], blob[1]
        if rev != 1 or len(blob) < 8 + subcount * 4:
            return ""
        authority = int.from_bytes(blob[2:8], "big")
        subs = [int.from_bytes(blob[8 + i * 4:12 + i * 4], "little") for i in range(subcount)]
        return "S-1-%d-%s" % (authority, "-".join(map(str, subs)))
    except Exception:
        return ""


def _decode_id(itype, blob, idx) -> str:
    if not blob:
        return f"Id{idx}"
    if itype == 3:                        # user -> SID
        sid = _sid(blob)
        if sid:
            return sid
    try:
        s = blob.decode("utf-16-le", "replace").replace("\x00", "").strip()
        if s:
            return s
    except Exception:
        pass
    return _sid(blob) or f"Id{idx}"


def _idmap(db) -> dict:
    out = {}
    try:
        for r in db.table("SruDbIdMapTable").records():
            idx = r.get("IdIndex")
            if idx is not None:
                out[idx] = _decode_id(r.get("IdType"), r.get("IdBlob"), idx)
    except Exception:
        pass
    return out


def _table(db, name):
    try:
        return db.table(name)
    except Exception:
        return None


def _emit(case, rel, loc_suffix, category, summary, ts, fields):
    case.add_event(source_artifact=SOURCE,
                   summary=summary[:600] + "  [+more fields — get_raw_event]",
                   locator=f"{SOURCE}:{rel}:{loc_suffix}", ts=ts, user="",
                   event_type=f"{SOURCE}:{category}", raw=json.dumps(fields, default=str))


def parse(case: CaseDB, root: Path, dir_code: str) -> None:
    try:
        from dissect.esedb import EseDB
    except ImportError:
        print("    [srum] dissect.esedb not installed (pip install dissect.esedb); skipping", flush=True)
        return

    base = root / dir_code
    dbs = list(base.rglob("SRUDB.dat"))
    if not dbs:
        print("    [srum] no SRUDB.dat found; skipping", flush=True)
        return

    total = 0
    for fp in dbs:
        rel = fp.relative_to(root).as_posix()
        try:
            db = EseDB(fp.open("rb"))
        except Exception as e:
            print(f"    [srum] could not open {rel}: {e}", flush=True)
            continue
        idmap = _idmap(db)

        # --- Application resource usage: aggregate per app ---
        appt = _table(db, _APP_USAGE)
        if appt:
            agg: dict[tuple, dict] = {}
            for r in appt.records():
                app = idmap.get(r.get("AppId"), f"App{r.get('AppId')}")
                user = idmap.get(r.get("UserId"), "")
                ts = _ole(r.get("TimeStamp"))
                br = (r.get("ForegroundBytesRead") or 0) + (r.get("BackgroundBytesRead") or 0)
                bw = (r.get("ForegroundBytesWritten") or 0) + (r.get("BackgroundBytesWritten") or 0)
                a = agg.setdefault((app, user), {"app": app, "user": user, "samples": 0,
                                                 "first": ts, "last": ts, "bytes_read": 0, "bytes_written": 0})
                a["samples"] += 1
                a["bytes_read"] += br
                a["bytes_written"] += bw
                if ts:
                    if not a["first"] or ts < a["first"]:
                        a["first"] = ts
                    if not a["last"] or ts > a["last"]:
                        a["last"] = ts
            for i, a in enumerate(agg.values()):
                summary = (f"[SRUM app] {a['app']} user={a['user']} active {a['first']}..{a['last']} "
                           f"samples={a['samples']} bytesRead={a['bytes_read']} bytesWritten={a['bytes_written']}")
                _emit(case, rel, f"app:{i}", "app", summary, a["last"], a)
                total += 1

        # --- Network connectivity: one event per record ---
        nett = _table(db, _NET_CONN)
        if nett:
            for r in nett.records():
                app = idmap.get(r.get("AppId"), f"App{r.get('AppId')}")
                start = _filetime(r.get("ConnectStartTime"))
                fields = {k.name: r.get(k.name) for k in nett.columns}
                fields["_app"] = app
                fields["_ConnectStartTime"] = start
                summary = (f"[SRUM net] {app} connected={r.get('ConnectedTime')}s start={start} "
                           f"interfaceLuid={r.get('InterfaceLuid')}")
                _emit(case, rel, f"net:{r.get('AutoIncId')}", "network", summary, start, fields)
                total += 1
        case.commit()
    print(f"    [srum] emitted {total} SRUM events", flush=True)
