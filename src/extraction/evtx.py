"""Parser: Windows event logs (`Evt`, *.evtx — binary).

Deterministic extraction into the normalized timeline. To keep the timeline focused
and the run fast, we parse only high-value channels and, within each, only high-value
event IDs (a collection has ~338 evtx files / 263MB — parsing everything would bury the
agent in noise). Each emitted record gets a stable locator
`event_logs:<relpath>:<record_id>`.

Backend-agnostic: uses the fast Rust `evtx` package if available, else pure-Python
`python-evtx`. If neither is installed, Evt is skipped gracefully (the file catalog
still lets the agent POINT at the .evtx files).
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from ..store.case_db import CaseDB

SOURCE = "event_logs"

# High-value event IDs per channel family.
_SEC = {4624, 4625, 4634, 4647, 4648, 4672, 4688, 4689, 4697, 4698, 4699, 4700, 4701,
        4702, 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4738, 4740, 4756, 1102}
_SYS = {7045, 7034, 7036, 7040, 7022, 104, 6005, 6006, 6008}
_PS = {4103, 4104, 400, 403, 600, 800}
_SYSMON = set(range(1, 30))
_TASK = {106, 140, 141, 200, 201, 202, 4698, 4699, 4700, 4701, 4702}
_RDP = {21, 22, 23, 24, 25, 39, 40, 1149}
_WINRM = {6, 91, 168}
_DEFENDER = {1006, 1007, 1008, 1009, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012}

# (filename substring, family label, interesting-id set). First match wins.
_CHANNELS = [
    ("security.evtx", "Security", _SEC),
    ("system.evtx", "System", _SYS),
    ("powershell%4operational", "PowerShell-Op", _PS),
    ("windows powershell.evtx", "PowerShell", _PS),
    ("sysmon%4operational", "Sysmon", _SYSMON),
    ("taskscheduler%4operational", "TaskScheduler", _TASK),
    ("terminalservices-localsessionmanager%4operational", "RDP", _RDP),
    ("terminalservices-remoteconnectionmanager%4operational", "RDP", _RDP),
    ("windows defender%4operational", "Defender", _DEFENDER),
    ("winrm%4operational", "WinRM", _WINRM),
]

# Fields surfaced first in the summary when present (most useful for triage).
_KEY_FIELDS = ["SubjectUserName", "TargetUserName", "LogonType", "IpAddress",
               "WorkstationName", "NewProcessName", "Image", "CommandLine",
               "ParentImage", "ParentCommandLine", "ProcessName", "ServiceName",
               "ImagePath", "StartType", "ScriptBlockText", "TargetFilename",
               "DestinationIp", "DestinationPort", "DestinationHostname", "Protocol",
               "TargetObject", "Details", "TaskName", "AccountName", "MemberName"]


def _channel_for(fname: str):
    low = fname.lower()
    for sub, family, ids in _CHANNELS:
        if sub in low:
            return family, ids
    return None, None


def _backend():
    try:
        import evtx  # noqa: F401  (fast, Rust-backed)
        return "evtx"
    except ImportError:
        pass
    try:
        import Evtx.Evtx  # noqa: F401  (pure Python)
        return "pyevtx"
    except ImportError:
        return None


def _iter_records(path: Path, backend: str):
    """Yield (record_id, timestamp_str, xml_string)."""
    if backend == "evtx":
        from evtx import PyEvtxParser
        parser = PyEvtxParser(str(path))
        for rec in parser.records():
            yield rec.get("event_record_id"), rec.get("timestamp", ""), rec.get("data", "")
    else:
        from Evtx.Evtx import Evtx
        with Evtx(str(path)) as log:
            for rec in log.records():
                try:
                    yield rec.record_num(), rec.timestamp().isoformat(), rec.xml()
                except Exception:
                    continue


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_xml(xml: str):
    """Return (event_id:int|None, computer, time, user, data:dict)."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None, "", "", "", {}
    eid = None
    computer = time = user = ""
    data: dict[str, str] = {}
    for el in root:
        ln = _local(el.tag)
        if ln == "System":
            for s in el:
                sln = _local(s.tag)
                if sln == "EventID":
                    try:
                        eid = int((s.text or "").strip())
                    except ValueError:
                        eid = None
                elif sln == "Computer":
                    computer = (s.text or "").strip()
                elif sln == "TimeCreated":
                    time = s.attrib.get("SystemTime", "")
                elif sln == "Security":
                    user = s.attrib.get("UserID", "")
        elif ln in ("EventData", "UserData"):
            for d in el.iter():
                name = d.attrib.get("Name")
                val = (d.text or "").strip()
                if name and val:
                    data[name] = val
                elif ln == "UserData" and val:
                    data[_local(d.tag)] = val
    return eid, computer, time, user, data


def _summary(family: str, eid: int, data: dict) -> str:
    parts = []
    used = set()
    for k in _KEY_FIELDS:
        if k in data and data[k] and data[k] != "-":
            v = data[k].replace("\n", " ").strip()
            parts.append(f"{k}={v[:160]}")
            used.add(k)
    for k, v in data.items():           # any remaining fields
        if k in used or not v or v == "-":
            continue
        parts.append(f"{k}={v.replace(chr(10), ' ')[:80]}")
        if len(parts) >= 12:
            break
    summary = f"[{family} {eid}] " + "; ".join(parts)
    if len(summary) > 600:
        summary = summary[:600]
    # Tell the agent if fields were left out, and how to get them.
    total = sum(1 for v in data.values() if v and v != "-")
    dropped = total - len(parts)
    if dropped > 0:
        summary += f"  [+{dropped} more fields — get_raw_event]"
    return summary


def _user_of(data: dict, fallback: str) -> str:
    for k in ("TargetUserName", "SubjectUserName", "AccountName", "User"):
        v = data.get(k, "")
        if v and v != "-":
            return v
    return fallback


def parse(case: CaseDB, root: Path, dir_code: str) -> None:
    backend = _backend()
    if backend is None:
        print("    [evtx] no EVTX backend installed (pip install python-evtx); skipping Evt parse",
              flush=True)
        return

    base = root / dir_code
    files = [fp for fp in base.rglob("*.evtx") if fp.is_file()]
    parsed = emitted = 0
    for fp in files:
        family, ids = _channel_for(fp.name)
        if family is None:
            continue
        rel = fp.relative_to(root).as_posix()
        parsed += 1
        for rec_id, ts, xml in _iter_records(fp, backend):
            eid, computer, time, sec_user, data = _parse_xml(xml)
            if eid is None or eid not in ids:
                continue
            case.add_event(
                source_artifact=SOURCE,
                summary=_summary(family, eid, data),
                locator=f"{SOURCE}:{rel}:{rec_id}",
                ts=time or ts, host=computer, user=_user_of(data, sec_user),
                event_type=f"{family}:{eid}",
                raw=json.dumps(data),   # full field set, retrievable via get_raw_event
            )
            emitted += 1
        case.commit()
    print(f"    [evtx] parsed {parsed} high-value channels, emitted {emitted} events "
          f"(backend: {backend})", flush=True)
