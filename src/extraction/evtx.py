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
from .progress import status as _status, status_done as _status_done
from ..ui import EMOJI, c

SOURCE = "event_logs"

# High-value event IDs per channel family. (A channel may instead use ids=None below,
# meaning "keep ALL event IDs" — used for low-volume, uniformly-high-value channels.)
_SEC = {
    # logon / session
    4624, 4625, 4634, 4647, 4648, 4672, 4778, 4779, 4964,
    # process / service creation
    4688, 4689, 4697,
    # account management
    4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767, 4781,
    # group management (AD: create/delete/change + member add/remove, all scopes)
    4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4737, 4754, 4755, 4756, 4757, 4764,
    # Kerberos / NTLM — DC authentication, lateral movement, ticket attacks
    4768, 4769, 4771, 4776, 4777,
    # account/group enumeration (recon)
    4798, 4799,
    # scheduled tasks (also logged in Security)
    4698, 4699, 4700, 4701, 4702,
    # file-share access
    5140, 5142, 5143, 5144, 5145,
    # anti-forensics / audit tampering
    1102, 1100, 4719, 4616,
}
_SYS = {7045, 7040, 7036, 7034, 7031, 7022, 7009, 7001, 7000, 104, 6005, 6006, 6008}
_PS = {4103, 4104, 400, 403, 600, 800}
_SYSMON = set(range(1, 30))
_TASK = {106, 140, 141, 200, 201, 202, 4698, 4699, 4700, 4701, 4702}
_RDP = {21, 22, 23, 24, 25, 39, 40, 1149}
_WINRM = {6, 91, 168}
_DEFENDER = {1006, 1007, 1008, 1009, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012}
_WMI = {5857, 5859, 5860, 5861}  # provider load + consumer/filter/binding (WMI persistence)

# (filename substring, family label, interesting-id set). FIRST MATCH WINS, so specific
# channels must precede the generic "security.evtx"/"system.evtx" entries — e.g. the SMB
# Security logs end in "...%4Security.evtx" and would otherwise be captured as "Security".
# ids=None means "keep every event ID in this channel" (for low-volume, high-value logs).
_CHANNELS = [
    ("powershell%4operational", "PowerShell-Op", _PS),
    ("windows powershell.evtx", "PowerShell", _PS),
    ("sysmon%4operational", "Sysmon", _SYSMON),
    ("taskscheduler%4operational", "TaskScheduler", _TASK),
    ("terminalservices-localsessionmanager%4operational", "RDP", _RDP),
    ("terminalservices-remoteconnectionmanager%4operational", "RDP", _RDP),
    ("terminalservices-rdpclient%4operational", "RDP-Client", None),   # outbound RDP (lateral src)
    ("windows defender%4operational", "Defender", _DEFENDER),
    ("winrm%4operational", "WinRM", _WINRM),
    ("wmi-activity%4operational", "WMI", _WMI),                        # WMI persistence
    ("bits-client%4operational", "BITS", None),                       # downloads via BITS
    ("applocker", "AppLocker", None),                                 # blocked/allowed execution
    ("smbserver%4security", "SMB", None),                             # share auth/access (server)
    ("smbclient%4security", "SMB", None),                             # share auth/access (client)
    ("directory service.evtx", "DirSvc", None),                       # AD directory changes (DCs)
    # Core logs last (their substrings are generic).
    ("security.evtx", "Security", _SEC),
    ("system.evtx", "System", _SYS),
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
        try:
            size_mb = fp.stat().st_size / (1024 * 1024)
        except OSError:
            size_mb = 0
        # Heartbeat: a single line per channel that UPDATES IN PLACE while scanning (a DC's
        # Security.evtx can hold millions of records), then finalizes to one permanent line.
        label = f"[evtx] {family} {fp.name} ({size_mb:.0f} MB)"
        scanned = kept = 0
        _status(f"    {label}: scanning...")
        for rec_id, ts, xml in _iter_records(fp, backend):
            scanned += 1
            if scanned % 25000 == 0:
                _status(f"    {label}: {scanned:,} scanned, {emitted:,} kept")
            eid, computer, time, sec_user, data = _parse_xml(xml)
            if eid is None or (ids is not None and eid not in ids):
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
            kept += 1
        case.commit()
        _status_done(f"    [evtx] {family} {fp.name}: {scanned:,} records, {kept:,} kept")
    print(f"    {EMOJI['ok']} {c('[evtx]', 'green', 'bold')} parsed {parsed} high-value channels, "
          f"emitted {c(str(emitted), 'bold')} events (backend: {backend})", flush=True)
