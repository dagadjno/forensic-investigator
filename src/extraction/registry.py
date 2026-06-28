"""Parser: Windows registry hives (`Reg` — binary).

Deterministic extraction of high-value keys into the normalized timeline
(source="registry"). Like the EVTX parser, this is a curated, extensible allowlist of
keys rather than a full hive dump — persistence, accounts, installed software, devices,
and user-activity artifacts that matter for triage (and often hold easter-egg answers).

Each emitted row keeps a short summary PLUS the full underlying object stored as JSON in
`events.raw` (all values of a subkey, or the full value), so nothing is silently lost: a
capped summary ends with `[+N more fields — get_raw_event]` and the agent can fetch the
complete field set with the get_raw_event tool (same as for event logs).

This module also parses **Amcache.hve** (found in the Reg tree) — program-execution
evidence with SHA1 hashes — emitting it under a distinct `source="amcache"`.

Locator: `registry:<relpath>:<keypath>\\<value-or-subkey>` (amcache rows use an
`amcache:` prefix). Backend: python-registry (pure Python). If it isn't installed, Reg is
skipped gracefully (file catalog remains).
"""
from __future__ import annotations

import codecs
import json
from pathlib import Path

from ..store.case_db import CaseDB
from .progress import status, status_done
from ..ui import EMOJI, c

SOURCE = "registry"

# ImagePath markers that make a service worth surfacing (vs. the hundreds of normal ones).
_SVC_SUSPICIOUS = ("powershell", "cmd.exe", "\\temp\\", "\\users\\", "appdata",
                   ".ps1", "mshta", "rundll32", "regsvr32", "\\programdata\\",
                   "-enc", "wscript", "cscript", "bitsadmin", "certutil")
# A service ImagePath in one of these (after env-var normalization) is treated as normal.
_SVC_STD_PREFIX = ("c:\\windows", "c:\\program files", "\\systemroot", "system32\\",
                   "\\??\\c:\\windows", "\\driver\\", "\\filesystem\\")


def _norm_imagepath(ip: str) -> str:
    s = ip.lower().strip().strip('"')
    return (s.replace("%systemroot%", "c:\\windows")
             .replace("%windir%", "c:\\windows")
             .replace("\\systemroot\\", "c:\\windows\\"))


def _hive_type(name: str) -> str | None:
    n = name.lower()
    if n == "software":
        return "SOFTWARE"
    if n == "system":
        return "SYSTEM"
    if n == "sam":
        return "SAM"
    if n == "ntuser.dat":
        return "NTUSER"
    if n == "amcache.hve":
        return "AMCACHE"
    return None  # SECURITY, UsrClass.dat, logs -> skip for now


def _user_from_path(rel: str) -> str:
    parts = rel.split("/")
    if "Users" in parts:
        i = parts.index("Users")
        if i + 1 < len(parts):
            return parts[i + 1]
    return ""


def _open(reg, path):
    try:
        return reg.open(path)
    except Exception:
        return None


def _vstr(val) -> str:
    """Display form for the summary (truncated)."""
    if isinstance(val, bytes):
        return val.hex()[:120]
    if isinstance(val, list):
        return "; ".join(str(x) for x in val)[:200]
    return str(val)


def _vfull(val) -> str:
    """Full form for raw storage (untruncated)."""
    if isinstance(val, bytes):
        return val.hex()
    if isinstance(val, list):
        return "; ".join(str(x) for x in val)
    return str(val)


def _all_values(key) -> dict:
    """Every value under a key, name -> full value (the subkey's complete field set)."""
    out = {}
    try:
        for v in key.values():
            try:
                out[v.name() or "(default)"] = _vfull(v.value())
            except Exception:
                pass
    except Exception:
        pass
    return out


class _Emit:
    def __init__(self, case: CaseDB, rel: str, user: str, source: str = SOURCE):
        self.case, self.rel, self.user, self.source, self.n = case, rel, user, source, 0

    def __call__(self, category: str, summary: str, keypath: str, leaf: str = "",
                 ts: str = "", fields: dict | None = None):
        summary = summary[:560]
        raw = ""
        if fields:
            raw = json.dumps(fields)
            # Fields present in the full object but not shown in the summary.
            dropped = sum(1 for k in fields if (k + "=") not in summary and k not in summary)
            if dropped > 0:
                summary += f"  [+{dropped} more fields — get_raw_event]"
        loc = f"{self.source}:{self.rel}:{keypath}" + (f"\\{leaf}" if leaf else "")
        self.case.add_event(source_artifact=self.source, summary=summary[:640], locator=loc,
                            ts=ts, user=self.user, event_type=f"{self.source}:{category}", raw=raw)
        self.n += 1


def _run_keys(reg, emit, base_paths, label="Run"):
    for kp in base_paths:
        k = _open(reg, kp)
        if not k:
            continue
        ts = str(k.timestamp())
        for v in k.values():
            emit("persistence", f"[{label}] {v.name()} = {_vstr(v.value())}", kp, v.name(), ts,
                 fields={v.name() or "(default)": _vfull(v.value())})


def _software(reg, emit):
    _run_keys(reg, emit, [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    ])
    cv = _open(reg, "Microsoft\\Windows NT\\CurrentVersion")
    if cv:
        for name in ("ProductName", "CurrentBuild", "RegisteredOwner", "InstallDate", "RegisteredOrganization"):
            try:
                val = cv.value(name).value()
            except Exception:
                continue
            emit("osinfo", f"[OSInfo] {name} = {_vstr(val)}",
                 "Microsoft\\Windows NT\\CurrentVersion", name, str(cv.timestamp()),
                 fields={name: _vfull(val)})
    for kp in ("Microsoft\\Windows\\CurrentVersion\\Uninstall",
               "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"):
        k = _open(reg, kp)
        if not k:
            continue
        for sk in k.subkeys():
            vals = _all_values(sk)
            name = vals.get("DisplayName")
            if not name:
                continue
            ver, pub = vals.get("DisplayVersion", ""), vals.get("Publisher", "")
            emit("software", f"[Installed] {name} {ver} ({pub})".strip(), kp, sk.name(),
                 str(sk.timestamp()), fields=vals)
    np = _open(reg, "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles")
    if np:
        for sk in np.subkeys():
            vals = _all_values(sk)
            pn = vals.get("ProfileName")
            if pn:
                emit("network", f"[Network] {pn}",
                     "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles", sk.name(),
                     str(sk.timestamp()), fields=vals)


def _ccs(reg) -> str:
    sel = _open(reg, "Select")
    if sel:
        try:
            return "ControlSet%03d" % sel.value("Current").value()
        except Exception:
            pass
    return "ControlSet001"


def _system(reg, emit):
    ccs = _ccs(reg)
    cn = _open(reg, f"{ccs}\\Control\\ComputerName\\ComputerName")
    if cn:
        try:
            name = cn.value("ComputerName").value()
            emit("system", f"[System] ComputerName = {name}",
                 f"{ccs}\\Control\\ComputerName\\ComputerName", "ComputerName", str(cn.timestamp()),
                 fields={"ComputerName": _vfull(name)})
        except Exception:
            pass
    tz = _open(reg, f"{ccs}\\Control\\TimeZoneInformation")
    if tz:
        vals = _all_values(tz)
        if "TimeZoneKeyName" in vals:
            emit("system", f"[System] TimeZone = {vals['TimeZoneKeyName']}",
                 f"{ccs}\\Control\\TimeZoneInformation", "TimeZoneKeyName", str(tz.timestamp()),
                 fields=vals)
    usb = _open(reg, f"{ccs}\\Enum\\USBSTOR")
    if usb:
        for cls in usb.subkeys():
            for inst in cls.subkeys():
                vals = _all_values(inst)
                fn = vals.get("FriendlyName", "")
                emit("usb", f"[USB] {cls.name()} {fn}".strip(),
                     f"{ccs}\\Enum\\USBSTOR\\{cls.name()}", inst.name(), str(inst.timestamp()),
                     fields=vals)
    # SCSI bus — where disk / virtual-disk devices enumerate (e.g. an EBS volume appears as
    # `Disk&Ven_NVMe&Prod_Amazon_Elastic_B`; the device *model* is the truncated Prod_ in the
    # class-key name). Low-volume (a handful of disks), unlike PCI which we skip as noise.
    scsi = _open(reg, f"{ccs}\\Enum\\SCSI")
    if scsi:
        for cls in scsi.subkeys():
            for inst in cls.subkeys():
                vals = _all_values(inst)
                desc = vals.get("FriendlyName", "") or vals.get("DeviceDesc", "")
                emit("device", f"[Device] {cls.name()} {desc}".strip(),
                     f"{ccs}\\Enum\\SCSI\\{cls.name()}", inst.name(), str(inst.timestamp()),
                     fields=vals)
    svc = _open(reg, f"{ccs}\\Services")
    if svc:
        for sk in svc.subkeys():
            vals = _all_values(sk)
            ip = vals.get("ImagePath")
            if not ip:
                continue
            ipl = ip.lower()
            suspicious = any(m in ipl for m in _SVC_SUSPICIOUS)
            nonstd = not _norm_imagepath(ip).startswith(_SVC_STD_PREFIX)
            if suspicious or nonstd:
                emit("service", f"[Service] {sk.name()}: ImagePath={ip} Start={vals.get('Start','')}",
                     f"{ccs}\\Services", sk.name(), str(sk.timestamp()), fields=vals)


def _sam(reg, emit):
    names = _open(reg, "SAM\\Domains\\Account\\Users\\Names")
    if names:
        for sk in names.subkeys():
            emit("account", f"[Account] {sk.name()}",
                 "SAM\\Domains\\Account\\Users\\Names", sk.name(), str(sk.timestamp()),
                 fields=_all_values(sk) or {"username": sk.name()})


def _ntuser(reg, emit):
    _run_keys(reg, emit,
              ["Software\\Microsoft\\Windows\\CurrentVersion\\Run"], label="Run(user)")
    mru = _open(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
    if mru:
        for v in mru.values():
            if v.name() != "MRUList":
                emit("activity", f"[RunMRU] {_vstr(v.value())}",
                     "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", v.name(),
                     str(mru.timestamp()), fields={v.name(): _vfull(v.value())})
    tp = _open(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths")
    if tp:
        for v in tp.values():
            emit("activity", f"[TypedPath] {_vstr(v.value())}",
                 "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", v.name(),
                 str(tp.timestamp()), fields={v.name(): _vfull(v.value())})
    ua = _open(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    if ua:
        emitted = 0
        for guid in ua.subkeys():
            count = _open(reg, f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{guid.name()}\\Count")
            if not count:
                continue
            for v in count.values():
                decoded = codecs.decode(v.name(), "rot_13")
                if "UEME_" in decoded:
                    continue
                # keep the raw binary blob (holds run count + last-execution time)
                emit("execution", f"[UserAssist] {decoded}",
                     f"...UserAssist\\{guid.name()}\\Count", v.name(), str(count.timestamp()),
                     fields={"decoded": decoded, "encoded_name": v.name(),
                             "data_hex": _vfull(v.value())})
                emitted += 1
                if emitted >= 150:
                    return


def _amcache(reg, emit):
    """Amcache.hve — program execution evidence with SHA1 hashes (emitted as source='amcache')."""
    appfile = _open(reg, "Root\\InventoryApplicationFile")
    if appfile:
        for sk in appfile.subkeys():
            vals = _all_values(sk)
            path = vals.get("LowerCaseLongPath") or vals.get("Name", "")
            sha1 = vals.get("FileId", "")
            if len(sha1) >= 44 and sha1.startswith("0000"):  # FileId = "0000" + 40-hex SHA1
                sha1 = sha1[4:]
            summary = (f"[AmcacheFile] {path} sha1={sha1} size={vals.get('Size', '')} "
                       f"publisher={vals.get('Publisher', '')} linkdate={vals.get('LinkDate', '')}")
            emit("file", summary, "Root\\InventoryApplicationFile", sk.name(),
                 str(sk.timestamp()), fields=vals)
    app = _open(reg, "Root\\InventoryApplication")
    if app:
        for sk in app.subkeys():
            vals = _all_values(sk)
            summary = (f"[AmcacheApp] {vals.get('Name', '')} {vals.get('Version', '')} "
                       f"({vals.get('Publisher', '')}) installed={vals.get('InstallDate', '')} "
                       f"root={vals.get('RootDirPath', '')}")
            emit("program", summary, "Root\\InventoryApplication", sk.name(),
                 str(sk.timestamp()), fields=vals)


_HANDLERS = {"SOFTWARE": _software, "SYSTEM": _system, "SAM": _sam, "NTUSER": _ntuser,
             "AMCACHE": _amcache}


def parse(case: CaseDB, root: Path, dir_code: str) -> None:
    try:
        from Registry import Registry
    except ImportError:
        print("    [registry] python-registry not installed (pip install python-registry); skipping Reg",
              flush=True)
        return

    base = root / dir_code
    total = 0
    for fp in base.rglob("*"):
        if not fp.is_file():
            continue
        htype = _hive_type(fp.name)
        if htype is None:
            continue
        rel = fp.relative_to(root).as_posix()
        status(f"    [registry] {htype} {fp.name} ({total} events so far) ...")
        try:
            reg = Registry.Registry(str(fp))
        except Exception as e:
            print(f"    [registry] could not open {rel}: {e}", flush=True)
            continue
        source = "amcache" if htype == "AMCACHE" else SOURCE
        emit = _Emit(case, rel, _user_from_path(rel) or ("SYSTEM" if htype != "NTUSER" else ""),
                     source=source)
        try:
            _HANDLERS[htype](reg, emit)
        except Exception as e:
            print(f"    [registry] error parsing {rel}: {type(e).__name__}: {e}", flush=True)
        case.commit()
        total += emit.n
    status_done(f"    {EMOJI['ok']} {c('[registry]', 'green', 'bold')} emitted {c(str(total), 'bold')} "
                f"registry/amcache events")
