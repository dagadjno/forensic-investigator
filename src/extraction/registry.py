"""Parser: Windows registry hives (`Reg` — binary).

Deterministic extraction of high-value keys into the normalized timeline
(source="registry"). Like the EVTX parser, this is a curated, extensible allowlist of
keys rather than a full hive dump — persistence, accounts, installed software, devices,
and user-activity artifacts that matter for triage (and often hold easter-egg answers).

Locator: `registry:<relpath>:<keypath>\\<value-or-subkey>`. Backend: python-registry
(pure Python). If it isn't installed, Reg is skipped gracefully (file catalog remains).
"""
from __future__ import annotations

import codecs
from pathlib import Path

from ..store.case_db import CaseDB

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
    return None  # SECURITY, UsrClass.dat, Amcache.hve, logs -> skip for now


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
    if isinstance(val, bytes):
        return val.hex()[:120]
    if isinstance(val, list):
        return "; ".join(str(x) for x in val)[:200]
    return str(val)


class _Emit:
    def __init__(self, case: CaseDB, rel: str, user: str):
        self.case, self.rel, self.user, self.n = case, rel, user, 0

    def __call__(self, category: str, summary: str, keypath: str, leaf: str = "", ts: str = ""):
        loc = f"{SOURCE}:{self.rel}:{keypath}" + (f"\\{leaf}" if leaf else "")
        self.case.add_event(source_artifact=SOURCE, summary=summary[:600], locator=loc,
                            ts=ts, user=self.user, event_type=f"{SOURCE}:{category}")
        self.n += 1


def _run_keys(reg, emit, base_paths, label="Run"):
    for kp in base_paths:
        k = _open(reg, kp)
        if not k:
            continue
        ts = str(k.timestamp())
        for v in k.values():
            emit("persistence", f"[{label}] {v.name()} = {_vstr(v.value())}", kp, v.name(), ts)


def _software(reg, emit):
    _run_keys(reg, emit, [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    ])
    # OS / owner info
    cv = _open(reg, "Microsoft\\Windows NT\\CurrentVersion")
    if cv:
        for name in ("ProductName", "CurrentBuild", "RegisteredOwner", "InstallDate", "RegisteredOrganization"):
            try:
                emit("osinfo", f"[OSInfo] {name} = {_vstr(cv.value(name).value())}",
                     "Microsoft\\Windows NT\\CurrentVersion", name, str(cv.timestamp()))
            except Exception:
                pass
    # Installed software (Uninstall)
    for kp in ("Microsoft\\Windows\\CurrentVersion\\Uninstall",
               "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"):
        k = _open(reg, kp)
        if not k:
            continue
        for sk in k.subkeys():
            try:
                name = sk.value("DisplayName").value()
            except Exception:
                continue
            ver = pub = ""
            try: ver = sk.value("DisplayVersion").value()
            except Exception: pass
            try: pub = sk.value("Publisher").value()
            except Exception: pass
            emit("software", f"[Installed] {name} {ver} ({pub})".strip(), kp, sk.name(),
                 str(sk.timestamp()))
    # Network profiles (SSIDs / networks seen)
    np = _open(reg, "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles")
    if np:
        for sk in np.subkeys():
            try:
                pn = sk.value("ProfileName").value()
                emit("network", f"[Network] {pn}",
                     "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles", sk.name(),
                     str(sk.timestamp()))
            except Exception:
                pass


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
            emit("system", f"[System] ComputerName = {cn.value('ComputerName').value()}",
                 f"{ccs}\\Control\\ComputerName\\ComputerName", "ComputerName", str(cn.timestamp()))
        except Exception:
            pass
    tz = _open(reg, f"{ccs}\\Control\\TimeZoneInformation")
    if tz:
        try:
            emit("system", f"[System] TimeZone = {tz.value('TimeZoneKeyName').value()}",
                 f"{ccs}\\Control\\TimeZoneInformation", "TimeZoneKeyName", str(tz.timestamp()))
        except Exception:
            pass
    # USB storage devices
    usb = _open(reg, f"{ccs}\\Enum\\USBSTOR")
    if usb:
        for cls in usb.subkeys():
            for inst in cls.subkeys():
                fn = ""
                try: fn = inst.value("FriendlyName").value()
                except Exception: pass
                emit("usb", f"[USB] {cls.name()} {fn}".strip(),
                     f"{ccs}\\Enum\\USBSTOR\\{cls.name()}", inst.name(), str(inst.timestamp()))
    # Services with a non-standard / suspicious ImagePath (potential persistence)
    svc = _open(reg, f"{ccs}\\Services")
    if svc:
        for sk in svc.subkeys():
            try:
                ip = sk.value("ImagePath").value()
            except Exception:
                continue
            if not ip:
                continue
            ipl = ip.lower()
            suspicious = any(m in ipl for m in _SVC_SUSPICIOUS)
            nonstd = not _norm_imagepath(ip).startswith(_SVC_STD_PREFIX)
            if suspicious or nonstd:
                start = ""
                try: start = sk.value("Start").value()
                except Exception: pass
                emit("service", f"[Service] {sk.name()}: ImagePath={ip} Start={start}",
                     f"{ccs}\\Services", sk.name(), str(sk.timestamp()))


def _sam(reg, emit):
    names = _open(reg, "SAM\\Domains\\Account\\Users\\Names")
    if names:
        for sk in names.subkeys():
            emit("account", f"[Account] {sk.name()}",
                 "SAM\\Domains\\Account\\Users\\Names", sk.name(), str(sk.timestamp()))


def _ntuser(reg, emit):
    _run_keys(reg, emit,
              ["Software\\Microsoft\\Windows\\CurrentVersion\\Run"], label="Run(user)")
    # Run-dialog history (commands the user typed)
    mru = _open(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
    if mru:
        for v in mru.values():
            if v.name() != "MRUList":
                emit("activity", f"[RunMRU] {_vstr(v.value())}",
                     "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", v.name(),
                     str(mru.timestamp()))
    # Explorer typed paths
    tp = _open(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths")
    if tp:
        for v in tp.values():
            emit("activity", f"[TypedPath] {_vstr(v.value())}",
                 "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", v.name(),
                 str(tp.timestamp()))
    # UserAssist (program execution; value names are ROT13-encoded paths)
    ua = _open(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    if ua:
        emitted = 0
        for guid in ua.subkeys():
            count = _open(reg, f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{guid.name()}\\Count")
            if not count:
                continue
            for v in count.values():
                decoded = codecs.decode(v.name(), "rot_13")
                if "UEME_" in decoded:   # skip session counters
                    continue
                emit("execution", f"[UserAssist] {decoded}",
                     f"...UserAssist\\{guid.name()}\\Count", v.name(), str(count.timestamp()))
                emitted += 1
                if emitted >= 150:
                    return


_HANDLERS = {"SOFTWARE": _software, "SYSTEM": _system, "SAM": _sam, "NTUSER": _ntuser}


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
        try:
            reg = Registry.Registry(str(fp))
        except Exception as e:
            print(f"    [registry] could not open {rel}: {e}", flush=True)
            continue
        emit = _Emit(case, rel, _user_from_path(rel) or ("SYSTEM" if htype != "NTUSER" else ""))
        try:
            _HANDLERS[htype](reg, emit)
        except Exception as e:
            print(f"    [registry] error parsing {rel}: {type(e).__name__}: {e}", flush=True)
        case.commit()
        total += emit.n
    print(f"    [registry] emitted {total} registry events", flush=True)
