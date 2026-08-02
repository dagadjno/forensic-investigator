"""Parser: Linux package-manager logs (`VarLog` — dpkg.log, apt/history.log).

The package install/remove/upgrade timeline: how tools or malware arrived via the package
manager, and — from apt's history — the **exact command line** the operator ran (attacker
installing tooling). source="package".

Locators: `package:VarLog/dpkg.log:<lineno>` / `package:VarLog/apt/history.log:<block-start>`.
"""
from __future__ import annotations

from pathlib import Path

from ..store.case_db import CaseDB
from ..textutil import read_text_auto
from .progress import status_done
from ..ui import EMOJI, c

SOURCE = "package"
_MAX = 8000
_DPKG_ACTIONS = {"install", "remove", "purge", "upgrade"}


def _parse_dpkg(case, root, fp, n_emitted):
    """dpkg.log line: `YYYY-MM-DD HH:MM:SS <action> <pkg:arch> <old> <new>`."""
    rel = fp.relative_to(root).as_posix()
    for n, line in enumerate(read_text_auto(fp).splitlines(), 1):
        if n_emitted[0] >= _MAX:
            break
        parts = line.split()
        if len(parts) >= 4 and parts[2] in _DPKG_ACTIONS:
            ts = f"{parts[0]}T{parts[1]}"
            summary = f"[dpkg {parts[2]}] {parts[3]} {' '.join(parts[4:])}".strip()
            case.add_event(source_artifact=SOURCE, summary=summary[:400],
                           locator=f"{SOURCE}:{rel}:{n}", ts=ts,
                           event_type=f"package:dpkg:{parts[2]}", raw=line)
            n_emitted[0] += 1


def _parse_apt_history(case, root, fp, n_emitted):
    """apt/history.log blocks: Start-Date / Commandline / Install / Remove / End-Date."""
    rel = fp.relative_to(root).as_posix()
    block: dict[str, str] = {}
    start_line = 0

    def flush():
        if not block:
            return
        ts = "T".join((block.get("Start-Date", "") or "").split())
        bits = []
        if block.get("Commandline"):
            bits.append(f"cmd={block['Commandline']}")
        if block.get("Install"):
            bits.append(f"install={block['Install']}")
        if block.get("Remove"):
            bits.append(f"remove={block['Remove']}")
        if block.get("Purge"):
            bits.append(f"purge={block['Purge']}")
        case.add_event(source_artifact=SOURCE, summary=("[apt] " + " ; ".join(bits))[:600],
                       locator=f"{SOURCE}:{rel}:{start_line}", ts=ts, event_type="package:apt",
                       raw="\n".join(f"{k}: {v}" for k, v in block.items()))
        n_emitted[0] += 1

    for n, line in enumerate(read_text_auto(fp).splitlines(), 1):
        if n_emitted[0] >= _MAX:
            break
        if not line.strip():
            flush()
            block = {}
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            if k == "Start-Date":
                start_line = n
            block[k] = v.strip()
    flush()


def parse(case: CaseDB, root: Path, dir_code: str) -> None:
    base = root / dir_code
    n_emitted = [0]
    for fp in base.rglob("*"):
        if not fp.is_file():
            continue
        name = fp.name.lower()
        try:
            if name == "dpkg.log" or name.startswith("dpkg.log."):
                _parse_dpkg(case, root, fp, n_emitted)
            elif name == "history.log" and "apt" in fp.as_posix().lower():
                _parse_apt_history(case, root, fp, n_emitted)
        except OSError:
            continue
    case.commit()
    status_done(f"    {EMOJI['ok']} {c('[package]', 'green', 'bold')} emitted "
                f"{c(str(n_emitted[0]), 'bold')} package events")
