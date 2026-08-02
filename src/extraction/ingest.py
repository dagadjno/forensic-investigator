"""Deterministic ingest (no LLM).

Walks the read-only artifact root, builds the coverage manifest from the artifact
map, catalogs EVERY file's metadata (binaries included, so the agent can POINT at
them), and runs the available parsers to populate the normalized timeline.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path

from ..store.case_db import CaseDB
from ..textutil import looks_text
from ..ui import EMOJI, c
from . import (bodyfile, browser, evtx, lnk, packages, proc, psh, registry,
               shell_history, srum, syslog, usn)

# parser name (from artifact_map.yaml) -> module with parse(case, root, dir_code)
PARSERS = {"psh": psh, "evtx": evtx, "registry": registry, "browser": browser,
           "lnk": lnk, "usn": usn, "srum": srum,
           # Linux parsers (see config/artifact_map.linux.yaml)
           "syslog": syslog, "packages": packages, "bodyfile": bodyfile,
           "shell_history": shell_history, "proc": proc}


def _parser_names(spec: dict) -> list[str]:
    """A bucket may declare one parser (`parser: usn`) or several (`parser: [syslog, packages]`
    — e.g. Linux VarLog holds both auth/syslog logs and package logs). Normalize to a list."""
    p = spec.get("parser")
    if not p:
        return []
    return list(p) if isinstance(p, (list, tuple)) else [p]


def _iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


_USER_IN_PATH = re.compile(r"(?:^|/)(?:Users|home)/([^/]+)/", re.IGNORECASE)


def _owner(rel: str) -> str:
    """Best-effort owner derived from the path. Real Windows owner lookup needs pywin32
    (not required), but triage paths almost always encode the user — e.g.
    `Reg/Users/olivia.parker/NTUSER.DAT`. Returns the `Users/<name>` component, or ""."""
    m = _USER_IN_PATH.search(rel)
    return m.group(1) if m else ""


def ingest(case: CaseDB, artifact_root: str | Path, artifact_map: dict,
           force: bool = False) -> bool:
    """Deterministic ingest. Idempotent: skips if already complete (resume), unless
    `force`. Returns True if it actually ingested, False if it skipped."""
    if case.get_meta("ingested") == "1" and not force:
        print("    ingest already complete for this case; skipping (resume). Use --reingest to redo.",
              flush=True)
        return False
    # Fresh or retried-after-partial-crash: clear any partial parse to avoid duplicates.
    case.clear_events_and_files()

    root = Path(artifact_root)
    present = {p.name for p in root.iterdir() if p.is_dir()}

    # OS family — drives which playbook set the sub-agent uses (Linux collections carry these
    # buckets; Windows ones don't). Stored so the agent picks Linux vs Windows domain knowledge.
    case.set_meta("os", "linux" if ({"VarLog", "Etc", "Home", "Svc"} & present) else "windows")

    # 1. Coverage manifest — graceful about absent buckets (e.g. namtsh01 has no Psh).
    for code, spec in artifact_map["artifacts"].items():
        parser = ",".join(_parser_names(spec)) or None
        case.upsert_coverage(code, spec["type"], parser, code in present)

    # 2. File-metadata catalog: every file under every present bucket.
    for code in present:
        if code not in artifact_map["artifacts"]:
            continue
        base = root / code
        for fp in base.rglob("*"):
            if not fp.is_file():
                continue
            try:
                st = fp.stat()
            except OSError:
                continue
            rel = fp.relative_to(root).as_posix()
            case.add_file(
                path=rel, artifact=code, name=fp.name, owner=_owner(rel),
                size=st.st_size, mtime=_iso(st.st_mtime), ctime=_iso(st.st_ctime),
                atime=_iso(st.st_atime), is_text=looks_text(fp, st.st_size),
            )
    case.commit()

    # 3. Run parsers for buckets that have one (a bucket may have several).
    for code, spec in artifact_map["artifacts"].items():
        if code not in present:
            continue
        for parser_name in _parser_names(spec):
            if parser_name in PARSERS:
                print(f"    {EMOJI['folder']} parsing {c(code, 'cyan', 'bold')} ({spec['type']}) "
                      f"via {parser_name} ...", flush=True)
                PARSERS[parser_name].parse(case, root, code)
    case.commit()
    case.set_meta("ingested", "1")
    return True
