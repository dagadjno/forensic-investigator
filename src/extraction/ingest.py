"""Deterministic ingest (no LLM).

Walks the read-only artifact root, builds the coverage manifest from the artifact
map, catalogs EVERY file's metadata (binaries included, so the agent can POINT at
them), and runs the available parsers to populate the normalized timeline.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from ..store.case_db import CaseDB
from . import browser, evtx, lnk, psh, registry, srum, usn

# parser name (from artifact_map.yaml) -> module with parse(case, root, dir_code)
PARSERS = {"psh": psh, "evtx": evtx, "registry": registry, "browser": browser,
           "lnk": lnk, "usn": usn, "srum": srum}

_TEXT_EXTS = {".txt", ".csv", ".log", ".ini", ".htm", ".html", ".json", ".xml", ".ps1", ".bat", ".md"}


def _iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _owner(path: Path) -> str:
    """Best-effort file owner. Windows owner lookup needs pywin32, which we don't
    require; fall back to empty. Path components often encode the user anyway."""
    return ""


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

    # 1. Coverage manifest — graceful about absent buckets (e.g. namtsh01 has no Psh).
    for code, spec in artifact_map["artifacts"].items():
        case.upsert_coverage(code, spec["type"], spec.get("parser"), code in present)

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
                path=rel, artifact=code, name=fp.name, owner=_owner(fp),
                size=st.st_size, mtime=_iso(st.st_mtime), ctime=_iso(st.st_ctime),
                atime=_iso(st.st_atime), is_text=fp.suffix.lower() in _TEXT_EXTS,
            )
    case.commit()

    # 3. Run parsers for buckets that have one.
    for code, spec in artifact_map["artifacts"].items():
        parser_name = spec.get("parser")
        if parser_name and code in present and parser_name in PARSERS:
            PARSERS[parser_name].parse(case, root, code)
    case.commit()
    case.set_meta("ingested", "1")
    return True
