"""Compatibility preflight for a triage collection.

Parsers degrade *silently* on an unfamiliar layout (skip missing files, emit 0 events), so
a collection from a different/newer collector can look like it "worked" while producing an
almost-empty timeline. This checks a collection against the loaded artifact map BEFORE a
real run and reports, with no LLM/cost:
  - which top-level dir-codes are KNOWN (mapped) vs UNKNOWN (new layout),
  - for each parseable bucket present, whether the parser's expected inputs exist,
  - for the CSV parsers (browser, usn), whether the expected columns are present.

Powers `python main.py check <collection_dir>`.
"""
from __future__ import annotations

import csv
from pathlib import Path

from .extraction import registry
from .ui import EMOJI, c


# parser-name -> detector returning the expected input files under a bucket folder
def _evtx(base):    return list(base.rglob("*.evtx"))
def _browser(base): return list(base.rglob("*.csv"))
def _usn(base):     return [p for p in base.rglob("*.csv") if "usn" in p.name.lower()]
def _srum(base):    return list(base.rglob("SRUDB.dat"))
def _lnk(base):     return list(base.rglob("*.lnk"))
def _psh(base):     return [p for p in base.rglob("*") if p.is_file()
                            and ("history" in p.name.lower() or p.suffix.lower() == ".txt")]
def _registry(base): return [p for p in base.rglob("*") if p.is_file() and registry._hive_type(p.name)]
# Linux parsers
def _syslog(base):   return [p for p in base.rglob("*") if p.is_file() and
                             (p.name.lower().startswith(("auth.log", "syslog"))
                              or p.name.lower() in ("secure", "kern.log", "messages", "daemon.log", "user.log"))]
def _packages(base): return [p for p in base.rglob("*") if p.is_file() and
                             (p.name.lower().startswith("dpkg.log")
                              or (p.name.lower() == "history.log" and "apt" in p.as_posix().lower()))]
def _bodyfile(base): return [p for p in base.rglob("*") if p.is_file() and "bodyfile" in p.name.lower()]
def _shell(base):    return [p for p in base.rglob("*") if p.is_file() and p.name in
                             {".bash_history", ".zsh_history", ".sh_history", ".history", ".python_history"}]
def _proc(base):     return [p for p in base.rglob("*") if p.is_file()
                             and p.name in ("proc-CommandLines.dat", "PSList.dat")]

_DETECT = {"evtx": _evtx, "registry": _registry, "psh": _psh, "browser": _browser,
           "usn": _usn, "srum": _srum, "lnk": _lnk,
           "syslog": _syslog, "packages": _packages, "bodyfile": _bodyfile,
           "shell_history": _shell, "proc": _proc}


def _parser_names(spec: dict) -> list[str]:
    """A bucket may declare one parser or a list (e.g. Linux VarLog: [syslog, packages])."""
    p = spec.get("parser")
    return [] if not p else (list(p) if isinstance(p, (list, tuple)) else [p])


def _browser_cols_ok(files) -> bool:
    """The browser parser keys on columns like URL / Visit Time / Filename (case-insensitive)."""
    for fp in files:
        try:
            with fp.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
                hdr = next(csv.reader(fh), [])
            if {h.lower() for h in hdr} & {"url", "visit time", "filename", "download url"}:
                return True
        except OSError:
            continue
    return False


def _usn_cols_ok(files) -> bool:
    """The USN parser skips a preamble to a `Usn,` header with File name / Reason / Time stamp."""
    for fp in files:
        try:
            with fp.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
                for line in fh:
                    if line.startswith("Usn,"):
                        cols = {x.lower() for x in next(csv.reader([line]))}
                        return {"file name", "reason", "time stamp"} <= cols
        except OSError:
            continue
    return False


def check(collection: Path, artifact_map: dict) -> int:
    """Print a compatibility report. Returns 0 if compatible, 1 if partial/unrecognized.

    Distinguishes real incompatibility (unknown dir-codes = renamed layout; CSV columns the
    parser can't read) from benign per-host variation (a correctly-named bucket that's simply
    empty — e.g. a host with no SRUDB.dat)."""
    arts = artifact_map["artifacts"]
    present = sorted(p.name for p in collection.iterdir() if p.is_dir())
    known = [d for d in present if d in arts]
    unknown = [d for d in present if d not in arts]
    parseable_codes = [d for d, s in arts.items() if _parser_names(s)]
    missing_parseable = [d for d in parseable_codes if d not in present]

    print(f"\n{EMOJI['search']} Compatibility check: {collection}")
    print(f"   artifact map: {len(arts)} known dir-codes | top-level folders found: {len(present)}\n")

    ok, empty, catalog_only = 0, [], 0   # ok = buckets with readable parser input
    issues: list[str] = []               # real problems: parser present but format unreadable

    print("  KNOWN dir-codes:")
    for d in known:
        spec = arts[d]
        plist = _parser_names(spec)
        if not plist:
            catalog_only += 1
            print(f"    {d:10} -> {spec['type']:20} {c('(no parser; file-catalog / on-demand)', 'gray')}")
            continue
        # A bucket may have several parsers; gather inputs across all of them.
        files = [f for pn in plist for f in _DETECT.get(pn, lambda b: [])(collection / d)]
        if not files:
            empty.append(d)
            print(f"    {d:10} -> {spec['type']:20} "
                  f"{c('(empty — no ' + '/'.join(plist) + ' inputs here; ok if this host lacks it)', 'gray')}")
            continue
        cols_ok, note = True, f"{len(files)} file(s)"
        if "browser" in plist:
            cols_ok = _browser_cols_ok(files)
            note += " | columns " + ("OK" if cols_ok else c("UNRECOGNIZED", "yellow"))
        elif "usn" in plist:
            cols_ok = _usn_cols_ok([f for f in files if "usn" in f.name.lower()])
            note += " | header " + ("OK" if cols_ok else c("UNRECOGNIZED", "yellow"))
        print(f"    {d:10} -> {spec['type']:20} {EMOJI['ok'] if cols_ok else EMOJI['warn']} "
              f"{'/'.join(plist)}: {note}")
        if cols_ok:
            ok += 1
        else:
            issues.append(f"{d}: '{'/'.join(plist)}' files present but column/format unrecognized — "
                          f"the parser would misread them (adapt the parser's column candidates)")

    if unknown:
        print(f"\n  {EMOJI['warn']} UNKNOWN dir-codes (not in the artifact map — possible renamed/new "
              f"layout): {', '.join(unknown)}")
    if missing_parseable:
        print(f"  {c('parseable dir-codes not present in this collection:', 'gray')} "
              f"{', '.join(missing_parseable)}")

    # Verdict. Truly incompatible = NO recognized dir-codes at all (a foreign layout). A
    # recognized layout is always at least catalog-usable (the agent reads text files + POINTs),
    # so it's COMPATIBLE even with zero timeline parsers — flagged "catalog-only" so you know
    # there's no parsed timeline. Unreadable parser formats are the PARTIAL case.
    print()
    if not known:
        verdict = c("UNRECOGNIZED LAYOUT — no dir-codes in this collection matched the map", "red", "bold")
        rc = 1
    elif issues:
        verdict = c(f"PARTIAL — {len(issues)} bucket(s) the parser can't read", "yellow", "bold")
        rc = 1
    elif ok == 0:
        verdict = c("COMPATIBLE (catalog-only)", "green", "bold") + \
            c(" — recognized layout, but no timeline parser matched; the agent reads/POINTs at "
              "files directly (add parsers to build a timeline)", "gray")
        rc = 0
    else:
        verdict = c("COMPATIBLE", "green", "bold")
        rc = 0
    print(f"  Verdict: {verdict}")
    print(f"  parseable buckets with readable input: {ok} | catalog-only: {catalog_only} | "
          f"empty: {len(empty)} | unknown folders: {len(unknown)}")
    for i in issues:
        print(f"    - {EMOJI['warn']} {i}")
    if unknown:
        print(f"  → If an unmapped folder holds artifacts you want parsed, map it in a "
              f"--artifact-map YAML (copy config/artifact_map.yaml and add/rename codes).")
    return rc
