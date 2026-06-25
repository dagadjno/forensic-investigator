"""On-demand Volatility3 memory analysis (targeted, not a bulk dump).

Memory images are multi-GB, so we never feed them to the LLM and never bulk-parse the
whole thing during ingest. Instead this shells out to Volatility3 (kept in its OWN venv /
install so its deps never touch the main tool) for a SPECIFIC plugin when a lead needs
memory-only evidence — process tree, network connections, injected code, cached creds.

Each plugin's JSON output is cached to disk keyed by (image, plugin, args), so a re-run is
free. Powers the `vol_run` tool; results are materialized into the timeline as
source="memory", one citable row per record (mirrors the mft_lookup pattern).

Volatility itself is invoked via a configurable command (`memory.vol_cmd` in config.yaml),
so it stays portable: a local venv, a system install, or `docker run ... volatility3`.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

# Plugins the agent may run, with the columns to feature in each row's one-line summary,
# plus which column (if any) carries a timestamp / a user. Anything not listed falls back
# to a generic key=value summary.
PLUGINS: dict[str, dict] = {
    "windows.pslist.PsList":   {"head": ["PID", "PPID", "ImageFileName", "CreateTime"], "ts": "CreateTime"},
    "windows.pstree.PsTree":   {"head": ["PID", "PPID", "ImageFileName", "CreateTime"], "ts": "CreateTime"},
    "windows.psscan.PsScan":   {"head": ["PID", "PPID", "ImageFileName", "CreateTime"], "ts": "CreateTime"},
    "windows.cmdline.CmdLine": {"head": ["PID", "Process", "Args"]},
    "windows.cmdscan.CmdScan": {"head": ["Process", "PID", "CommandLine"]},
    "windows.consoles.Consoles": {"head": ["PID", "Process", "CommandHistory", "Screen"]},
    "windows.netscan.NetScan": {"head": ["Proto", "LocalAddr", "LocalPort", "ForeignAddr",
                                          "ForeignPort", "State", "PID", "Owner", "Created"],
                                 "ts": "Created", "user": "Owner"},
    "windows.netstat.NetStat": {"head": ["Proto", "LocalAddr", "LocalPort", "ForeignAddr",
                                          "ForeignPort", "State", "PID", "Owner"], "user": "Owner"},
    "windows.svcscan.SvcScan": {"head": ["PID", "Name", "Display", "State", "Start", "Binary"]},
    "windows.dlllist.DllList": {"head": ["PID", "Process", "Path", "LoadTime"], "ts": "LoadTime"},
    "windows.getsids.GetSIDs": {"head": ["PID", "Process", "SID", "Name"]},
    "windows.envars.Envars":   {"head": ["PID", "Process", "Variable", "Value"]},
    "windows.sessions.Sessions": {"head": ["Session ID", "Process", "User Name", "Create Time"], "ts": "Create Time"},
    "windows.malfind.Malfind": {"head": ["PID", "Process", "Protection", "CommitCharge", "Notes"]},
    "windows.filescan.FileScan": {"head": ["Offset", "Name", "Size"]},
    "windows.registry.printkey.PrintKey": {"head": ["Hive Offset", "Key", "Name", "Data", "Type"]},
    "windows.registry.userassist.UserAssist": {"head": ["Hive Name", "Path", "Name", "Count", "Last Updated"]},
    # NOTE: Volatility3 2.28 has NO core hashdump/lsadump/cachedump — credential dumping
    # is not available as a built-in plugin. The realistic memory path to a typed secret is
    # consoles/cmdscan (what was typed at a console) or process Args (cmdline).
}


def supported() -> list[str]:
    return sorted(PLUGINS)


def _cache_path(cache_dir: Path, image: Path, plugin: str, extra: list[str]) -> Path:
    key = hashlib.sha1(str(image).encode()).hexdigest()[:10]
    tag = plugin + ("__" + "_".join(extra) if extra else "")
    tag = "".join(c if c.isalnum() or c in "._-" else "_" for c in tag)
    return cache_dir / key / f"{tag}.json"


def _flatten(rows: list, depth: int = 0, out: list | None = None) -> list[dict]:
    """Volatility JSON nests children under '__children' (e.g. pstree). Flatten to a list
    of plain rows, dropping the nesting key but keeping a _depth hint."""
    if out is None:
        out = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        kids = r.pop("__children", None)
        r["_depth"] = depth
        out.append(r)
        if kids:
            _flatten(kids, depth + 1, out)
    return out


def run_plugin(image: str | Path, plugin: str, vol_cmd: list[str], cache_dir: str | Path,
               extra_args: list[str] | None = None, timeout: int = 1200,
               force: bool = False) -> list[dict]:
    """Run one Volatility plugin against `image` and return a flat list of row dicts.
    Cached to disk; a cache hit skips Volatility entirely."""
    image, cache_dir = Path(image), Path(cache_dir)
    extra = list(extra_args or [])
    cpath = _cache_path(cache_dir, image, plugin, extra)
    if cpath.is_file() and not force:
        return json.loads(cpath.read_text(encoding="utf-8"))

    cmd = [*vol_cmd, "-q", "-r", "json", "-f", str(image), plugin, *extra]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = proc.stdout.strip()
    start = out.find("[")
    if start == -1:
        err = (proc.stderr or "").strip().splitlines()[-3:]
        raise RuntimeError(f"volatility produced no JSON for {plugin}: {' | '.join(err) or 'no output'}")
    rows = _flatten(json.loads(out[start:]))
    cpath.parent.mkdir(parents=True, exist_ok=True)
    cpath.write_text(json.dumps(rows), encoding="utf-8")
    return rows


def summarize(plugin: str, row: dict) -> str:
    """One-line, human/agent-readable summary of a plugin row."""
    spec = PLUGINS.get(plugin, {})
    head = spec.get("head")
    short = plugin.split(".")[-1].lower()
    if head:
        parts = [f"{k}={row[k]}" for k in head if row.get(k) not in (None, "", "-")]
    else:
        parts = [f"{k}={v}" for k, v in row.items()
                 if k not in ("__children", "_depth") and v not in (None, "", "-")]
    indent = "  " * int(row.get("_depth", 0))
    return f"[{short}] {indent}{' '.join(parts)}"


def event_fields(plugin: str, row: dict) -> dict:
    """Return (summary, ts, user) for materializing a timeline event."""
    spec = PLUGINS.get(plugin, {})
    ts = str(row.get(spec.get("ts", ""), "") or "")
    user = str(row.get(spec.get("user", ""), "") or "")
    return {"summary": summarize(plugin, row), "ts": ts, "user": user}
