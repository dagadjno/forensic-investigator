#!/usr/bin/env python
"""Run `main.py investigate` across MANY host collections in parallel.

Each host runs as its own process with its own `output/<case-id>/case.db` — no shared state,
so this is the simplest, lowest-risk speedup for a multi-host CTF (the orchestrator itself is
still sequential per host). Concurrency is bounded by --jobs to respect the API rate limit and
CPU. Each host's console output goes to `output/<case-id>/run.log`; this driver prints a
one-line status as each finishes.

    # parse every host once (no AI), 4 at a time:
    python run_hosts.py "C:/.../FORENSICS/ACQ-IR-*" --ingest-only --jobs 4

    # investigate every host against a question set:
    python run_hosts.py "C:/.../FORENSICS/ACQ-IR-*" --questions questions.txt --relevant-only --jobs 3
"""
from __future__ import annotations

import argparse
import glob
import re
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from src import ui

ROOT = Path(__file__).resolve().parent

# Serialize console writes so concurrent hosts don't garble each other's lines.
_PRINT_LOCK = threading.Lock()
# Per-host tag colors (cycled) so you can follow one host's stream amid the others.
_TAG_COLORS = ["cyan", "green", "yellow", "magenta", "blue", "red"]


def _short(case_id: str) -> str:
    """ACQ-IR-namtdc01-20250702-0100 -> namtdc01 (a compact console tag)."""
    return re.sub(r"-\d{8}-\d{4}$", "", re.sub(r"^ACQ-IR-", "", case_id)) or case_id


def _answer_count(case_id: str):
    db = ROOT / "output" / case_id / "case.db"
    if not db.exists():
        return "?"
    try:
        con = sqlite3.connect(db)
        n = con.execute("SELECT COUNT(DISTINCT question_id) FROM answers").fetchone()[0]
        con.close()
        return n
    except Exception:
        return "?"


def _run_one(host_dir: Path, py: str, fwd: list[str], stream: bool, color: str):
    case_id = host_dir.name
    out_dir = ROOT / "output" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = ui.c(f"[{_short(case_id)}]", color, "bold")
    # -u: unbuffered child so its step lines reach us live (not block-buffered when piped).
    cmd = [py, "-u", str(ROOT / "main.py"), "investigate", str(host_dir), "--case-id", case_id, *fwd]
    t0 = time.time()
    # main.py writes out_dir/run.log itself now (timestamped, full investigation). Here we only
    # relay the child's live output to the console so concurrent hosts can be followed.
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace", bufsize=1)
    for line in proc.stdout:
        if stream:
            with _PRINT_LOCK:
                print(f"{tag} {line.rstrip()}", flush=True)
    proc.wait()
    return case_id, proc.returncode, time.time() - t0


def main() -> int:
    ap = argparse.ArgumentParser(description="Run investigations across hosts in parallel.")
    ap.add_argument("patterns", nargs="+", metavar="PATTERN",
                    help="one or more globs/paths for host collection dirs. One glob for all "
                         "(e.g. '.../ACQ-IR-*'), or list specific hosts: "
                         "'.../ACQ-IR-dc01-*' '.../ACQ-IR-ws003-*'")
    ap.add_argument("--jobs", type=int, default=3, help="max concurrent hosts (default 3)")
    ap.add_argument("--python", default=sys.executable, help="python used to run main.py")
    ap.add_argument("--quiet", action="store_true",
                    help="don't stream per-host step output to the console (logs still written); "
                         "only print a line as each host finishes")
    # forwarded to `main.py investigate`
    ap.add_argument("--questions")
    ap.add_argument("--question", action="append")
    ap.add_argument("--relevant-only", action="store_true")
    ap.add_argument("--only")
    ap.add_argument("--expand", action="store_true")
    ap.add_argument("--reingest", action="store_true")
    ap.add_argument("--ingest-only", action="store_true")
    ap.add_argument("--artifact-map")
    args = ap.parse_args()

    # Union every pattern's matches (dedup, keep first-seen order) so you can name specific hosts.
    hosts, seen = [], set()
    for pat in args.patterns:
        for p in sorted(glob.glob(pat)):
            rp = str(Path(p).resolve())
            if Path(p).is_dir() and rp not in seen:
                seen.add(rp); hosts.append(Path(p))
    if not hosts:
        print(f"no host directories matched: {args.patterns}", file=sys.stderr)
        return 2

    fwd: list[str] = []
    if args.questions:     fwd += ["--questions", args.questions]
    for q in (args.question or []): fwd += ["--question", q]
    if args.relevant_only: fwd += ["--relevant-only"]
    if args.only:          fwd += ["--only", args.only]
    if args.expand:        fwd += ["--expand"]
    if args.reingest:      fwd += ["--reingest"]
    if args.ingest_only:   fwd += ["--ingest-only"]
    if args.artifact_map:  fwd += ["--artifact-map", args.artifact_map]

    print(f"{ui.EMOJI['search']} {ui.c('run_hosts', 'cyan', 'bold')}: {len(hosts)} host(s), "
          f"{args.jobs} at a time  {ui.c('[' + ' '.join(fwd) + ']', 'gray')}")
    for i, h in enumerate(hosts):
        print(f"    - {ui.c(_short(h.name), _TAG_COLORS[i % len(_TAG_COLORS)])}  ({h.name})")
    if not args.quiet:
        print(f"  {ui.c('streaming per-host step output below, tagged [host] — pass --quiet to silence', 'gray')}")

    done, failed, t0 = 0, 0, time.time()
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(_run_one, h, args.python, fwd, not args.quiet,
                          _TAG_COLORS[i % len(_TAG_COLORS)]): h for i, h in enumerate(hosts)}
        for fut in as_completed(futs):
            case_id, rc, dt = fut.result()
            done += 1
            ok = rc == 0
            failed += 0 if ok else 1
            mark = ui.EMOJI['ok'] if ok else ui.EMOJI['error']
            extra = f"answers={_answer_count(case_id)}" if not args.ingest_only else "parsed"
            print(f"  {mark} [{done}/{len(hosts)}] {ui.c(case_id, 'bold')}  exit={rc}  "
                  f"{dt/60:.1f}min  {extra}  {ui.c('(log: output/' + case_id + '/run.log)', 'gray')}",
                  flush=True)

    mins = (time.time() - t0) / 60
    tag = ui.c('all done', 'green', 'bold') if not failed else ui.c(f'{failed} failed', 'red', 'bold')
    print(f"\n{ui.EMOJI['ok']} {tag}: {done} host(s) in {mins:.1f}min wall-clock")

    # After an investigation sweep, collate all hosts into one combined answer sheet so you
    # don't have to open each report to find which host answered (skip for --ingest-only).
    if not args.ingest_only:
        out_root = str(ROOT / "output")
        if subprocess.run([args.python, str(ROOT / "scripts" / "aggregate.py"),
                           "--root", out_root]).returncode == 0:
            print(f"    {ui.EMOJI['report']} combined sheet: "
                  f"{ui.c('output/_combined/answer_sheet.md', 'bold')}")
        html_cmd = [args.python, str(ROOT / "scripts" / "report_html.py"), "--root", out_root]
        if args.questions:   # number the combined dashboard by the asked order (file)
            html_cmd += ["--questions", args.questions]
        for qq in (args.question or []):   # ...and/or inline --question order
            html_cmd += ["--question", qq]
        if subprocess.run(html_cmd).returncode == 0:
            print(f"    {ui.EMOJI['report']} interactive dashboard: "
                  f"{ui.c('output/_combined/report.html', 'bold')} (search/filter/sort)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
