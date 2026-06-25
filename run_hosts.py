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
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from src import ui

ROOT = Path(__file__).resolve().parent


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


def _run_one(host_dir: Path, py: str, fwd: list[str]):
    case_id = host_dir.name
    out_dir = ROOT / "output" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [py, str(ROOT / "main.py"), "investigate", str(host_dir), "--case-id", case_id, *fwd]
    t0 = time.time()
    with (out_dir / "run.log").open("w", encoding="utf-8") as fh:
        proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, text=True)
    return case_id, proc.returncode, time.time() - t0


def main() -> int:
    ap = argparse.ArgumentParser(description="Run investigations across hosts in parallel.")
    ap.add_argument("pattern", help="glob for host collection dirs, e.g. '.../ACQ-IR-*'")
    ap.add_argument("--jobs", type=int, default=3, help="max concurrent hosts (default 3)")
    ap.add_argument("--python", default=sys.executable, help="python used to run main.py")
    # forwarded to `main.py investigate`
    ap.add_argument("--questions")
    ap.add_argument("--relevant-only", action="store_true")
    ap.add_argument("--only")
    ap.add_argument("--expand", action="store_true")
    ap.add_argument("--reingest", action="store_true")
    ap.add_argument("--ingest-only", action="store_true")
    ap.add_argument("--artifact-map")
    args = ap.parse_args()

    hosts = sorted(Path(p) for p in glob.glob(args.pattern) if Path(p).is_dir())
    if not hosts:
        print(f"no host directories matched: {args.pattern}", file=sys.stderr)
        return 2

    fwd: list[str] = []
    if args.questions:     fwd += ["--questions", args.questions]
    if args.relevant_only: fwd += ["--relevant-only"]
    if args.only:          fwd += ["--only", args.only]
    if args.expand:        fwd += ["--expand"]
    if args.reingest:      fwd += ["--reingest"]
    if args.ingest_only:   fwd += ["--ingest-only"]
    if args.artifact_map:  fwd += ["--artifact-map", args.artifact_map]

    print(f"{ui.EMOJI['search']} {ui.c('run_hosts', 'cyan', 'bold')}: {len(hosts)} host(s), "
          f"{args.jobs} at a time  {ui.c('[' + ' '.join(fwd) + ']', 'gray')}")
    for h in hosts:
        print(f"    - {h.name}")

    done, failed, t0 = 0, 0, time.time()
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(_run_one, h, args.python, fwd): h for h in hosts}
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
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
