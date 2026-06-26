"""forensic-investigator CLI (vertical slice).

    python main.py investigate <artifact_dir> --case-id NAME [--questions FILE | --question "..."]

Phases: deterministic ingest -> agentic loop (run to completion) -> report + verify.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

import yaml

from src.agents import orchestrator, router
from src.extraction.ingest import ingest
from src.llm.client import LLMClient
from src.report.generator import write_report
from src.store.case_db import CaseDB
from src import ui, keepawake

ROOT = Path(__file__).parent

# Console progress logging echoes LLM/tool text that often contains non-cp1252
# characters (→, em-dashes, curly quotes). Force UTF-8 with replacement so a print
# can never crash the run on Windows. (The report file is already written as UTF-8.)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (no dependency). Existing env vars win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def _host_name(artifact_root: Path) -> str:
    name = artifact_root.name
    return name[len("ACQ-IR-"):] if name.startswith("ACQ-IR-") else name


def _qid(text: str) -> str:
    """Content-based question id: same text -> same id (answer reused on resume);
    changed text -> new id (fresh investigation, no stale-answer inheritance)."""
    norm = " ".join(text.lower().split())
    return "q" + hashlib.sha1(norm.encode("utf-8")).hexdigest()[:8]


def _load_artifact_map(args: argparse.Namespace) -> dict:
    """Load the artifact map — the layout adapter. Defaults to config/artifact_map.yaml;
    --artifact-map selects a different one (e.g. for a stock-AChoirX or other collector)."""
    path = Path(args.artifact_map) if getattr(args, "artifact_map", None) \
        else (ROOT / "config" / "artifact_map.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def cmd_check(args: argparse.Namespace) -> int:
    collection = Path(args.artifact_dir).resolve()
    if not collection.is_dir():
        print(f"error: not a directory: {collection}", file=sys.stderr)
        return 2
    from src.compat import check
    return check(collection, _load_artifact_map(args))


def cmd_investigate(args: argparse.Namespace) -> int:
    artifact_root = Path(args.artifact_dir).resolve()
    if not artifact_root.is_dir():
        print(f"error: not a directory: {artifact_root}", file=sys.stderr)
        return 2

    # Keep the machine from idle-sleeping mid-run (auto-released on exit). Does NOT override
    # closing a laptop lid — keep the lid open for unattended runs.
    if keepawake.prevent_idle_sleep():
        print(f"    {ui.c('(keep-awake on: system will not idle-sleep during this run)', 'gray')}")

    config = yaml.safe_load((ROOT / "config" / "config.yaml").read_text(encoding="utf-8"))
    artifact_map = _load_artifact_map(args)

    out_dir = ROOT / config["paths"]["output"] / args.case_id
    kb_dir = ROOT / config["paths"]["knowledge_base"]
    host = _host_name(artifact_root)

    case = CaseDB(out_dir / "case.db")
    resuming = case.get_meta("ingested") == "1"
    if resuming:
        print(f"{ui.EMOJI['resume']} {ui.c('Resuming', 'yellow', 'bold')} case "
              f"'{args.case_id}' (existing case.db found).")

    # --questions FILE *defines* the set (replace: a removed line drops that question).
    # --question TEXT (inline) *adds* to the existing set, so iterative one-off questions on the
    # same case-id accumulate instead of each run wiping the previous one. Content-hashed ids
    # mean an unchanged question keeps its answer; add_question is idempotent (INSERT OR REPLACE).
    inline = list(args.question or [])
    if args.questions is not None:
        case.clear_questions()        # the file is the source of truth for the question set
        for line in Path(args.questions).read_text(encoding="utf-8").splitlines() + inline:
            q = line.strip()
            if q:
                case.add_question(_qid(q), q)
    elif inline:
        for line in inline:           # inline-only: append; do NOT clear prior questions
            q = line.strip()
            if q:
                case.add_question(_qid(q), q)
    if args.questions is not None or inline:
        case.backfill_answer_questions()  # a re-added question reclaims its existing answer's text

    print(f"{ui.EMOJI['search']} {ui.c('Ingesting', 'cyan', 'bold')} {ui.c(host, 'bold')} ...")
    ingest(case, artifact_root, artifact_map, force=args.reingest)
    n_events = case.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    n_files = case.conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    print(f"    {ui.EMOJI['chart']} cataloged {ui.c(str(n_files), 'bold')} files, "
          f"{ui.c(str(n_events), 'bold')} timeline events")

    if args.ingest_only:
        print(f"    {ui.EMOJI['ok']} {ui.c('--ingest-only', 'green')}: parsed case.db is ready; "
              f"skipping investigation.")
        case.close()
        return 0

    llm = LLMClient(models=config["models"], effort=config["llm"]["effort"],
                    max_tokens=config["llm"]["max_tokens"])

    explicit_only = {s.strip() for s in args.only.split(",")} if args.only else None
    only = explicit_only
    priority_overrides = None
    budgets = dict(config["budgets"])

    # Memory (Volatility) config rides along in budgets (the runtime-settings bag the tools
    # already read). Resolve relative paths against the repo root so the vol_run tool, which
    # has no notion of ROOT, gets absolute paths.
    mem = dict(config.get("memory") or {})
    if mem.get("vol_cmd"):
        vc = list(mem["vol_cmd"])
        if vc and not Path(vc[0]).is_absolute() and (ROOT / vc[0]).exists():
            vc[0] = str(ROOT / vc[0])
        mem["vol_cmd"] = vc
    cache = mem.get("cache_dir") or str(ROOT / config["paths"]["output"] / "_memcache")
    mem["cache_dir"] = cache if Path(cache).is_absolute() else str(ROOT / cache)
    budgets["memory"] = mem

    if explicit_only is not None:
        # Manual scope: stays scoped, no expansion unless --expand. No LLM ranking.
        budgets["allow_expansion"] = args.expand
    else:
        budgets["allow_expansion"] = True
        # Question-driven bucket ranking: default whenever questions are present (sets
        # lead priority; all buckets still examined), or whenever --relevant-only is set.
        if case.questions() or args.relevant_only:
            present = [(c["artifact"], c["type"]) for c in case.coverage_rows() if c["present"]]
            try:
                ranked = router.rank_buckets(llm, case.questions(), present, kb_dir)
            except Exception as e:
                print(f"    router failed ({e}); using default priority", flush=True)
                ranked = None
            if ranked:
                priority_overrides = {b: max(100 - i * 5, 40) for i, b in enumerate(ranked)}
                print(f"    question-ranked bucket priority: {ranked}", flush=True)
                if args.relevant_only:
                    only = set(ranked)   # examine only the relevant ones
            elif args.relevant_only:
                print("    router selected nothing; examining all buckets", flush=True)

    bits = []
    if only:
        bits.append(f"scoped: {sorted(only)}")
    if priority_overrides:
        bits.append("question-ranked priority")
    bits.append(f"expansion={'on' if budgets['allow_expansion'] else 'off'}")
    print(f"{ui.EMOJI['brain']} {ui.c('Investigating', 'magenta', 'bold')} (run to completion) "
          f"... {ui.c('[' + ', '.join(bits) + ']', 'gray')}", flush=True)
    try:
        orchestrator.run(llm, case, artifact_root, kb_dir, host, budgets,
                         only=only, priority_overrides=priority_overrides)
    except KeyboardInterrupt:
        print(f"    {ui.EMOJI['warn']} {ui.c('interrupted', 'yellow')}; writing report with "
              f"results so far", flush=True)
    except Exception as e:
        print(f"    {ui.EMOJI['error']} {ui.c('investigation error', 'red', 'bold')} "
              f"({type(e).__name__}: {e}); writing partial report", flush=True)

    print(f"{ui.EMOJI['report']} {ui.c('Writing report', 'blue', 'bold')} ...")
    report = write_report(case, host, out_dir)
    print(f"{ui.EMOJI['ok']} {ui.c('Done.', 'green', 'bold')} Report: {report}")
    case.close()
    _write_html_dashboard(out_dir)
    return 0


def _write_html_dashboard(out_dir: Path) -> None:
    """Emit the single-host interactive HTML dashboard (report.html) next to report.md.
    Best-effort: reuses scripts/report_html.py over this one case.db; never fails the run."""
    import subprocess
    html = out_dir / "report.html"
    try:
        subprocess.run([sys.executable, str(ROOT / "scripts" / "report_html.py"),
                        "--glob", str(out_dir / "case.db"), "--out", str(html)],
                       check=False, capture_output=True)
    except Exception:
        return
    if html.exists():
        print(f"{ui.EMOJI['report']} {ui.c('Dashboard', 'blue', 'bold')}: {html} "
              f"{ui.c('(open in a browser to search/filter/sort)', 'gray')}")


def main() -> int:
    p = argparse.ArgumentParser(prog="forensic-investigator")
    sub = p.add_subparsers(dest="cmd", required=True)
    inv = sub.add_parser("investigate", help="investigate one host's artifact collection")
    inv.add_argument("artifact_dir")
    inv.add_argument("--case-id", required=True)
    inv.add_argument("--questions", help="text file, one CTF question per line")
    inv.add_argument("--question", action="append", metavar="TEXT",
                     help="an inline question string (repeatable; combinable with --questions)")
    inv.add_argument("--only", help="comma-separated dir-codes to scope coverage leads, e.g. 'Psh'")
    inv.add_argument("--expand", action="store_true",
                     help="allow the agent to file follow-up leads even under --only")
    inv.add_argument("--relevant-only", action="store_true",
                     help="LLM picks which buckets are relevant to the questions and examines "
                          "only those (expansion stays on so threads can still be followed)")
    inv.add_argument("--reingest", action="store_true",
                     help="force re-parsing artifacts even if this case was already ingested")
    inv.add_argument("--ingest-only", action="store_true",
                     help="parse artifacts into case.db and stop (no LLM investigation); "
                          "useful as a reusable base to copy per-question")
    inv.add_argument("--artifact-map",
                     help="path to an artifact_map.yaml for a different collection layout "
                          "(default config/artifact_map.yaml)")
    inv.set_defaults(func=cmd_investigate)

    chk = sub.add_parser("check", help="preflight: does a collection match the parsers' "
                                       "expected layout? (no LLM, no cost)")
    chk.add_argument("artifact_dir")
    chk.add_argument("--artifact-map", help="artifact_map.yaml to check against "
                                            "(default config/artifact_map.yaml)")
    chk.set_defaults(func=cmd_check)

    _load_dotenv(ROOT / ".env")
    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
