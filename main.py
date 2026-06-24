"""forensic-investigator CLI (vertical slice).

    python main.py investigate <artifact_dir> --case-id NAME [--questions FILE]

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


def cmd_investigate(args: argparse.Namespace) -> int:
    artifact_root = Path(args.artifact_dir).resolve()
    if not artifact_root.is_dir():
        print(f"error: not a directory: {artifact_root}", file=sys.stderr)
        return 2

    config = yaml.safe_load((ROOT / "config" / "config.yaml").read_text(encoding="utf-8"))
    artifact_map = yaml.safe_load((ROOT / "config" / "artifact_map.yaml").read_text(encoding="utf-8"))

    out_dir = ROOT / config["paths"]["output"] / args.case_id
    kb_dir = ROOT / config["paths"]["knowledge_base"]
    host = _host_name(artifact_root)

    case = CaseDB(out_dir / "case.db")
    resuming = case.get_meta("ingested") == "1"
    if resuming:
        print(f"[*] Resuming case '{args.case_id}' (existing case.db found).")

    # When --questions is given, replace the question SET (content-hashed ids). Unchanged
    # questions keep their answers; changed/new ones become new questions; removed ones drop.
    if args.questions:
        case.clear_questions()
        for line in Path(args.questions).read_text(encoding="utf-8").splitlines():
            q = line.strip()
            if q:
                case.add_question(_qid(q), q)

    print(f"[A] Ingesting {host} ...")
    ingest(case, artifact_root, artifact_map, force=args.reingest)
    n_events = case.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    n_files = case.conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    print(f"    cataloged {n_files} files, {n_events} timeline events")

    llm = LLMClient(models=config["models"], effort=config["llm"]["effort"],
                    max_tokens=config["llm"]["max_tokens"])

    explicit_only = {s.strip() for s in args.only.split(",")} if args.only else None
    only = explicit_only
    priority_overrides = None
    budgets = dict(config["budgets"])

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
    print(f"[B/C] Investigating (run to completion) ... [{', '.join(bits)}]", flush=True)
    try:
        orchestrator.run(llm, case, artifact_root, kb_dir, host, budgets,
                         only=only, priority_overrides=priority_overrides)
    except KeyboardInterrupt:
        print("    interrupted; writing report with results so far", flush=True)
    except Exception as e:
        print(f"    investigation error ({type(e).__name__}: {e}); writing partial report", flush=True)

    print("[D] Writing report ...")
    report = write_report(case, host, out_dir)
    print(f"Done. Report: {report}")
    case.close()
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="forensic-investigator")
    sub = p.add_subparsers(dest="cmd", required=True)
    inv = sub.add_parser("investigate", help="investigate one host's artifact collection")
    inv.add_argument("artifact_dir")
    inv.add_argument("--case-id", required=True)
    inv.add_argument("--questions", help="text file, one CTF question per line")
    inv.add_argument("--only", help="comma-separated dir-codes to scope coverage leads, e.g. 'Psh'")
    inv.add_argument("--expand", action="store_true",
                     help="allow the agent to file follow-up leads even under --only")
    inv.add_argument("--relevant-only", action="store_true",
                     help="LLM picks which buckets are relevant to the questions and examines "
                          "only those (expansion stays on so threads can still be followed)")
    inv.add_argument("--reingest", action="store_true",
                     help="force re-parsing artifacts even if this case was already ingested")
    inv.set_defaults(func=cmd_investigate)
    _load_dotenv(ROOT / ".env")
    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
