"""Agent-callable tools.

Design rules:
- Read/search tools register every locator they hand back (emit_locator), so a later
  finding/answer can only cite something a tool actually returned.
- record_finding / answer_question REJECT any cited locator that wasn't emitted -> the
  no-uncited-assertions rule is enforced at write time, not just hoped for in a prompt.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..store.case_db import CaseDB
from ..textutil import read_text_auto


class ToolContext:
    def __init__(self, case: CaseDB, artifact_root: Path, kb_dir: Path,
                 lead_depth: int, budgets: dict):
        self.case = case
        self.root = artifact_root
        self.kb_dir = kb_dir
        self.lead_depth = lead_depth
        self.budgets = budgets


def _ok(payload) -> str:
    return json.dumps(payload, default=str)[:12000]


def _add_truncation(res, ctx, base_from_where, params, shown, maybe_truncated, hint,
                    noun="matches"):
    """If a LIMIT-capped SQL query may have hidden rows, tell the model the TRUE total so a
    slice isn't mistaken for the whole set. The COUNT only runs when the page filled up
    (i.e. truncation is actually possible), so small result sets pay nothing extra."""
    if not maybe_truncated:
        return
    total = ctx.case.conn.execute(f"SELECT COUNT(*) {base_from_where}", params).fetchone()[0]
    if total > shown:
        res["truncated"] = True
        res["total_matched"] = total
        res["note"] = (f"showing first {shown} of {total} {noun} (sorted). "
                       f"To reach the rest, {hint}.")


# CTF flag markers: btv{...}, flag{...}, FL4G={...}, key{...}, ctf{...} (the answer is often
# planted as such a marker). Allows an optional = / : before the braces (e.g. `FL4G={...}`).
_FLAG_RX = re.compile(r"(?i)(?:btv|flag|fl4g|ctf|key)\s*[=:]?\s*\{[^}]{1,200}\}")


# ---- tool schemas (sent to the model) -----------------------------------
TOOL_SCHEMAS = [
    {
        "name": "kb_read",
        "description": "Read a knowledge-base document (a playbook or reference). "
                       "Read the relevant playbook before investigating.",
        "input_schema": {
            "type": "object",
            "properties": {"doc": {"type": "string",
                                   "description": "e.g. 'playbooks/powershell_history.md' or 'artifact_map.md'"}},
            "required": ["doc"],
        },
    },
    {
        "name": "query_timeline",
        "description": "Query the normalized event timeline. Returns rows each with a 'locator' you can "
                       "cite. If the result is capped, the reply includes truncated=true and "
                       "total_matched — DON'T assume you saw everything; add a filter or raise limit.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "description": "source_artifact filter, e.g. 'powershell_history'"},
                "user": {"type": "string"},
                "contains": {"type": "string", "description": "substring filter on the event text"},
                "limit": {"type": "integer", "default": 100},
            },
        },
    },
    {
        "name": "grep_artifact",
        "description": "Regex search over parsed event text. Returns matching rows with locators. If "
                       "capped, the reply includes truncated=true and total_matched — tighten the "
                       "pattern or raise limit rather than assuming the shown rows are all of them.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "source": {"type": "string"},
                "limit": {"type": "integer", "default": 100},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "find_flags",
        "description": "Scan ALL parsed artifacts and readable text files for planted CTF flag "
                       "markers — btv{...}, flag{...}, FL4G={...}, key{...}, ctf{...}. In a CTF the "
                       "intended answer is frequently planted as such a marker, so call this EARLY "
                       "and whenever a question's answer is elusive. Each hit comes back with a "
                       "citable locator; record the value inside the braces via answer_question.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_files",
        "description": "Search the file-metadata catalog (every file incl. binaries you cannot read). "
                       "Use to find candidate files to POINT at. Returns path/owner/size/timestamps + a "
                       "'file:' locator. If capped, the reply includes truncated=true and total_matched — "
                       "narrow with query=/artifact= or raise limit to see the rest.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "substring match on file path/name"},
                "artifact": {"type": "string", "description": "dir-code filter, e.g. 'Brw'"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "read_file",
        "description": "Read a slice of a text file from the catalog. Lines come back with 'file:<path>:<line>' locators.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "catalog path (relative)"},
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 200},
            },
            "required": ["path"],
        },
    },
    {
        "name": "mft_lookup",
        "description": "Resolve a file's full path and $SI/$FN MAC timestamps from the $MFT by filename "
                       "(substring, case-insensitive). Use when you need a file's directory/path or "
                       "creation/modification times other artifacts don't give — e.g. resolving a USN "
                       "filename to its path, recovering a deleted file's path, or checking for timestomping "
                       "($SI vs $FN mismatch). First call builds an index (~a few seconds); later calls are "
                       "instant. Each result becomes a citable timeline row (source='mft').",
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "filename or substring, e.g. 'launcher.exe'"},
                "limit": {"type": "integer", "default": 20},
            },
            "required": ["filename"],
        },
    },
    {
        "name": "vol_run",
        "description": "Run ONE Volatility3 plugin against this host's memory image for evidence that "
                       "lives only in RAM (running processes, network connections, injected code, typed "
                       "console commands). SLOW (tens of seconds to minutes) and cached — use targeted, "
                       "only when disk artifacts can't answer. Pass 'contains' to filter to matching rows. "
                       "Each row becomes a citable timeline event (source='memory'). Key plugins: "
                       "windows.pslist/pstree/psscan (processes), windows.cmdline/cmdscan/consoles "
                       "(what ran / was typed), windows.netscan/netstat (connections), windows.svcscan "
                       "(services), windows.malfind (injected code), windows.dlllist/getsids/envars/sessions, "
                       "windows.registry.printkey/userassist. NOTE: no credential-dump plugin exists — for a "
                       "typed secret try consoles/cmdscan/cmdline. If memory is disabled or absent, POINT instead.",
        "input_schema": {
            "type": "object",
            "properties": {
                "plugin": {"type": "string", "description": "full plugin name, e.g. 'windows.netscan.NetScan'"},
                "contains": {"type": "string", "description": "case-insensitive substring filter on row text"},
                "pid": {"type": "integer", "description": "optional: restrict to one process id"},
            },
            "required": ["plugin"],
        },
    },
    {
        "name": "get_raw_event",
        "description": "Get the FULL field set for a timeline row by its locator. Event-log summaries "
                       "show only the top ~12 fields; if a summary ends with '[+N more fields — "
                       "get_raw_event]', call this to see the rest (e.g. Hashes, IntegrityLevel, "
                       "LogonId, OriginalFileName). The returned locator is citable.",
        "input_schema": {
            "type": "object",
            "properties": {"locator": {"type": "string", "description": "a locator a tool returned to you"}},
            "required": ["locator"],
        },
    },
    {
        "name": "list_findings",
        "description": "List findings already recorded by you or other sub-agents (id, severity, technique, "
                       "title). Check this before recording so you add to an existing finding instead of duplicating it.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "record_finding",
        "description": "Record a cited finding to the ledger. 'evidence' must be non-empty and every locator "
                       "must be one a tool returned to you. If a finding with the same ATT&CK technique already "
                       "cites one of your locators, your evidence is merged into it instead of duplicating.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                "attack_technique": {"type": "string", "description": "ATT&CK id if applicable, e.g. T1059.001"},
                "description": {"type": "string"},
                "evidence": {
                    "type": "array",
                    "items": {"type": "object",
                              "properties": {"locator": {"type": "string"}, "excerpt": {"type": "string"}},
                              "required": ["locator"]},
                },
            },
            "required": ["title", "severity", "evidence"],
        },
    },
    {
        "name": "answer_question",
        "description": "Resolve a CTF question. answered -> answer + non-empty evidence (verified citations). "
                       "pointer -> candidate_files + reasoning (you cannot read it; never guess). "
                       "unresolved -> reasoning describing what you searched.",
        "input_schema": {
            "type": "object",
            "properties": {
                "question_id": {"type": "string"},
                "status": {"type": "string", "enum": ["answered", "pointer", "unresolved"]},
                "answer": {"type": "string"},
                "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                "reasoning": {"type": "string"},
                "evidence": {
                    "type": "array",
                    "items": {"type": "object",
                              "properties": {"locator": {"type": "string"}, "excerpt": {"type": "string"}},
                              "required": ["locator"]},
                },
                "candidate_files": {
                    "type": "array",
                    "items": {"type": "object",
                              "properties": {"path": {"type": "string"}, "reason": {"type": "string"}},
                              "required": ["path"]},
                },
            },
            "required": ["question_id", "status"],
        },
    },
    {
        "name": "file_lead",
        "description": "Queue a NEW line of investigation for the orchestrator. Don't chase it yourself.",
        "input_schema": {
            "type": "object",
            "properties": {"title": {"type": "string"}, "reason": {"type": "string"}},
            "required": ["title"],
        },
    },
    {
        "name": "mark_examined",
        "description": "Mark an artifact bucket as fully triaged. The run finishes only when all are examined.",
        "input_schema": {
            "type": "object",
            "properties": {"artifact": {"type": "string", "description": "dir-code, e.g. 'Psh'"}},
            "required": ["artifact"],
        },
    },
]


# ---- handlers -----------------------------------------------------------
def dispatch(ctx: ToolContext, name: str, args: dict) -> tuple[str, bool]:
    """Returns (result_text, is_error)."""
    fn = _HANDLERS.get(name)
    if fn is None:
        return f"unknown tool: {name}", True
    try:
        return fn(ctx, args)
    except Exception as e:  # surface tool errors back to the model
        return f"tool error in {name}: {e}", True


def _kb_read(ctx, args):
    doc = args["doc"].lstrip("/")
    fp = (ctx.kb_dir / doc).resolve()
    if ctx.kb_dir.resolve() not in fp.parents and fp != ctx.kb_dir.resolve():
        return "refused: path outside knowledge base", True
    if not fp.is_file():
        return f"no such kb doc: {doc}", True
    return fp.read_text(encoding="utf-8")[:12000], False


def _query_timeline(ctx, args):
    where, params = ["1=1"], []
    if args.get("source"):
        where.append("source_artifact=?"); params.append(args["source"])
    if args.get("user"):
        where.append("user LIKE ?"); params.append(f"%{args['user']}%")
    if args.get("contains"):
        where.append("summary LIKE ?"); params.append(f"%{args['contains']}%")
    limit = min(int(args.get("limit", 100)), 500)
    base = f"FROM events WHERE {' AND '.join(where)}"
    rows = ctx.case.conn.execute(
        f"SELECT ts, user, summary, locator {base} ORDER BY id LIMIT ?", (*params, limit),
    ).fetchall()
    out = []
    for r in rows:
        ctx.case.emit_locator(r["locator"], "event")
        out.append({"locator": r["locator"], "user": r["user"], "ts": r["ts"], "text": r["summary"]})
    res = {"count": len(out), "rows": out}
    _add_truncation(res, ctx, base, params, len(out), len(rows) == limit,
                    "narrow with contains=/user=/source=, or raise limit (max 500)")
    return _ok(res), False


def _grep_artifact(ctx, args):
    rx = re.compile(args["pattern"], re.IGNORECASE)
    q = "SELECT user, summary, locator FROM events"
    params = []
    if args.get("source"):
        q += " WHERE source_artifact=?"; params.append(args["source"])
    q += " ORDER BY id"
    limit = min(int(args.get("limit", 100)), 500)
    out, total = [], 0
    for r in ctx.case.conn.execute(q, params):
        if rx.search(r["summary"] or ""):
            total += 1   # keep counting past the cap so we can report the true total
            if len(out) < limit:
                ctx.case.emit_locator(r["locator"], "event")
                out.append({"locator": r["locator"], "user": r["user"], "text": r["summary"]})
    res = {"count": len(out), "rows": out}
    if total > len(out):
        res["truncated"] = True
        res["total_matched"] = total
        res["note"] = (f"showing first {len(out)} of {total} matches (ordered by time). "
                       f"Tighten the pattern, or raise limit (max 500), to reach the rest.")
    return _ok(res), False


def _find_flags(ctx, args):
    """Deterministic CTF-flag-marker scan over parsed events + readable text files. Each
    distinct flag is returned once with its first citable locator."""
    out, seen = [], set()
    # 1) Parsed artifacts (PowerShell history, EVTX scriptblocks, registry, browser, USN …).
    for r in ctx.case.conn.execute("SELECT summary, raw, locator FROM events"):
        blob = (r["summary"] or "") + "\n" + (r["raw"] or "")
        for m in _FLAG_RX.finditer(blob):
            flag = m.group(0)
            if flag.lower() in seen:
                continue
            seen.add(flag.lower())
            ctx.case.emit_locator(r["locator"], "event")
            out.append({"flag": flag, "locator": r["locator"]})
            if len(out) >= 100:
                return _ok({"count": len(out), "flags": out, "note": "capped at 100"}), False
    # 2) Readable text files not covered by a parser (bounded by size).
    for r in ctx.case.conn.execute("SELECT path FROM files WHERE is_text=1"):
        fp = ctx.root / r["path"]
        try:
            if fp.stat().st_size > 5_000_000:
                continue
            lines = read_text_auto(fp).splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for m in _FLAG_RX.finditer(line):
                flag = m.group(0)
                if flag.lower() in seen:
                    continue
                seen.add(flag.lower())
                loc = f"file:{r['path']}:{i}"
                ctx.case.emit_locator(loc, "file_line", r["path"])
                out.append({"flag": flag, "locator": loc})
                if len(out) >= 100:
                    return _ok({"count": len(out), "flags": out, "note": "capped at 100"}), False
    return _ok({"count": len(out), "flags": out}), False


def _list_files(ctx, args):
    where, params = ["1=1"], []
    if args.get("query"):
        where.append("path LIKE ?"); params.append(f"%{args['query']}%")
    if args.get("artifact"):
        where.append("artifact=?"); params.append(args["artifact"])
    limit = min(int(args.get("limit", 50)), 200)
    base = f"FROM files WHERE {' AND '.join(where)}"
    rows = ctx.case.conn.execute(
        f"SELECT path, owner, size, mtime, ctime, is_text {base} ORDER BY path LIMIT ?", (*params, limit),
    ).fetchall()
    out = []
    for r in rows:
        loc = f"file:{r['path']}"
        ctx.case.emit_locator(loc, "file", r["path"])
        out.append({"locator": loc, "path": r["path"], "owner": r["owner"],
                    "size": r["size"], "mtime": r["mtime"], "ctime": r["ctime"],
                    "readable": bool(r["is_text"])})
    res = {"count": len(out), "files": out}
    _add_truncation(res, ctx, base, params, len(out), len(rows) == limit,
                    "narrow with query=/artifact=, or raise limit (max 200)", noun="files")
    return _ok(res), False


# Parsed buckets: a binary file here is ALREADY extracted into the timeline, so reading it
# raw (or POINTing at it) is wrong — redirect to the query that serves its parsed data.
# dir-code -> how to get at it. Covers DC33 + stock (SYS) dir-codes.
_PARSED_BUCKET_HINT = {
    "Evt":     'query_timeline(source="event_logs", contains=...) and get_raw_event(locator) for full fields',
    "Reg":     'query_timeline(source="registry" or "amcache", contains=...) and get_raw_event(locator)',
    "Brw":     'query_timeline(source="browser", contains=...)',
    "Lnk":     'query_timeline(source="lnk", contains=...)',
    "RawData": 'query_timeline(source="usn", contains=...) and mft_lookup(name) for paths/timestamps',
    "Sys":     'query_timeline(source="srum", contains=...)',
    "SYS":     'query_timeline(source="srum", contains=...)',
}


def _read_file(ctx, args):
    rel = args["path"]
    row = ctx.case.conn.execute("SELECT is_text, artifact FROM files WHERE path=?", (rel,)).fetchone()
    if row is None:
        return f"not in catalog: {rel}", True
    if not row["is_text"]:
        how = _PARSED_BUCKET_HINT.get(row["artifact"])
        if how:
            return (f"{rel} is a parsed artifact (bucket '{row['artifact']}'), not a raw text file — "
                    f"its contents are already in the timeline. Don't read it raw or POINT at it; "
                    f"use {how} instead."), True
        return (f"{rel} is not a readable text file. If the answer lives here, POINT at it "
                f"(answer_question status=pointer) rather than guessing."), True
    fp = (ctx.root / rel)
    lines = read_text_auto(fp).splitlines()
    offset = max(int(args.get("offset", 0)), 0)
    limit = min(int(args.get("limit", 200)), 500)
    out = []
    for n in range(offset, min(offset + limit, len(lines))):
        loc = f"file:{rel}:{n + 1}"
        ctx.case.emit_locator(loc, "file_line", rel)
        out.append({"locator": loc, "line": n + 1, "text": lines[n]})
    return _ok({"path": rel, "total_lines": len(lines), "rows": out}), False


_BACKSLASH_RUN = re.compile(r"\\{2,}")


def _resolve_locator(loc: str, exists_fn) -> str:
    """Return the canonical stored form of a locator. The model often OVER-escapes the
    backslashes in registry key paths (`\\` -> `\\\\`), so an exact match fails even though
    the locator is real. If the literal form isn't known, collapse backslash runs and use
    that — registry paths never contain doubled backslashes, so this is safe."""
    if exists_fn(loc):
        return loc
    collapsed = _BACKSLASH_RUN.sub(r"\\", loc)
    if collapsed != loc and exists_fn(collapsed):
        return collapsed
    return loc


def _check_evidence(ctx, evidence):
    # Canonicalize each cited locator in place (fixes over-escaped registry backslashes) so a
    # real citation isn't wrongly rejected AND the stored evidence matches the events table.
    for e in evidence:
        e["locator"] = _resolve_locator(e["locator"], ctx.case.locator_exists)
    bad = [e["locator"] for e in evidence if not ctx.case.locator_exists(e["locator"])]
    return bad


def _mft_lookup(ctx, args):
    from ..extraction import mft
    row = ctx.case.conn.execute("SELECT path FROM files WHERE name='$MFT' LIMIT 1").fetchone()
    if row is None:
        row = ctx.case.conn.execute("SELECT path FROM files WHERE path LIKE '%MFT' LIMIT 1").fetchone()
    if row is None:
        return "no $MFT present in this collection's file catalog", True
    rel = row["path"]
    limit = min(int(args.get("limit", 20)), 100)
    results = mft.lookup(ctx.root / rel, args["filename"], limit)
    out = []
    for r in results:
        loc = f"mft:{rel}:{r['record_no']}"
        si, fn = r.get("si_times") or {}, r.get("fn_times") or {}
        summary = (f"[MFT] {r['path']} | deleted={r['deleted']} size={r['size']} "
                   f"SI(c={si.get('created')} m={si.get('modified')}) FN(c={fn.get('created')})")
        if ctx.case.conn.execute("SELECT 1 FROM events WHERE locator=?", (loc,)).fetchone() is None:
            ctx.case.add_event(source_artifact="mft", summary=summary[:600] + "  [+more fields — get_raw_event]",
                               locator=loc, ts=(si.get("modified") or fn.get("modified") or ""),
                               user="", event_type="mft:file", raw=json.dumps(r))
            ctx.case.commit()
        ctx.case.emit_locator(loc, "event")   # citable
        out.append({"locator": loc, "path": r["path"], "deleted": r["deleted"],
                    "size": r["size"], "si_times": si, "fn_times": fn})
    return _ok({"query": args["filename"], "count": len(out), "results": out}), False


def _vol_run(ctx, args):
    from ..extraction import memory
    mem = ctx.budgets.get("memory") or {}
    if not mem.get("enabled") or not mem.get("vol_cmd"):
        return ("memory analysis is not enabled for this run (no Volatility configured). "
                "If the answer lives in the memory image, answer_question with status='pointer' "
                "and nominate the MemDump image."), True
    plugin = args["plugin"]
    if plugin not in memory.PLUGINS:
        return (f"unsupported plugin {plugin!r}. Choose one of: {', '.join(memory.supported())}"), True
    row = ctx.case.conn.execute(
        "SELECT path FROM files WHERE artifact='MemDump' AND ("
        "lower(path) LIKE '%.raw' OR lower(path) LIKE '%.mem' OR lower(path) LIKE '%.dmp' "
        "OR lower(path) LIKE '%.lime' OR lower(path) LIKE '%winpmem%') LIMIT 1").fetchone()
    if row is None:
        return ("no memory image found in this collection's MemDump bucket; "
                "POINT at the image or resolve from disk artifacts instead."), True
    rel = row["path"]
    extra = ["--pid", str(args["pid"])] if args.get("pid") is not None else []
    short = plugin.split(".")[-1].lower()
    try:
        rows = memory.run_plugin(ctx.root / rel, plugin, list(mem["vol_cmd"]),
                                 mem.get("cache_dir", "output/_memcache"), extra)
    except Exception as e:
        return f"volatility run failed for {plugin}: {e}", True

    needle = (args.get("contains") or "").lower()
    out, materialized = [], 0
    for i, r in enumerate(rows):
        ef = memory.event_fields(plugin, r)
        if needle and needle not in ef["summary"].lower():
            continue
        loc = f"memory:{short}:{i}"
        if ctx.case.conn.execute("SELECT 1 FROM events WHERE locator=?", (loc,)).fetchone() is None:
            ctx.case.add_event(source_artifact="memory",
                               summary=ef["summary"][:600] + "  [+full row — get_raw_event]",
                               locator=loc, ts=ef["ts"], user=ef["user"],
                               event_type=f"memory:{short}", raw=json.dumps(r))
            ctx.case.commit()
        ctx.case.emit_locator(loc, "event")   # citable
        out.append({"locator": loc, "text": ef["summary"][:300]})
        materialized += 1
        if materialized >= 80:
            break
    note = f"{len(rows)} total rows; showing {len(out)}"
    if needle:
        note += f" matching '{args['contains']}'"
    if len(rows) > materialized and not needle:
        note += " (use 'contains' to filter)"
    return _ok({"plugin": plugin, "note": note, "rows": out}), False


def _get_raw_event(ctx, args):
    loc = _resolve_locator(args["locator"], lambda L: ctx.case.conn.execute(
        "SELECT 1 FROM events WHERE locator=?", (L,)).fetchone() is not None)
    row = ctx.case.conn.execute(
        "SELECT summary, raw FROM events WHERE locator=?", (loc,)).fetchone()
    if row is None:
        return f"no timeline row with locator {loc}", True
    ctx.case.emit_locator(loc, "event")   # make it citable
    if not row["raw"]:
        return _ok({"locator": loc, "note": "no extra stored fields for this row",
                    "summary": row["summary"]}), False
    try:
        fields = json.loads(row["raw"])
    except (json.JSONDecodeError, TypeError):
        fields = row["raw"]
    return _ok({"locator": loc, "fields": fields}), False


def _list_findings(ctx, args):
    rows = ctx.case.findings_summary()
    out = [{"id": r["id"], "severity": r["severity"], "technique": r["attack_technique"],
            "title": r["title"]} for r in rows]
    return _ok({"count": len(out), "findings": out}), False


def _record_finding(ctx, args):
    evidence = args.get("evidence") or []
    if not evidence:
        return "rejected: a finding needs at least one evidence locator", True
    bad = _check_evidence(ctx, evidence)
    if bad:
        return f"rejected: these locators were never returned by a tool: {bad}. Cite real locators.", True
    # Dedup: if another sub-agent already recorded this (same technique + a shared
    # locator), merge the new evidence in instead of creating a duplicate.
    dup = ctx.case.find_duplicate_finding(args.get("attack_technique", ""),
                                          [e["locator"] for e in evidence])
    if dup is not None:
        added = ctx.case.add_finding_evidence(dup, evidence)
        return _ok({"merged_into_finding": dup, "evidence_added": added,
                    "note": "duplicate of an existing finding; evidence merged"}), False
    fid = ctx.case.add_finding(
        title=args["title"], severity=args["severity"], evidence=evidence,
        confidence=args.get("confidence", ""), attack_technique=args.get("attack_technique", ""),
        description=args.get("description", ""),
    )
    return _ok({"recorded_finding": fid}), False


def _answer_question(ctx, args):
    status = args["status"]
    qid = args["question_id"]
    conf = args.get("confidence", "")
    if status == "answered":
        evidence = args.get("evidence") or []
        if not evidence:
            return "rejected: an answered question needs evidence. Use 'pointer' or 'unresolved' if you have none.", True
        bad = _check_evidence(ctx, evidence)
        if bad:
            return f"rejected: uncited locators {bad}. Cite locators a tool returned.", True
        if ctx.case.answer_is_duplicate(qid, "answered", args.get("answer", ""), None):
            return _ok({"skipped": "this exact answer is already recorded; "
                        "record a DIFFERENT or better-supported answer, or move on"}), False
        aid = ctx.case.add_answer(qid, "answered", answer=args.get("answer", ""),
                                  reasoning=args.get("reasoning", ""), evidence=evidence, confidence=conf)
    elif status == "pointer":
        cands = args.get("candidate_files") or []
        if not cands:
            return "rejected: a pointer needs candidate_files.", True
        bad = [c["path"] for c in cands
               if ctx.case.conn.execute("SELECT 1 FROM files WHERE path=?", (c["path"],)).fetchone() is None]
        if bad:
            return f"rejected: these candidate paths are not in the file catalog: {bad}", True
        if ctx.case.answer_is_duplicate(qid, "pointer", "", cands):
            return _ok({"skipped": "the same candidate files are already recorded"}), False
        aid = ctx.case.add_answer(qid, "pointer", reasoning=args.get("reasoning", ""),
                                  candidates=cands, confidence=conf)
    else:  # unresolved
        if ctx.case.answer_is_duplicate(qid, "unresolved", "", None):
            return _ok({"skipped": "this question already has an answer; not recording unresolved"}), False
        aid = ctx.case.add_answer(qid, "unresolved", reasoning=args.get("reasoning", ""))
    return _ok({"recorded_answer": aid, "status": status}), False


def _file_lead(ctx, args):
    if not ctx.budgets.get("allow_expansion", True):
        return "expansion disabled for this run; investigate within this lead or record a finding instead", False
    if ctx.case.total_leads() >= ctx.budgets.get("max_total_leads", 200):
        return "lead budget reached; not filing", False
    if ctx.lead_depth + 1 > ctx.budgets.get("max_lead_depth", 4):
        return "max lead depth reached; investigate within this lead or record a finding instead", False
    lid = ctx.case.add_lead(title=args["title"], reason=args.get("reason", ""),
                            source="agent", depth=ctx.lead_depth + 1, priority=60)
    return _ok({"filed_lead": lid if lid else "duplicate (already queued)"}), False


def _mark_examined(ctx, args):
    ctx.case.set_coverage_status(args["artifact"], "analyzed")
    return _ok({"examined": args["artifact"]}), False


_HANDLERS = {
    "kb_read": _kb_read,
    "query_timeline": _query_timeline,
    "grep_artifact": _grep_artifact,
    "find_flags": _find_flags,
    "list_files": _list_files,
    "read_file": _read_file,
    "mft_lookup": _mft_lookup,
    "vol_run": _vol_run,
    "get_raw_event": _get_raw_event,
    "list_findings": _list_findings,
    "record_finding": _record_finding,
    "answer_question": _answer_question,
    "file_lead": _file_lead,
    "mark_examined": _mark_examined,
}
