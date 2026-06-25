"""Render the Case File into a Markdown report.

Consumes ONLY the ledger / answers / coverage — never the chat history — and runs every
cited locator through the verifier so no uncited or fabricated claim survives.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..store.case_db import CaseDB
from . import verifier


def _cite(case: CaseDB, locator: str, excerpt: str) -> str:
    ok = verifier.resolves(case, locator)
    mark = "" if ok else " ⚠️UNVERIFIED"
    ex = f" — “{excerpt}”" if excerpt else ""
    return f"`{locator}`{mark}{ex}"


def generate(case: CaseDB, host: str) -> str:
    L: list[str] = []
    L.append(f"# Forensic investigation report — {host}\n")
    L.append(f"_Generated {datetime.now(timezone.utc).isoformat()}_\n")

    findings = case.findings()
    questions = case.questions()
    L.append(f"**Findings:** {len(findings)} · **Questions:** {len(questions)}\n")

    # ---- Answer sheet ----
    if questions:
        L.append("\n## Answer sheet\n")
        for q in questions:
            ans = case.answers_for(q["id"])
            L.append(f"\n### [{q['id']}] {q['text']}\n")
            answered = [a for a in ans if a["status"] == "answered"]
            pointers = [a for a in ans if a["status"] == "pointer"]

            if answered:
                if len(answered) > 1:
                    L.append("- **ANSWERED — multiple candidates (analyst to choose):**\n")
                for a in answered:
                    conf = f" _(confidence: {a['confidence']})_" if a["confidence"] else ""
                    bullet = "  - " if len(answered) > 1 else "- **ANSWERED:** "
                    L.append(f"{bullet}{a['answer']}{conf}\n")
                    for ev in case.answer_evidence(a["id"]):
                        L.append(f"    - {_cite(case, ev['locator'], ev['excerpt'])}\n")
            elif pointers:
                L.append("- **POINTER** — likely lives in a file we can't read; inspect manually:\n")
                seen = set()
                for a in pointers:
                    for c in case.answer_candidates(a["id"]):
                        if c["path"] in seen:
                            continue
                        seen.add(c["path"])
                        why = f" — {c['reason']}" if c["reason"] else ""
                        L.append(f"  - `{c['path']}`{why}\n")
            else:
                reason = ans[-1]["reasoning"] if ans else "not reached."
                L.append(f"- **UNRESOLVED** — {reason or 'no answer found.'}\n")

    # ---- Findings ----
    L.append("\n## Findings\n")
    if not findings:
        L.append("_None recorded._\n")
    for f in findings:
        tech = f" ({f['attack_technique']})" if f["attack_technique"] else ""
        conf = f" · confidence: {f['confidence']}" if f["confidence"] else ""
        L.append(f"\n### [{f['severity'].upper()}] {f['title']}{tech}{conf}\n")
        if f["description"]:
            L.append(f"{f['description']}\n")
        L.append("\nEvidence:\n")
        for ev in case.finding_evidence(f["id"]):
            L.append(f"- {_cite(case, ev['locator'], ev['excerpt'])}\n")

    # ---- Coverage & gaps ----
    L.append("\n## Coverage & gaps\n")
    L.append("| Artifact | Type | Present | Parsed | Status |\n")
    L.append("|---|---|---|---|---|\n")
    for c in case.coverage_rows():
        L.append(f"| {c['artifact']} | {c['type']} | {'yes' if c['present'] else 'no'} "
                 f"| {'yes' if c['parser'] else 'no'} | {c['status']} |\n")
    L.append("\n_Buckets with Parsed=no were cataloged by file metadata only — answers that "
             "depend on their parsed content appear as POINTERs. Exception: `MemDump` is "
             "analyzed on demand via the `vol_run` (Volatility) tool, so it can yield verified "
             "`memory:` answers despite Parsed=no._\n")
    return "".join(L)


def write_report(case: CaseDB, host: str, out_dir: Path) -> Path:
    out = out_dir / "report.md"
    out.write_text(generate(case, host), encoding="utf-8")
    return out
