#!/usr/bin/env python
"""Convert the DC33 CTF Q&A CSV into the eval answer-key JSON format.

  python eval/csv_to_key.py "<path to ...Q&A.csv>" eval/answers.json

- Strips btv{...} / BTV{...} / Flag{...} wrappers from answers.
- Multiple acceptable answers (separated by ' | ') become `expected_any`.
- The question text is cleaned of the trailing 'Flag format is ...' boilerplate,
  markdown image refs, and hints.
- Intro/freebie rows (answer 'OK'/'winner') are skipped.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

_WRAP = re.compile(r"^(?:btv|flag)\{(.*)\}$", re.IGNORECASE | re.DOTALL)


def clean_question(q: str) -> str:
    lines = []
    for line in (q or "").splitlines():
        if re.search(r"flag\s*format", line, re.IGNORECASE):
            break
        if line.strip().startswith("!["):       # markdown image
            break
        lines.append(line)
    return " ".join(" ".join(lines).split())


def strip_flag(tok: str) -> str:
    tok = tok.strip()
    m = _WRAP.match(tok)
    return (m.group(1).strip() if m else tok)


def parse_answers(cell: str) -> list[str]:
    out, seen = [], set()
    for part in (cell or "").split(" | "):
        s = strip_flag(part)
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def main() -> int:
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    entries = []
    with src.open(encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            q = clean_question(r.get("question", ""))
            accs = parse_answers(r.get("answers", ""))
            if not q or not accs:
                continue
            if accs[0].lower() in ("ok", "winner"):     # skip intro/freebie flags
                continue
            entry = {"question": q}
            if len(accs) == 1:
                entry["expected"] = accs[0]
            else:
                entry["expected_any"] = accs
            entries.append(entry)
    dst.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {len(entries)} questions to {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
