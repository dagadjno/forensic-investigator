#!/usr/bin/env python
"""Select the namtws004 (gloria.bradley) host-artifact questions for the eval.

Same approach as select_ws005/ws003: pull EXACT question text from answers.json by
unique substring; write eval/q_ws004/qNN.txt + manifest.tsv + all.txt.

  python eval/select_ws004.py
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).parent
KEY = HERE / "answers.json"
OUT = HERE / "q_ws004"

# Browser-heavy (Brw) + EVTX/PowerShell intrusion chain (Evt/Psh) + one filesystem
# needle (RawData/MFT). All answerable from the namtws004 triage collection.
PICKS = [
    "MTFIN employee owner of Workstation NAMTWS004",        # registry (ProfileList)
    "what website focused on staying stylish",              # browser
    "what company might be the company's 401k provider",    # browser
    "How many total file downloads via browser",            # browser
    "looked up a recipe for this item",                     # browser
    "Single Sign-On service did Gloria use to log into a LLM",  # browser
    "accesses her personal email on her company asset",     # browser
    "What is the specific illegal activity suspected",       # browser
    "convenience service might she be using",               # browser
    "had the account 'administrator' connect to it via an IP Address",  # Evt 4624
    "application package manager installed on it",          # Psh/Evt (chocolatey)
    "built-in command run that is commonly used by threat actors to find out what account",  # whoami.exe
    "included an encoded command - what IP Address and Port",  # Evt/Psh
    "name of the malware used in the attack on NAMTWS04",   # reasoning (Empire)
    "created a file they wanted to keep under wraps",       # RawData/MFT/USN
]


def main() -> int:
    key = json.loads(KEY.read_text(encoding="utf-8"))
    OUT.mkdir(exist_ok=True)
    manifest, allq = [], []
    for i, sub in enumerate(PICKS, 1):
        hits = [e for e in key if sub.lower() in e["question"].lower()]
        if len(hits) > 1:   # collapse exact-duplicate entries
            seen, uniq = set(), []
            for e in hits:
                if e["question"] not in seen:
                    seen.add(e["question"]); uniq.append(e)
            hits = uniq
        if len(hits) != 1:
            raise SystemExit(f"q{i:02d}: substring matched {len(hits)} questions: {sub!r}")
        e = hits[0]
        q = e["question"]
        exp = e.get("expected") or " | ".join(e.get("expected_any", []))
        (OUT / f"q{i:02d}.txt").write_text(q + "\n", encoding="utf-8")
        manifest.append(f"q{i:02d}.txt\t{exp}\t{q}")
        allq.append(q)
    (OUT / "manifest.tsv").write_text("\n".join(manifest) + "\n", encoding="utf-8")
    (OUT / "all.txt").write_text("\n".join(allq) + "\n", encoding="utf-8")
    print(f"wrote {len(PICKS)} question files + all.txt to {OUT}")
    for line in manifest:
        f, exp, _ = line.split("\t")
        print(f"  {f}  ->  {exp[:60]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
