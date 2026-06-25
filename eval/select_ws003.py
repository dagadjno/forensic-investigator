#!/usr/bin/env python
"""Select the namtws003 host-artifact questions for the single-host eval.

Same approach as select_ws005.py: pull EXACT question text from answers.json by
unique substring, write eval/q_ws003/qNN.txt + manifest.tsv + all.txt.

  python eval/select_ws003.py
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).parent
KEY = HERE / "answers.json"
OUT = HERE / "q_ws003"

# All answerable from the namtws003 triage collection. This set leans harder on
# read_file/grep over script & text files than ws005 did (Discord exfil, scraped
# password, channel_id) plus LNK / amcache / registry / Defender.
PICKS = [
    "exact version of Advanced IP Scanner",          # amcache/registry
    "A desktop shortcut was created on namtws003",    # LNK
    "What user is assigned to namtws003?",            # registry (ProfileList)
    "What account conducted forensics on namtws003?", # Evt / acquisition
    "On namtws003, what directory did the threat actor put their tools in",  # files/Psh (music)
    "domain name used for the credential exfiltration",        # Psh/browser/file
    "what is his channel_id",                         # read_file (exfil script)
    "password for the Administrator account scraped", # read_file
    "what txt file was created in c:\\users\\public\\music",    # USN/MFT/files
    "what exe allowed for user account control",      # Evt/Psh (fodhelper)
    "What is Olivia Parker's password?",              # file/registry (stretch)
]


def main() -> int:
    key = json.loads(KEY.read_text(encoding="utf-8"))
    OUT.mkdir(exist_ok=True)
    manifest, allq = [], []
    for i, sub in enumerate(PICKS, 1):
        hits = [e for e in key if sub.lower() in e["question"].lower()]
        if len(hits) > 1:
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
        print(f"  {f}  ->  {exp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
