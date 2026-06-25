#!/usr/bin/env python
"""Select the namtws005 host-artifact questions for the single-host eval.

Pulls the EXACT question text out of answers.json (matched by a unique substring)
and writes one questions-file per question to eval/q_ws005/qNN.txt, plus a
manifest.tsv mapping file -> expected -> question. Run-one-at-a-time loop then
feeds each qNN.txt to `main.py investigate ... --questions qNN.txt`.

  python eval/select_ws005.py
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).parent
KEY = HERE / "answers.json"
OUT = HERE / "q_ws005"

# Unique substrings identifying each chosen question (order = run order).
# All are answerable from the namtws005 triage collection alone.
PICKS = [
    "Operating System was the victim machine running",          # Reg
    "When was the Operating System Installed",                  # Reg
    "Time Zone (TimeZoneKeyName)",                              # Reg
    "Victim's Host Name",                                       # Reg
    "RMM tool did the Threat Actor use",                        # Amcache/Evt/Psh
    "executable file name of the RMM Program",                  # Amcache/Evt
    "executable file name of the IP Scanner",                   # Amcache/Psh
    "Active Directory reconnaissance tool",                     # Amcache/Psh
    "file name of the zip tool that was downloaded",            # Psh/Amcache
    "If Defender detected a Hacking tool",                      # Evt (Defender)
    "What directory did the Threat Actor put their tools in?",  # Psh/files
    "command used to download the file transfer program",      # Psh
    "command used to download the network scanning program",   # Psh
    "full path and filename where the TA stored their recon",   # Psh/files
    "What command did the TA use to map to a server",          # Psh
    "Were any other domain users found on the compromised",     # Reg (SAM/profiles)
]


def main() -> int:
    key = json.loads(KEY.read_text(encoding="utf-8"))
    OUT.mkdir(exist_ok=True)
    manifest = []
    for i, sub in enumerate(PICKS, 1):
        hits = [e for e in key if sub.lower() in e["question"].lower()]
        if len(hits) > 1:
            # Collapse exact-duplicate entries (the key lists a few questions twice).
            seen, uniq = set(), []
            for e in hits:
                if e["question"] not in seen:
                    seen.add(e["question"])
                    uniq.append(e)
            hits = uniq
        if len(hits) > 1:
            # Disambiguate: this is the namtws005 set, so drop variants that name
            # another host explicitly (e.g. the "On namtws003, ..." twin).
            hits = [e for e in hits if "namtws00" not in e["question"].lower()]
        if len(hits) != 1:
            raise SystemExit(f"q{i:02d}: substring matched {len(hits)} questions: {sub!r}")
        e = hits[0]
        q = e["question"]
        exp = e.get("expected") or " | ".join(e.get("expected_any", []))
        f = OUT / f"q{i:02d}.txt"
        f.write_text(q + "\n", encoding="utf-8")
        manifest.append(f"q{i:02d}.txt\t{exp}\t{q}")
    (OUT / "manifest.tsv").write_text("\n".join(manifest) + "\n", encoding="utf-8")
    print(f"wrote {len(PICKS)} question files to {OUT}")
    for line in manifest:
        print("  " + line.split("\t", 1)[0] + "  ->  " + line.split("\t")[1])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
