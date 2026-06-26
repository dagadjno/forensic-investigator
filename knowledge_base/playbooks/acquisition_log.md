# Playbook: Acquisition log (`Logs`)

This bucket is the **collector's own run log** (e.g. `ACQ-IR-<host>-<date>.log` from
AChoirX) — it documents *the collection itself*, not the compromise. **Low forensic
value.** Don't spend many steps here.

## What it's good for
- **Provenance / scope**: when the collection ran, on which host, and **what was or wasn't
  captured** (e.g. a bucket that failed or was skipped) — useful for explaining a gap
  elsewhere ("SRUM wasn't collected on this host").
- A sanity check on collection time vs. the incident timeline.

## How to work it
`list_files(artifact="Logs")` then `read_file(path)` if a question is specifically about
the collection process. Run `find_flags` once (a marker could be planted anywhere), then
`mark_examined("Logs")` and move on — the real evidence is in the other buckets.
