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

## Collector-introduced tooling (do NOT attribute to the attacker)
The acquisition itself drops and runs DFIR tooling on the host, which then shows up in
service installs (7045), process creation, prefetch, amcache, and the file catalog. When a
question asks what the **attacker** installed/ran, **exclude the collector's own tools**:

- **WinPmem** / `pmem` / `winpmem*.exe` / the `pmem` kernel driver — memory acquisition (Windows).
- **avml** (`*avml*`) — the Linux memory-acquisition tool (its binary copy appears under `RanProg`).
- **AChoir / AChoirX** (`AChoir*.exe`, `Ach*.exe`) — the collection framework itself.
- Bundled sysinternals / coreutils the collector invokes during acquisition (on Linux the collector
  runs `ps`, `ss`, `lsof`, `find`, `dpkg`, etc. — their `RanProg` copies are collector activity).

**Scope the exclusion by TIME, not just by name.** These run *during the acquisition window*
(see the collection start time in this log) — typically well after the incident. A
same-named tool the *attacker* dropped earlier, inside the incident window, is NOT collector
noise. So: confirm the artifact's timestamp matches the acquisition before discounting it,
and if a tool is genuinely ambiguous, surface it with a note rather than silently dropping
it. The intended "suspicious install" answer is the **attacker's** service, not WinPmem.
