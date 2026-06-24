# Playbook: USN change journal (`RawData`)

The USN journal is the filesystem change log. It's parsed (from the USNJrnl.csv export)
into the timeline as `source="usn"` — but **curated**: only high-value lifecycle events
(file CREATE / DELETE / RENAME) for interesting file types (executables, scripts,
archives, docs, keys). The raw journal has hundreds of thousands of low-value
data-write/close records that are intentionally dropped. Cite the row `locator`.

## Important limitation (and the fix)
USN records the file **name only, not its directory**. To get the full path (and the
$SI/$FN timestamps), call **`mft_lookup(filename)`** — it resolves the file against the
$MFT on demand and returns a citable `source="mft"` row. So: find the change in USN, then
`mft_lookup` the filename to learn where it lived and when it was created/modified.

## How to work it
- `query_timeline(source="usn", contains="...")` — filter by filename or extension.
- `grep_artifact(pattern, source="usn")` — regex across USN summaries.
- Categories (`event_type`): `usn:create`, `usn:delete`, `usn:rename`.

## What to look for
- **Created executables/scripts** — payloads landing on disk, with the on-disk creation
  time (e.g. `launcher.exe` created at HH:MM corroborating a download in PowerShell).
- **Deleted files** — what the attacker removed (payloads, logs, tools). Deletions are
  often the only remaining trace of a removed file.
- **Renames** — masquerading (e.g. a `.txt` saved/renamed to `.ps1`/`.exe`).
- **Tooling artifacts** — wordlists (`passwords.txt`, name lists) = credential cracking;
  `.dmp` files = process memory dumps (LSASS theft); archives = staging/exfil.

## $MFT note
The full `$MFT` is deliberately NOT bulk-parsed (it would bury the timeline in every file
on the volume). Instead, use `mft_lookup(filename)` for **targeted** path/timestamp
resolution of specific files on demand. USN covers the recent-change timeline; mft_lookup
fills in the *where* and the authoritative MAC times for any file you care about.

## get_raw_event
The summary shows name + reason + timestamp; the full USN record (File ID, Parent file
ID, attributes, source info, security ID) is in `raw` — call `get_raw_event(locator)`.

## Concluding
When you've reviewed the relevant USN events for this lead, `mark_examined("RawData")`.
