# Playbook: Amcache (program execution evidence)

Amcache.hve (parsed from the registry tree) records executables that were present/run on
the host, **with SHA1 hashes**. It lands in the timeline as `source="amcache"`, separate
from `source="registry"`. Cite the row `locator`.

## How to work it
- `query_timeline(source="amcache", contains="...")` — filter by a program name, path,
  publisher, or a hash.
- `grep_artifact(pattern, source="amcache")` — regex across amcache summaries.
- Categories (`event_type`): `amcache:file` (individual executables — path + SHA1 + size +
  compile date) and `amcache:program` (installed applications).

## Why it matters
- **SHA1 of executables** (`sha1=...` in the summary, full `FileId` in raw) — pivot a
  suspicious binary against threat intel / VirusTotal, or confirm a payload's identity.
- **Path + presence** — proves a binary existed on disk even if it's since deleted;
  corroborates execution seen in PowerShell history, event logs (Sysmon 1 / 4688), and
  the `Ranprog` binary copies.
- **Compile date (`LinkDate`)** and **size** — anomaly hunting (recently compiled,
  unusual size) and matching to known samples.
- **Publisher / ProductName** — unsigned or oddly-attributed binaries stand out.

## get_raw_event
Summaries show the headline fields; the full Amcache entry (e.g. `ProgramId`,
`BinFileVersion`, `BinaryType`, `Usn`, full `FileId`) is in `raw`. If a summary ends with
`[+N more fields — get_raw_event]`, call `get_raw_event(locator)` for everything.

## Note
Amcache is parsed during the `Reg` coverage lead (the hive lives under `Reg/Programs/`),
so you'll see `source="amcache"` rows even though there's no separate Amcache bucket.
There is no `mark_examined("amcache")` — examining `Reg` covers it.
