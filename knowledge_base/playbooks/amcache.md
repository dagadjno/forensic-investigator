# Playbook: Amcache (execution) & Autoruns (`Arn`)

Two related things live here: **Amcache** (parsed → timeline, execution evidence) and the
**`Arn` bucket** (autoruns export + binary copies, read on demand). The coverage lead
you're on is for `Arn` — start with `list_files(artifact="Arn")` and the **Autoruns**
section at the bottom; the Amcache rows are already available from the `Reg` parse.

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

## Autoruns — the `Arn` bucket
`Arn/AutoRun.dat` is an **Autorunsc** export: one row per **autostart entry (ASEP)** across
Run keys, services, scheduled tasks, logon, drivers, codecs, and Boot Execute — a single
view of everything set to run automatically, **with hashes**. Read it with
`read_file("Arn/AutoRun.dat")` (it's UTF-16 but decoded for you). Columns include:
**Time, Entry Location** (the autostart key/path), **Entry, Enabled, Category, Description,
Company, Image Path** (the binary), **Launch String** (full command), and **MD5 / SHA-1 /
SHA-256**.

What to look for (ATT&CK **T1547** autostart, **T1543** services, **T1053** tasks):
- An **Image Path / Launch String in a user-writable dir** (`\Users\Public\`, `\AppData\`,
  `\Temp\`, `\ProgramData\`) or invoking a LOLBin/script.
- **Blank or untrusted Company** / unsigned entries; a name masquerading as a system entry.
- Pivot the **hash** against threat intel; cross-ref the same path in Amcache/`Ranprog` to
  confirm it actually executed.

The `Arn` bucket also holds **copies of some autostart-referenced binaries** (e.g.
`Arn/system32/*.dll`, `Arn/installer/setup.exe`) — these are PE files (binary → POINT/hash),
but their catalog **paths** themselves are evidence of what was set to load.

## Concluding & note
Amcache is parsed during the `Reg` coverage lead (the hive lives under `Reg/Programs/`), so
you'll see `source="amcache"` rows even though there's no separate Amcache bucket — there is
no `mark_examined("amcache")`. The **`Arn` bucket IS a real bucket**: when you've reviewed
`AutoRun.dat` (run `find_flags` too), call `mark_examined("Arn")`.
