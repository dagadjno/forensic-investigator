# Playbook: Program Compatibility Assistant (`PCA`)

**Execution evidence** — the PCA records applications the OS observed running (especially
GUI/installer apps), with **paths and timestamps**. A modern, high-value "what ran and when"
source (Windows 11 / Server 2022+). **Not parsed** — reach it via `list_files(artifact="PCA")`
then `read_file(path)`; the files are plain text. Cite the `file:<path>:<line>` locator.

## Files
- **`PcaAppLaunchDic.txt`** — the gold: **`<full exe path>|<last-run timestamp>`** per program.
  A direct "this binary executed, last at this time" list.
- **`PcaGeneralDb0.txt` / `PcaGeneralDb1.txt`** — broader records: program path, description,
  vendor, and an abort/compatibility status, with timestamps.

## What to look for (ATT&CK T1204 / execution)
- A binary that ran from **`\Temp\`, `\AppData\`, `\Users\Public\`, `\Downloads\`** or another
  user-writable / staging path.
- A **hacking/RAT tool** name, or a legit-looking name in the wrong directory.
- The **last-run timestamp** — anchors when the attacker's tooling executed; line it up with
  the PowerShell history, EVTX, and prefetch timeline.

## Cross-reference
- **Prefetch (`Prf`)** and **Amcache** — corroborate the same execution with run counts / hashes.
- **`Conn/CPorts.csv`** / memory — tie a still-running program to a network connection.
- PCA catches some GUI/installer launches that prefetch can miss, and vice-versa — use both.

## Concluding
Run `find_flags` if you haven't, then `mark_examined("PCA")` when done with this lead.
