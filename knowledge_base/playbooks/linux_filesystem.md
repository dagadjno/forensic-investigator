# Playbook: Linux filesystem timeline (`Disk`)

`Disk/bodyfile.dat` (a Sleuthkit mactime bodyfile) is parsed into a **curated** filesystem MAC
timeline — `source="filesystem"`. It's the Linux analog of the Windows `$MFT`/USN timeline. The
raw bodyfile has 100k+ entries; the parser keeps only attacker-relevant locations (see below), so
if you need a path outside those, `read_file` the raw `Disk/bodyfile.dat` or `Disk/AllFiles.csv`.

## How to work it
- `query_timeline(source="filesystem", contains="/tmp/")` / `/dev/shm/` / `/home/` / a filename.
- Each event: `[fs <mode>] <path> size=… uid=… gid=… mtime=… ctime=…` with flags. `ts` = **mtime**.

## What's kept (curated) & why it matters
- Files under `/tmp`, `/var/tmp`, `/dev/shm`, `/home`, `/root`, `/usr/local`, `/opt`, `/run`,
  `/var/www`, `/srv` — where dropped payloads, webshells, and staging live (T1074 / T1105).
- Any **`SETUID/SETGID`** file anywhere (mode flag) — planted setuid root = privilege escalation
  (T1548.001). An unexpected setuid binary in `/tmp` or `/home` is a strong signal.

## Timeline tradecraft
- **`ctime` > `mtime`** is flagged **`TIMESTOMP?`** — metadata was touched after content, a common
  anti-forensic tell (T1070.006). `ctime` cannot be set by `touch`, so a mismatch is meaningful.
- Cluster files by **mtime** around the suspected intrusion window to see what was dropped/modified
  together; a burst of new executables in `/tmp` or `/dev/shm` is the payload staging.
- **`/dev/shm`** and **`/run`** are tmpfs (RAM) — malware favors them (no disk trace after reboot).
- Executables in world-writable dirs, hidden files (`/home/*/.<name>`), files owned by an unexpected
  uid.

## Concluding
`mark_examined("Disk")` when done.
