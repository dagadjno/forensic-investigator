# Playbook: Linux running processes (`Proc`)

A snapshot of every process alive at collection time, parsed into `source="process"` — one event
per PID, correlating command line + owning user + executable SHA-1 + a deleted-executable flag.

## How to work it
- `query_timeline(source="process", contains="<name/path/user>")` — find a process by binary,
  argument, or user.
- `query_timeline(source="process", contains="sha1=")` then a specific hash for VT lookups.
- The raw text dumps hold more (`get_raw_event`, or `read_file` on `Proc/*.dat`): `proc-Environ.dat`
  (env vars — may hold `LD_PRELOAD`, proxies, C2), `proc-CWDs.dat` (working dirs), `proc-FDLinks.dat`
  (open files/sockets), `OpenFiles.dat`, `proc-Strings.dat` (strings of process memory).

## What to look for
- **Deleted-executable processes** (`event_type="process:deleted_exe"`): a process whose on-disk
  binary is **deleted while still running** — the classic Linux malware tell (run-then-`unlink`, or
  fileless exec from `memfd`). Almost always worth a finding (T1620 / T1070.004). `query_timeline(
  source="process", contains="DELETED-EXE")`.
- **Suspicious execution paths**: binaries running from `/tmp`, `/dev/shm`, `/var/tmp`, `/home`,
  `/run` (T1059) — legitimate daemons live in `/usr`, `/sbin`.
- **Masquerading**: a process `COMMAND` like `[kworker/…]` or `sshd` whose path/args don't match the
  real one; odd args on common names.
- **SHA-1** (`sha1=…`): hash of `/proc/PID/exe` — pivot to VirusTotal or compare against `dpkg`-owned
  binaries; an executable not owned by any package is suspect.
- **Interpreters / recon**: `python`, `perl`, `bash -i`, `nc`, `socat`, `curl|wget … | sh`, `nmap`,
  `masscan` running interactively.

Note: on a normal desktop, `memfd`/deleted **file descriptors** (pipewire, snap) are common — those
are `proc-DelFDLinks`, NOT the deleted-**executable** flag, and are not flagged here.

## Concluding
`mark_examined("Proc")` when done.
