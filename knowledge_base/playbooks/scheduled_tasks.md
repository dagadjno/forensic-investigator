# Playbook: Scheduled tasks & services (`Sch`)

Persistence evidence captured as text dumps. **Not parsed into the timeline** — reach it
via `list_files(artifact="Sch")` then `read_file(path)`; cite the `file:<path>:<line>`
locator. Scheduled tasks = ATT&CK **T1053.005**, services = **T1543.003** — both classic
ways an attacker survives reboot.

## Files
- `SchedTasks.dat` — a `schtasks /query` dump. Each task's **name, run-as principal,
  trigger (logon/boot/time), and the command + arguments** it runs.
- `Services.dat` — installed services: **name, display name, state, start type, and the
  binary path** (`ImagePath`).

## What to look for
- A task/service whose command launches from **`\Users\Public\`, `\AppData\`, `\Temp\`,
  or `\ProgramData\`**, or invokes a **LOLBin** (`powershell`, `mshta`, `rundll32`,
  `regsvr32`, `cmd /c`, a `.ps1`/`.bat`/`.vbs`).
- **Run-as SYSTEM** or a logon/boot trigger on an otherwise unremarkable-looking entry.
- A name that **mimics a legit task/service** (typo-squat, odd casing) or an unusual
  **Author**.
- An **auto-start service** pointing at an unsigned binary in a user-writable path.

## If `SchedTasks.dat` is empty / errored
The dump sometimes fails ("request not supported"). Don't conclude "no persistence" —
fall back to:
- **EVTX**: `query_timeline(source="event_logs", contains="4698")` (task created), `4702`
  (updated), `4699/4701`, and Service Control Manager **`7045`** (service installed).
- **Registry** Run/RunOnce keys and the `Services\` tree (`source="registry"`).

## Cross-reference
Autoruns (`Arn` / amcache.md) lists tasks & services alongside other ASEPs **with hashes**;
the `Ranprog`/amcache buckets confirm whether the referenced binary actually executed.

## Concluding
Run `find_flags` if you haven't, then `mark_examined("Sch")` when done with this lead.
