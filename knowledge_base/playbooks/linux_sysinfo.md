# Playbook: Linux system info (`Sys`)

Host facts and inventory, collected as plain-text command dumps (`.dat`). Not parsed into the
timeline — `list_files(artifact="Sys")` then `read_file`, cite by line. Low forensic drama, but the
answer to many "what/which/version" questions and useful context for the rest of the investigation.

## Key files
- **`Uname.dat` / `Version.dat`** — kernel version, distro, architecture, hostname.
- **`hostname-f.dat`**, **`timedatectl-status.dat`** (timezone — important for aligning timestamps),
  **`uptime-s.dat`** (boot time), **`Logname.dat` / `Whoami.dat`** (who ran the collection).
- **`dpkg-l.dat`** — every installed package + version. Use it to decide whether a binary is
  package-owned (expected) or not (suspect); to spot attacker-installed tools; and for version/CVE
  questions. Corroborates `source="package"` (VarLog).
- **`EnVar.dat`** — environment variables (proxies, `LD_PRELOAD`, injected paths).
- **`lsmod.dat`** — loaded kernel modules; an unexpected module = possible LKM rootkit (T1547.006).
- **`dmesg.dat`** — kernel ring buffer (module loads, OOM, USB/device events, segfaults).
- `lscpu` / `lshw` / `lspci` / `lsusb` / `sysctl-a` — hardware & kernel tunables.

## What to look for
- An installed package or loaded module that isn't part of a stock Ubuntu baseline.
- Timezone (for converting/aligning event times), kernel version (for exploit/CVE relevance).

## Concluding
`mark_examined("Sys")` when done.
