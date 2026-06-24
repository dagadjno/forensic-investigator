# Artifact Map (dir-code legend)

The triage collection uses short dir-codes. What each holds and where answers tend to hide:

| Code | Artifact | Good for |
|------|----------|----------|
| `Arn` | Amcache + Autoruns | program execution evidence, persistence (autoruns) |
| `Brw` | Browser history/downloads | visited sites, downloaded files (filenames + source URLs) |
| `Conn` | Network (arp, cports, ipconfig, netbios) | connections, listening ports, host networking, hostnames |
| `Evt` | Windows event logs (EVTX) | logons (4624/4625), service installs, PowerShell (4104), process creation (4688) |
| `Lnk` | LNK / shortcut files | recently opened files + their original target paths |
| `Logs` | Acquisition log | what the collector did and when |
| `MemDump` | Memory image | running processes, network, injected code (needs Volatility) |
| `Proc` | Process / task listings | what was running at collection time |
| `Psh` | PowerShell console history | commands users typed in PowerShell (plain text, high signal) |
| `Ranprog` | Prefetch | programs that were run + run counts/times |
| `RawData` | `$MFT`, `$LogFile`, `$UsnJrnl` | file creation/deletion timeline, deleted files |
| `Rcy` | Recycle Bin | deleted files + original paths |
| `Reg` | Registry hives (incl. SAM) | users, run keys, USB, typed paths, config |
| `Sch` | Scheduled tasks | persistence, scheduled execution |
| `Sys` | SRUM / system info | app+network resource usage over time, host facts |
| `WMI` | WMI repository (`OBJECTS.DATA`) | WMI event-subscription persistence |

Easter-egg / benign-trivia answers (a person's department, a pet's name, etc.) most
often live in: `Brw` (browsing), `Lnk`/`Rcy` (file names), `Reg` (typed paths, profile
info), and image/document files surfaced via `list_files` (POINT at these — don't guess).
