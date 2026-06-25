# Artifact Map (dir-code legend)

The triage collection uses short dir-codes. What each holds and where answers tend to hide:

| Code | Artifact | Good for |
|------|----------|----------|
| `Arn` | Autoruns output + autostart binary copies | persistence (autoruns). NOTE: the Amcache hive lives under `Reg/Programs/` and is parsed as `source="amcache"` (execution evidence + SHA1 hashes) — see playbooks/amcache.md |
| `Brw` | Browser history/downloads | visited sites, downloaded files (filenames + source URLs) |
| `Conn` | Network (arp, cports, ipconfig, netbios) | connections, listening ports, host networking, hostnames |
| `Evt` | Windows event logs (EVTX) | logons (4624/4625), Kerberos/NTLM (4768/4769/4776 — lateral movement, esp. DCs), account & AD group changes (4720/4728/4732…), service installs (7045), PowerShell (4104), process creation (4688/Sysmon 1), share access (5140/5145), log clearing (1102/104) |
| `Lnk` | LNK / shortcut files | recently opened files + their original target paths |
| `Logs` | Acquisition log | what the collector did and when |
| `MemDump` | Memory image | running processes, network, injected code, typed console commands — analyzed on demand via the `vol_run` tool (see playbooks/memory.md) |
| `Proc` | Process / task listings | what was running at collection time |
| `Psh` | PowerShell console history | commands users typed in PowerShell (plain text, high signal) |
| `Ranprog` | Prefetch | programs that were run + run counts/times |
| `RawData` | `$MFT`, `$LogFile`, `$UsnJrnl` | USN journal parsed as `source="usn"` (curated file create/delete/rename — see playbooks/usn.md); full `$MFT` not parsed (POINT at it for a specific path/timestamp) |
| `Rcy` | Recycle Bin | deleted files + original paths |
| `Reg` | Registry hives (incl. SAM) | users, run keys, USB, typed paths, config |
| `Sch` | Scheduled tasks | persistence, scheduled execution |
| `Sys` | SRUM / system info | SRUDB.dat parsed as `source="srum"` (app activity windows + network connectivity — see playbooks/srum.md); also text exports (`LastActivity.csv`, `GPResult.txt`, `WinAudit`) readable via `read_file` |
| `WMI` | WMI repository (`OBJECTS.DATA`) | WMI event-subscription persistence |

Easter-egg / benign-trivia answers (a person's department, a pet's name, etc.) most
often live in: `Brw` (browsing), `Lnk`/`Rcy` (file names), `Reg` (typed paths, profile
info), and image/document files surfaced via `list_files` (POINT at these — don't guess).
