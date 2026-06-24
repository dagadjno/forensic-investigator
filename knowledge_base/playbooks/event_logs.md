# Playbook: Windows event logs (`Evt`)

EVTX records are parsed into the timeline as `source="event_logs"`, one event per
high-value record. Each summary is prefixed `[<Family> <EventID>]` and the
`event_type` is `<Family>:<EventID>` (e.g. `Security:4624`). Cite the row `locator`.

## How to work it
- `query_timeline(source="event_logs", ...)` — filter by `contains` (an EventID,
  username, IP, process name, service name…) or by `user`.
- `grep_artifact(pattern, source="event_logs")` — regex across event summaries.
- Summaries show only the top ~12 fields. If one ends with `[+N more fields —
  get_raw_event]`, the record has more (e.g. **Hashes** for Sysmon 1, `IntegrityLevel`,
  `LogonId`, `OriginalFileName`, `ParentProcessId`). Call `get_raw_event(locator)` to get
  the complete field set — do this when a question needs a field the summary didn't show
  (e.g. "what is the SHA256 of the payload?" → Sysmon 1 `Hashes`).

## High-value event IDs (what to look for)
**Logons / accounts (Security):** 4624 successful logon (check `LogonType`: 3=network,
10=RDP, 2=interactive), 4625 failed logon (brute force), 4672 admin logon, 4720 user
created, 4732 added to group, 1102 **audit log cleared** (anti-forensics).
**Execution:** 4688 process creation (`NewProcessName` + `CommandLine`), Sysmon 1
process create (`Image`, `CommandLine`, `ParentImage`), prefetch corroboration.
**PowerShell:** 4104 ScriptBlock logging (`ScriptBlockText` — decoded scripts, often
the richest evidence), 4103 module logging.
**Persistence:** 7045 service install (`ServiceName`, `ImagePath`), TaskScheduler
106/200/201, Sysmon 12/13 registry, Sysmon 11 file create.
**Network (Sysmon 3):** `DestinationIp`/`DestinationPort`/`DestinationHostname` —
corroborate C2 seen elsewhere (e.g. PowerShell history).
**Defense evasion:** 1102 (log cleared), Defender 5001/5007, service stops (7034/7036).

## Correlate
Event logs are where you confirm/expand leads from other artifacts: a C2 IP from
PowerShell history should show in Sysmon 3; a downloaded payload in Sysmon 1/4688;
an RMM install in 7045 or process creation. Tie events together by user + time + host
and record one finding per distinct activity (reuse the ATT&CK technique so evidence
merges rather than duplicating).

## Concluding
When you've reviewed the relevant events for this lead, `mark_examined("Evt")`.
