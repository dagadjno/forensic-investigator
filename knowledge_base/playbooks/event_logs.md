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
**Logons / sessions (Security):** 4624 successful logon (check `LogonType`: 3=network,
10=RDP, 2=interactive), 4625 failed logon (brute force), 4634/4647 logoff, 4648 explicit-
credential logon, 4672 admin logon, 4778/4779 session reconnect/disconnect.
**Kerberos / NTLM (Security — especially on Domain Controllers):** 4768 TGT requested,
4769 service ticket (TGS) requested, 4771 pre-auth failed, 4776 NTLM validation, 4777 NTLM
failure. These trace **authentication and lateral movement across the domain** — the
`TargetUserName` / `IpAddress` / `ServiceName` fields show who authenticated to what and
from where. Essential for pivot detection and ticket attacks; on a DC this is the richest
lateral-movement evidence.
**Account management (Security):** 4720 user created, 4722/4725/4726 enabled/disabled/
deleted, 4723/4724 password change/reset, 4738 user changed, 4740 locked out, 4767
unlocked, 4781 renamed.
**Group management (Security — AD):** 4727/4731/4754 group created (global/local/
universal), 4730/4734 deleted, 4737/4755 changed, **4728/4732/4756 member ADDED**,
4729/4733/4757 member removed, 4764 group type changed. Trace attacker AD group
manipulation (adding accounts into privileged or nested groups → Domain Admins).
**Recon (Security):** 4798 user's local-group membership enumerated, 4799 security-group
membership enumerated.
**File-share access (Security):** 5140 share accessed, 5145 detailed file access,
5142-5144 share added/modified/deleted.
**Execution:** 4688 process creation (`NewProcessName` + `CommandLine`), Sysmon 1
process create (`Image`, `CommandLine`, `ParentImage`, `Hashes`), prefetch corroboration.
**PowerShell:** 4104 ScriptBlock logging (`ScriptBlockText` — decoded scripts, often
the richest evidence), 4103 module logging.
**Persistence:** 7045 service install (`ServiceName`, `ImagePath`), TaskScheduler
106/200/201 (also Security 4698), Sysmon 12/13 registry, Sysmon 11 file create, WMI
**5859/5860/5861** (event-subscription persistence).
**Network (Sysmon 3):** `DestinationIp`/`DestinationPort`/`DestinationHostname` —
corroborate C2 seen elsewhere (e.g. PowerShell history).
**Defense evasion / anti-forensics:** 1102 Security log cleared, 104 other log cleared,
4719 audit policy changed, 4616 system time changed, Defender 5001/5007, service stops
(7034/7036).
**RDP:** RemoteConnectionManager **1149** + LocalSessionManager **21/22/25** record inbound
interactive sessions with the `User` + source `Address`; the **RDP-Client** channel records
*outbound* RDP — i.e. this host as the lateral-movement **source**.
**Other channels now parsed:** BITS-Client (downloads via BITS), AppLocker (blocked/allowed
execution), SMB-Server/Client Security (share auth/access), Directory Service (AD object
changes on DCs).

## Attribution: "who connected from where"
For "which IP did <account> connect/log in from", match the **account to its logon
event** — do NOT answer with the most-frequently-seen IP. The high-count IP is almost
always infrastructure (a DNS/LDAP/domain controller in constant Sysmon-3 background
chatter), not a person. Use:
- **Security 4624** with `LogonType=10` (RDP) or `=2` (interactive) — read its
  `IpAddress` + `TargetUserName`.
- **RDP operational logs** — RemoteConnectionManager **1149** and LocalSessionManager
  **21/22/25** state the `User` + source `Address` explicitly.
- **4778/4779** reconnect/disconnect (source `ClientAddress`).
The answer is the IP on the event that *names the account and an interactive/RDP logon* —
even if it appears only a few times — not the noisiest IP in the timeline.

## Correlate
Event logs are where you confirm/expand leads from other artifacts: a C2 IP from
PowerShell history should show in Sysmon 3; a downloaded payload in Sysmon 1/4688;
an RMM install in 7045 or process creation. Tie events together by user + time + host
and record one finding per distinct activity (reuse the ATT&CK technique so evidence
merges rather than duplicating).

## Concluding
When you've reviewed the relevant events for this lead, `mark_examined("Evt")`.
