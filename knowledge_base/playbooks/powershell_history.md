# Playbook: PowerShell console history (`Psh`)

PowerShell console history is plain text — one command per line, per user
(`ConsoleHost_history.txt`). It records what a user actually typed, so it is high-signal
for both attacker activity and benign user trivia.

## How to work it
1. `query_timeline(source="powershell_history")` (or `grep_artifact` over it) to see the
   commands. Each row has a `locator` you cite.
2. Read top-to-bottom: history is roughly chronological within a file.

## Suspicious patterns (file a finding, cite the line)
- Encoded / obfuscated execution: `-enc`, `-EncodedCommand`, base64 blobs,
  `FromBase64String`, `-w hidden`, `-nop`, `IEX`, `Invoke-Expression`.
- Download + execute: `Invoke-WebRequest`/`iwr`/`curl`/`wget`, `DownloadString`,
  `Net.WebClient`, `Start-BitsTransfer` followed by execution.
- Credential / discovery: `Mimikatz`, `Get-ADUser`, `net user`, `whoami /all`,
  `Get-LocalUser`, dumping `lsass`.
- Persistence: `New-ScheduledTask`, registry Run-key writes, `New-Service`.
- Defense evasion: `Set-MpPreference -DisableRealtimeMonitoring`, clearing logs.

When you find an encoded blob, do NOT try to fully decode it inline — `file_lead` it
("decode encoded PowerShell at <locator>") so it gets its own focused investigation.

## Benign / trivia answers
History also captures ordinary typing — names, paths, project names, hostnames,
search terms. For an easter-egg question, grep the history for the subject (a person's
name, "cat", "department", etc.) and cite the matching line if found. If the answer
clearly lives in a file the command references but you cannot read (an image, a doc),
POINT at that file via `list_files` instead of guessing.

## Concluding
Once you've read the relevant history for this lead and recorded findings/answers,
`mark_examined("Psh")` and stop.
