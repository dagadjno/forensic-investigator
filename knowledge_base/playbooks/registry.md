# Playbook: Windows registry (`Reg`)

Registry hives are parsed into the timeline as `source="registry"`, one event per
high-value key/value. Summaries are prefixed by category, e.g. `[Run]`, `[Installed]`,
`[Service]`, `[USB]`, `[Account]`, `[RunMRU]`, `[TypedPath]`, `[UserAssist]`,
`[Network]`, `[OSInfo]`, `[System]`. The `event_type` is `registry:<category>`
(persistence, software, service, usb, account, activity, execution, network, osinfo,
system). Cite the row `locator`.

## How to work it
- `query_timeline(source="registry", contains="...")` — filter by category tag,
  program name, username, path, etc.
- `grep_artifact(pattern, source="registry")` — regex across registry summaries.

## What's captured & why it matters
- **persistence** — Run/RunOnce keys (SOFTWARE + per-user NTUSER). Attacker autostart.
- **service** — services whose ImagePath is non-standard/suspicious (powershell, temp,
  users, appdata, rundll32/mshta/regsvr32…). Service-based persistence.
- **software** — installed programs (Uninstall keys): RMM tools (AnyDesk, TeamViewer),
  hacking tools, anything unexpected. Corroborates installs seen elsewhere.
- **account** — local accounts (SAM user names). Rogue/added accounts.
- **execution** — UserAssist (GUI program execution, ROT13-decoded). What the user ran.
- **activity** — RunMRU (Run-dialog commands typed) and TypedPaths (Explorer). High
  signal for both attacker actions and benign user trivia (easter eggs).
- **usb** — USBSTOR device history. Data exfil / device use.
- **network** — saved network profiles (SSIDs / network names).
- **osinfo / system** — OS build, registered owner, computer name, timezone (host facts;
  registered owner/org sometimes answers "who/what department" style questions).

## Easter-egg note
Benign-trivia answers (a person's name, a project, a typed path, a recent program)
often live in `activity` (RunMRU/TypedPaths), `execution` (UserAssist), `software`, or
`osinfo` (RegisteredOwner/Organization). If the answer is in a value you can read,
cite it; if it points to a file you cannot read, POINT at that file instead.

## Concluding
When you've reviewed the relevant registry events for this lead, `mark_examined("Reg")`.
