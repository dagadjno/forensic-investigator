# Playbook: Running-process snapshot (`Proc`)

What was **live on the host at the moment of collection** — a process snapshot, not a
historical timeline. **Not parsed** — reach it via `list_files(artifact="Proc")` then
`read_file(path)`; cite the `file:<path>:<line>` locator.

## Files (use the richest one for the question)
- `Tasklist.dat` — `tasklist` table: Image Name, **PID**, Session, Mem, User Name, Window
  Title. **No command line.**
- `TaskAll.dat` / `Info.dat` — fuller listings (often include **command line** and/or
  modules/services per process — best for *how* a process was launched).
- `PSList.dat` — PID/PPID and start time (best for **parent→child** relationships).

## What to look for
- A process running from **`\Temp\`, `\AppData\`, `\Users\Public\`, `\ProgramData\`** or a
  download path — executables rarely live there legitimately.
- **Masquerading** names (`svch0st.exe`, `lsass .exe`, `chrome.exe` outside Program Files).
- **Anomalous parent→child** (e.g. `winword.exe`→`powershell.exe`, `explorer`→`cmd`→LOLBin).
- A **remote-access tool** (AnyDesk, TeamViewer, ScreenConnect, ngrok) or hacking tool
  (mimikatz, Rubeus, PsExec) present in the live process set.
- The **User Name** column attributes the process to an account (SYSTEM vs a logged-on user).

## Cross-reference
- Memory `windows.pstree` / `pslist` / `cmdline` (vol_run) — authoritative process tree and
  full command lines straight from RAM, including processes hidden from a user-space dump.
- `Conn/CPorts.csv` — ties one of these PIDs to a remote IP (C2).
- Amcache / `Ranprog` — confirms the on-disk binary and its hash.

## Concluding
`find_flags` if you haven't, then `mark_examined("Proc")` when done with this lead.
