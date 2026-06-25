# Playbook: Memory image (`MemDump`)

The host's RAM capture (`MemDump/WinPmemDump.Raw`, multi-GB) is **not** parsed into the
timeline up front. Analyze it **on demand** with the `vol_run` tool, which runs one
Volatility3 plugin and materializes each result row as a citable `source="memory"` event.

## When to reach for memory (and when NOT to)
Memory is **slow and expensive** — only use it for evidence that lives **only in RAM** and
that disk artifacts can't give you. First exhaust the disk buckets (Psh, Evt, Reg, Brw,
Amcache, USN/MFT). Good reasons to go to memory:
- a **running process / its command line** that left no disk trace,
- **network connections** active at capture time (C2 still connected),
- **injected / hollowed code** (no file on disk),
- a **secret that was typed at a console** (not written to a file).

If memory is disabled or has no image, `vol_run` says so — then `answer_question`
status=`pointer` at the MemDump image rather than guessing.

## How to work it
- `vol_run(plugin="windows.netscan.NetScan")` — runs the plugin (cached after first run).
- `vol_run(plugin=..., contains="13.58")` — filter to rows whose text matches (do this;
  process/handle lists are large).
- `vol_run(plugin=..., pid=1234)` — restrict to one process.
- Each row comes back with a `memory:<plugin>:<n>` locator; cite it. Summaries are trimmed —
  `get_raw_event(locator)` returns the full row.

## Plugin map (what answers what)
- **Processes:** `windows.pslist.PsList`, `windows.pstree.PsTree` (parent/child),
  `windows.psscan.PsScan` (also finds hidden/terminated via pool scan).
- **What ran / was typed:** `windows.cmdline.CmdLine` (process args),
  `windows.cmdscan.CmdScan` + `windows.consoles.Consoles` (console command history AND
  screen buffer — the place a typed password/URL/ID may survive).
- **Network:** `windows.netscan.NetScan` (scan, incl. closed), `windows.netstat.NetStat`.
- **Services:** `windows.svcscan.SvcScan`.
- **Injection / evasion:** `windows.malfind.Malfind` (private RWX/injected regions).
- **Process detail:** `windows.dlllist.DllList`, `windows.getsids.GetSIDs`,
  `windows.envars.Envars`, `windows.sessions.Sessions`.
- **Registry from RAM:** `windows.registry.printkey.PrintKey`,
  `windows.registry.userassist.UserAssist`.

## Important limitation
This Volatility build has **no credential-dump plugin** (no hashdump/lsadump/cachedump).
You cannot dump password hashes here. For a credential that a user/attacker *typed*, try
`consoles` / `cmdscan` / `cmdline`; otherwise POINT at the image.

## Concluding
When you've run the plugins this lead needs, `mark_examined("MemDump")`.
