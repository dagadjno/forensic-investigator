# Playbook: Execution evidence (`Ranprog`)

This bucket is **execution evidence**, but its exact form depends on the collector — check
which you have with `list_files(artifact="Ranprog")` first.

## Two possible layouts
**A) DC33 / custom AChoirX — executable *copies* (this dataset).** Files are named like
`C-SecurityTools-SYS-cports.exe-4fa182c6a58819c5fcbd5be73694c4ac` — i.e.
`<orig-path-with-dashes>-<name>.exe-<MD5>`. **The filename IS the evidence**: it encodes the
binary's **original full path** and its **MD5 hash**, even though the file content is the
raw PE (binary — POINT, don't read). So:
- `list_files(artifact="Ranprog")` and read the **names** — each is a program that was
  present/ran, with where it lived and its hash.
- Pivot the **MD5** against threat intel; pivot the **path** to see if it's a user-writable
  / staging location.
- These often include the responder's *own* tools (Autorunsc, winpmem, cports) — distinguish
  those from attacker binaries by path/name.

**B) Stock AChoirX — real Prefetch (`.pf`).** Standard Windows prefetch: **first-run and
last-run times, run count, and referenced files/dirs**. `.pf` is binary → POINT at it (or
note it for PECmd); the catalog **name** still tells you *which* program executed.

## What to look for
- A binary executed from **`\Temp\`, `\AppData\`, `\Downloads\`, `\Users\Public\`**.
- A **hacking/RAT tool** name, or a legit-looking name in the wrong path.
- (Layout B) **first/last execution times** that anchor when the attack ran.

## Cross-reference
Amcache (`source="amcache"`) gives **SHA1 + presence** for the same binaries; `Conn` and
memory tie a running instance to a network connection; PowerShell history / EVTX show the
command that launched it.

## Concluding
`find_flags` if you haven't, then `mark_examined("Ranprog")` when done with this lead.
