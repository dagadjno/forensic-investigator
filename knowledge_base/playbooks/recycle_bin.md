# Playbook: Recycle Bin (`Rcy`)

What was **deleted** on the host — often the only trace of a file the attacker removed
(anti-forensics) or staged. **Not parsed** — reach it via `list_files(artifact="Rcy")`.
Layout is `$Recycle.Bin/<SID>/...` with paired files per deleted item:

- **`$I######`** — metadata: the file's **original full path**, **deletion timestamp**, and
  **original size**. Small; may be readable (`read_file`) — if it comes back binary, use
  `mft_lookup` on the name or POINT at it.
- **`$R######`** — the deleted file's **actual content** (same suffix as the original). If
  it's a text type, `read_file` it; otherwise POINT.
- `desktop.ini` entries are noise — ignore them.

## What the SID tells you
The `<SID>` folder attributes the deletion to **a specific account**. Map the SID to a user
(`S-1-5-21-…-500` = the local Administrator; cross-ref `registry` SAM / profile list). "Who
deleted it" is answered by which SID folder the `$I/$R` pair sits in.

## What to look for
- A **deleted payload/tool/script** (`.exe`, `.ps1`, `.bat`, archive) — recover intent from
  the `$R` content and timing from the `$I` deletion timestamp.
- A **deleted document/credential file** (`passwords.txt`, a wordlist, a `.kdbx`).
- Deletion timestamps that line up with the **end** of the attack (cleanup phase).

## Cross-reference
- USN (`source="usn"`) — the `usn:delete` event for the same file (corroborating time).
- `mft_lookup(name)` — authoritative $SI/$FN MAC times and the full path.

## Concluding
`find_flags` if you haven't, then `mark_examined("Rcy")` when done with this lead.
