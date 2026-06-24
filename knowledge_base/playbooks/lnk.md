# Playbook: Shortcut / LNK files (`Lnk`)

LNK files are parsed into the timeline as `source="lnk"`, one event per shortcut. They
are strong evidence that a user **opened a specific file or folder** — the shortcut
embeds the target's full path, the target's MAC timestamps, size, and which volume it
lived on. Cite the row `locator`.

## How to work it
- `query_timeline(source="lnk", contains="...")` — filter by a filename, path, user, or
  drive type.
- `grep_artifact(pattern, source="lnk")` — regex across shortcut summaries.
- Most LNKs live under each user's `Recent/` folder (auto-created when a file is opened),
  so they're a per-user "recently accessed" trail. The shortcut name is the item opened.

## What to look for
- **Accessed sensitive files** — SSH keys, credential files, scripts, archives, tools
  (e.g. a `Recent/` LNK to another user's private key proves cross-user access).
- **Targets on other volumes** — `drive=DRIVE_REMOVABLE` (USB exfil) or network/`tsclient`
  paths (files pulled over RDP / shares = lateral movement or data transfer).
- **Target MAC timestamps** — the embedded `target C=`/`M=` times tell you when the
  opened file was created/modified, independent of the filesystem timeline.
- **command-line arguments** — present on some shortcuts; suspicious for LOLBins.

## Easter-egg note
`Recent/` LNKs are a goldmine for "what file did user X open" trivia questions — a
document, an image, a note on the Desktop. If the answer is in the target path/name you
can read, cite it; if it points at an image/doc you can't read, POINT at that file.

## get_raw_event
The summary shows the headline fields; the full parsed LNK record (target ID list, drive
serial number, machine identifier, extra blocks) is in `raw`. Call
`get_raw_event(locator)` for it.

## Concluding
When you've reviewed the relevant shortcuts for this lead, `mark_examined("Lnk")`.
