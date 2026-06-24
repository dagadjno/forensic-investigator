# Playbook: SRUM + system info (`Sys`)

SRUM (System Resource Usage Monitor, from SRUDB.dat) is parsed into the timeline as
`source="srum"`. It records, over time, which applications were active and the host's
network connectivity. Cite the row `locator`.

## How to work it
- `query_timeline(source="srum", contains="...")` — filter by app path, user SID, etc.
- `grep_artifact(pattern, source="srum")` — regex across SRUM summaries.
- Categories (`event_type`):
  - `srum:app` — **aggregated** per application: its active window (`first..last`), sample
    count, and total disk bytes read/written. (The raw table has thousands of hourly rows;
    this is a per-app rollup. App paths use the NT form `\Device\HarddiskVolume1\...` ≈ `C:`.)
  - `srum:network` — one record per network connection: app, connected duration, start time,
    interface.

## What to look for
- **Execution windows** — proof an app was active during a time range (corroborates
  PowerShell history / event logs / prefetch). Unexpected apps with activity stand out.
- **Heavy disk I/O** — large `bytesWritten`/`bytesRead` can indicate staging, archiving,
  or dumping (e.g. an archive tool or a memory-dumper).
- **Network connectivity periods** — when the host was connected and for how long;
  pair with PowerShell/EVTX C2 timestamps.

> Note: this collection does **not** contain SRUM's per-app network *data-volume* table
> (bytes sent/received), so SRUM here gives app *activity* + connectivity, not network byte
> counts. For network destinations/ports, use `Conn/CPorts.csv` and Sysmon 3 events.

## Other Sys artifacts (read directly)
The `Sys` bucket also holds text exports you can `read_file` (they aren't parsed into the
timeline): `LastActivity.csv` (a LastActivityView action timeline — high value),
`GPResult.txt`, `WinAudit`/`WinAudLog.txt`, `services`, `hosts`, `networks`. Use
`list_files(artifact="Sys")` then `read_file` for these.

## get_raw_event
The summary shows the rollup/headline; the full record (all SRUM columns) is in `raw` —
call `get_raw_event(locator)`.

## Concluding
When you've reviewed SRUM and the relevant Sys exports, `mark_examined("Sys")`.
