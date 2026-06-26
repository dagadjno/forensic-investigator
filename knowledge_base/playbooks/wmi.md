# Playbook: WMI persistence (`WMI`)

WMI event-subscription persistence — ATT&CK **T1546.003** — a stealthy way to run code on a
trigger (logon, time, process start) with no file on disk and no Run key. **Not parsed** —
reach it via `list_files(artifact="WMI")`.

> This bucket is **often empty** (host-dependent). If it is, say so and pivot to the EVTX
> cross-reference below rather than concluding there was no WMI activity.

## What's in it (when present)
- A binary **`OBJECTS.DATA`** (the CIM repository) — not text → **POINT** at it; it can't be
  read here. The repository holds any persistence triad:
  - **`__EventFilter`** — the trigger (a WQL query, e.g. fires N seconds after boot).
  - **`__EventConsumer`** — the payload. **`CommandLineEventConsumer`** (a command line) or
    **`ActiveScriptEventConsumer`** (inline VBScript/JScript) are the malicious ones.
  - **`__FilterToConsumerBinding`** — the link that arms filter→consumer.
- If the collection includes **text exports** of these classes, `read_file` them and quote
  the **`CommandLineTemplate`** / **`ScriptText`** verbatim — that's the payload.

## Cross-reference (the reliable signal here)
EVTX **WMI-Activity/Operational** is parsed into the timeline:
`query_timeline(source="event_logs", contains="5861")` (and `5857`–`5860`) shows consumer/
filter registration and execution — frequently the clearest proof of WMI persistence even
when the repository itself can't be read. Sysmon 19/20/21 (if present) also record it.

## Concluding
`find_flags` if you haven't, then `mark_examined("WMI")` when done with this lead.
