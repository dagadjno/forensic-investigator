# Playbook: Browser history & downloads (`Brw`)

Browser data is parsed from the collection's CSV exports into the timeline as
`source="browser"`, one event per visit / download. Cite the row `locator`.

## How to work it
- `query_timeline(source="browser", contains="...")` — filter by URL, title, filename,
  domain, browser, or user.
- `grep_artifact(pattern, source="browser")` — regex across browser summaries.
- Categories (`event_type`): `browser:history` (visits) and `browser:download`
  (downloaded files).

## What to look for
- **Downloads** — attacker tools pulled via the browser (RMM installers, PuTTY, Chrome,
  archive tools, payloads). Each row has the source URL, the saved path, size, and
  timing. This is prime evidence of how tooling arrived on the host.
- **History** — visited sites: paste/transfer services, VirusTotal (checking payloads),
  webmail, cloud storage (exfil), attacker infrastructure, and `file://` URLs that reveal
  locally-opened files (often easter-egg trivia — a document, an image, a note).
- **User attribution** — the `User Profile` (history) / saved path (downloads) tells you
  *who* browsed.

## Easter-egg note
Benign-trivia answers frequently live in browser history — a searched term, a visited
profile page, a `file://` to a local document/image. If the answer is in a URL/title you
can read, cite it; if it's a downloaded image/doc you can't read, POINT at that file.

## get_raw_event
Summaries show the key columns; the full CSV row (e.g. `Visited From`, `Record ID`,
`MIME Type`, `Hash`, `Web Page URL`) is in `raw`. If a summary ends with
`[+N more fields — get_raw_event]`, call `get_raw_event(locator)` for the full row.

## Concluding
When you've reviewed the relevant browser events for this lead, `mark_examined("Brw")`.
