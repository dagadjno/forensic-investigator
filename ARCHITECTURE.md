# Architecture

A reference for engineers working on **forensic-investigator**. It explains the agent
topology, how the agents coordinate, the tool layer, how everything reads and writes the
Case File (SQLite), and the LLM plumbing. For *usage*, see `README.md`; for the day-of CTF
runbook, see `CTF_PLAYBOOK.md`.

---

## 1. Design thesis (read this first)

The whole system exists to make an LLM do forensics **without hallucinating**. The rule that
drives every design decision:

> **The LLM never parses raw bytes, and may never assert anything it can't cite to a real
> parsed record.**

This is enforced in three ways, structurally — not just by prompting:

1. **Parse before reason.** Deterministic, trusted parsers turn binary artifacts (EVTX,
   registry hives, `$MFT`, SRUDB.dat, …) into normalized rows in SQLite *first*. The agent
   only ever sees that structured data.
2. **Citation-at-write-time.** Every read tool *registers* the locators it hands back. A
   finding/answer is **rejected** at write time if it cites a locator no tool emitted.
3. **Independent verification.** A final pass re-resolves every cited locator against the DB
   and flags any that don't exist.

Everything below is in service of those three guarantees.

---

## 2. The three layers

```
            ┌──────────────────────────────────────────────────────────────┐
            │  A. PARSE (deterministic, no LLM)                            │
 evidence ─▶│     src/extraction/*  ─▶  normalized rows in case.db         │
  folder    └──────────────────────────────────────────────────────────────┘
                                  │
            ┌─────────────────────▼────────────────────────────────────────┐
            │  B. INVESTIGATE (agentic loop, the only LLM-driven layer)     │
            │     orchestrator ⇄ Case File ⇄ sub-agents ⇄ tools            │
            └─────────────────────┬────────────────────────────────────────┘
                                  │
            ┌─────────────────────▼────────────────────────────────────────┐
            │  C. REPORT (deterministic, no LLM)                            │
            │     render Markdown/HTML from the ledger + verify citations   │
            └──────────────────────────────────────────────────────────────┘
```

Only **layer B** calls the LLM. Layers A and C are ordinary Python and produce identical
output every run. `main.py :: cmd_investigate` runs the three in sequence per host.

---

## 3. The Case File is the bus (`output/<case-id>/case.db`)

There is **no direct message-passing between agents.** The orchestrator and every sub-agent
communicate exclusively through one SQLite database — a classic **blackboard architecture**.
This is the single most important structural fact about the system. Because all state is
durable in SQLite, the run is **resumable** (re-run with the same `--case-id`) and
**idempotent** (parsing is skipped if `meta.ingested=1`).

Schema in `src/store/schema.sql`, wrapped by `src/store/case_db.py :: CaseDB`. Every table and
column below, with **real example rows** from a DC33 host investigation.

### The locator (the citation handle)

A **locator** is the stable string a read tool returns and a finding/answer cites. Format is
`"<source>:<relpath>:<record-key>"`, where the `<source>` prefix equals the row's
`source_artifact` and the record-key depends on the source:

| source | record-key | example locator |
|--------|-----------|-----------------|
| `event_logs` | EVTX record id | `event_logs:Evt/.../Security.evtx:269584` |
| `powershell_history` | line number | `powershell_history:Psh/Users/<u>/.../ConsoleHost_history.txt:1` |
| `registry` | key path | `registry:Reg/Config/SAM:SAM\Domains\Account\Users\Names\Administrator` |
| `amcache` | entry id | `amcache:Reg/.../Amcache.hve:1234` |
| `browser` | csv row | `browser:Brw/History.csv:42` |
| `usn` | USN number | `usn:RawData/.../USNJrnl.csv:5916816` |
| `srum` | row id | `srum:Sys/.../SRUDB.dat:88` |
| `mft` *(on-demand)* | `$MFT` record no. | `mft:RawData/C/$MFT:248126` |
| `memory` *(on-demand)* | result index | `memory:netscan:7` |
| `file` *(catalog)* | — or `:<line>` | `file:Conn/CPorts.csv` · `file:Logs/run.log:88` |

### `events` — the normalized timeline (the bulk of the DB)

One row per parsed record. This is what `query_timeline`/`grep_artifact` search.

| Column | Holds | Example |
|--------|-------|---------|
| `id` | autoincrement PK | `34019` |
| `ts` | ISO-8601 event time, or `""` if the artifact has none | `2025-06-29T00:45:51.439092Z` |
| `source_artifact` | which parser produced it (= locator prefix) | `powershell_history` |
| `host` | host name if the record carries one | `namtws004.mtfin.local` |
| `user` | user/SID associated with the event | `administrator.MTFIN`, `S-1-5-18` |
| `event_type` | parser sub-type tag | `ps_command`, `BITS:306`, `mft:file` |
| `summary` | the human/agent-readable line (capped ~600 chars; may end `[+N more fields — get_raw_event]`) | `get-content 'C:\Program Files (x86)\ossec-agent\ossec.conf'` |
| `locator` | stable citation handle (see above) | `powershell_history:Psh/Users/administrator.MTFIN/.../ConsoleHost_history.txt:1` |
| `raw` | full field set as JSON (event logs/registry) or the raw line; backs `get_raw_event` | `{"EventID":4720,"TargetSid":"S-1-5-...",...}` |

`idx_events_source` indexes `source_artifact` (the most common filter).

### `files` — metadata for EVERY file (incl. unparseable binaries)

Powers POINTER answers and `mft_lookup`/`read_file` path resolution.

| Column | Holds | Example |
|--------|-------|---------|
| `path` (PK) | path relative to the artifact root | `RawData/$UsnJrnl_$J.bin` |
| `artifact` | owning dir-code | `RawData` |
| `name` | basename | `$UsnJrnl_$J.bin` |
| `owner` | best-effort owner from the path (`Users/<x>/`) | `gloria.bradley` |
| `size` | bytes | `39071552` |
| `mtime`/`ctime`/`atime` | filesystem MAC times (ISO-8601) | `2025-07-02T01:17:35+00:00` |
| `is_text` | 1 if readable as text (content-sniffed) → `read_file` works; else POINT only | `0` |

### `coverage` — the bucket manifest (drives termination)

| Column | Holds | Example |
|--------|-------|---------|
| `artifact` (PK) | dir-code | `Arn` |
| `type` | artifact type from the map | `amcache_autoruns` |
| `parser` | parser module name, or NULL (catalog-only) | `NULL` |
| `present` | 1 if the folder exists in this collection | `1` |
| `status` | `unexamined → triaged → analyzed`; run ends when none are `unexamined` | `analyzed` |

### `leads` — the work queue (the engine)

| Column | Holds | Example |
|--------|-------|---------|
| `id` (PK) | order tiebreaker | `1` |
| `title` | the task | `Answer: A user on NAMTWS04 created a file they wanted to keep under wraps. …` |
| `reason` | why (for agent-filed leads) | `""` |
| `source` | `question` \| `coverage` \| `agent` | `question` |
| `question_id` | set when `source=question` | `q870b206e` |
| `artifact` | target bucket when `source=coverage` | `NULL` |
| `priority` | higher = sooner (question 70; coverage from the per-bucket table / router) | `70` |
| `depth` | agent-filed lead chain depth (capped by `max_lead_depth`) | `0` |
| `status` | `open → in_progress → closed` | `closed` |
| `dedup_key` | `UNIQUE` — `source\|qid\|artifact\|title` — blocks re-filing the same lead | `question\|q870b206e\|\|answer: a user on namtws04 …` |

### `findings` + `finding_evidence` — the ledger

| `findings` column | Holds | Example |
|-------------------|-------|---------|
| `id` (PK) | finding id | `1` |
| `title` | short title | `User hid file in deeply obfuscated directory structure` |
| `severity` | `info\|low\|medium\|high\|critical` | `medium` |
| `confidence` | `low\|medium\|high` | `high` |
| `attack_technique` | ATT&CK id (dedup key with a shared locator) | `T1564` |
| `description` | free text | `gloria.bradley created a deeply nested folder tree …` |
| `status` | ledger status | `corroborated` |
| `created_at` | ISO-8601 | `2026-06-26T15:08:09.6…` |

`finding_evidence`: `finding_id` → (`locator`, `excerpt`). Example:
`(1, "mft:RawData/C/$MFT:248126", "\Users\gloria.bradley\…\DO NOT LOOK\…")`.

### `questions` / `answers` / `answer_evidence` / `answer_candidates`

`questions`: `id` = content hash `q<sha1[:8]>` of the normalized text · `text` = the question.
Example: `("q79044b52", "What SID of the first account created by the compromised account…?")`.

| `answers` column | Holds | Example |
|------------------|-------|---------|
| `id` (PK) | answer id | `1` |
| `question_id` | FK to `questions.id` | `q870b206e` |
| `status` | `answered \| pointer \| unresolved` | `answered` |
| `answer` | the answer text (verbatim token when applicable) | `C:\Users\gloria.bradley\…\DO NOT LOOK` |
| `confidence` | `low\|medium\|high` | `high` |
| `reasoning` | rationale; for unresolved, **what was searched** | `User gloria.bradley created a deeply nested folder …` |
| `created_at` | ISO-8601 | `2026-06-26T15:08:09.6…` |
| `question_text` | snapshot of the question text → answer survives a question-set change | `A user on NAMTWS04 created a file …` |

- `answer_evidence`: `answer_id` → (`locator`, `excerpt`) — for **answered**.
- `answer_candidates`: `answer_id` → (`path`, `reason`) — for **pointer** (paths must exist in
  `files`). Example: `(7, "Brw/Downloads/proof.png", "screenshot likely shows the answer")`.

### `emitted_locators` — the citation registry (anti-hallucination)

Every locator any tool has returned. A finding/answer may only cite a locator present here.

| Column | Holds | Example |
|--------|-------|---------|
| `locator` (PK) | the emitted locator | `event_logs:Evt/.../Microsoft-Windows-PowerShell%4Operational.evtx:191054` |
| `kind` | `event` \| `file` \| `file_line` | `event` |
| `detail` | optional (e.g. the file path for `file_line`) | `""` |

### `meta` — case state

Key/value. `("ingested","1")` flags a completed parse (idempotent ingest / resume). `meta`
plus the schema's `IF NOT EXISTS` + `CaseDB._migrate` (e.g. the `answers.question_text` column
add) let an older `case.db` upgrade in place when reopened.

---

## 4. Layer A — deterministic parse (`src/extraction/`)

`ingest.py :: ingest()` walks the read-only evidence root and:

1. Builds the **coverage manifest** from the artifact map (`config/artifact_map*.yaml` — the
   dir-code → (type, parser) adapter). Codes that map but aren't present are marked absent.
2. **Catalogs every file** into `files` (path/owner/size/MAC times). `is_text` is set by a
   content sniff (`src/textutil.py`), so plain-text `.dat` dumps are readable while registry
   hives stay binary.
3. Runs each available parser for present, parseable buckets. Parsers
   (`psh, evtx, registry, browser, lnk, usn, srum`) emit normalized rows into `events` via
   `case.add_event(...)`, each with a **stable `locator`** (see §3).

Two artifacts are deliberately **not** bulk-parsed (too large): the full `$MFT` and the memory
image. They're queried lazily during layer B (see §6, on-demand tools).

### The parser contract (shared by every parser)

Each `src/extraction/<x>.py` exposes one `parse(case, root, dir_code)` and obeys the same
five rules, so they're interchangeable and degrade predictably:

1. **Curate, don't dump.** A triage collection is mostly noise (a DC's `Security.evtx` alone is
   ~170k records; a `$MFT`/USN journal is hundreds of thousands of files). Parsers emit a *high-
   value allowlist* — chosen channels/IDs/keys/event-types — so the timeline stays a signal, not
   a haystack. Completeness is recovered on demand (`get_raw_event`, `mft_lookup`), not up front.
2. **Read by name, never by position.** CSV via `DictReader`, EVTX via `EventData Name=`, ESE/
   registry by column/value name. A newer collector that adds or reorders columns is *ignored,
   not fatal*. CSV column lookups go through a tolerant `_get(row, *candidates)` (case-insensitive,
   first non-empty) so vendor-tool header drift is absorbed.
3. **Summary + full raw.** Every row gets a short, triage-readable `summary` AND the complete
   underlying record as JSON in `events.raw`. When the summary omits fields it appends
   `[+N more fields — get_raw_event]`, so nothing is silently lost — the agent can pull the full
   object with `get_raw_event`.
4. **Stable locator per row** (the citation handle — §3): `<source>:<relpath>:<record-key>`.
5. **Degrade gracefully.** A missing backend library (registry/lnk/srum/evtx) or absent input
   *skips that bucket* with a one-line note; the file catalog still lets the agent POINT at it.

The owning user is recovered the same way everywhere — the `…/Users/<user>/…` path segment.

### How each parser reads its source

**`psh` — PowerShell console history** (`ConsoleHost_history.txt`, plain text). Walks the bucket
for `*history*` / `*.txt`, emits **one event per non-empty line** (a typed command). These files
carry no timestamps, so events are ordered but un-timed; `raw` is the verbatim line.
Locator `powershell_history:<rel>:<lineno>`.

**`browser` — history & downloads** (NirSoft *BrowsingHistoryView* / *BrowserDownloadsView* CSV).
`csv.DictReader` with `utf-8-sig` (strips the BOM). `_classify()` decides *history* vs *download*
from the header set, then pulls URL / title / visit-time / filename / saved-path / start-time via
the tolerant `_get`. Capped at 5000 rows/file. Locator `browser:<rel>:<rownum>`.

**`usn` — USN change journal** (`USNJrnl.csv`, an ExtractUSNJrnl export). The journal is huge and
mostly data-write churn, so this is a **curated lifecycle parse**: only CREATE / DELETE / RENAME
records for *interesting extensions* (executables, scripts, archives, docs, creds/dumps), deduped
per file, noise-filtered (`__PSScriptPolicyTest`, `mpcache-`, Office `~$` locks, Search-indexer
churn), capped at 6000. USN stores the file *name* but not its directory (resolving a full path
needs the `$MFT` → `mft_lookup`). Locator `usn:<rel>:<usn-number>`.

**`evtx` — Windows event logs** (`*.evtx`, binary). Backend: Rust-backed `evtx` (falls back to
pure-Python `python-evtx`, which is far slower and can silently truncate — a startup guard warns).
Two-stage curation: (a) a **channel allowlist** — `_CHANNELS` matches a filename substring to a
family + an interesting-ID set, first-match-wins (so `…%4Security.evtx` resolves as SMB before the
generic `security.evtx`); `ids=None` keeps every ID for low-volume channels. (b) within a kept
channel, only **whitelisted EventIDs** (`_SEC`/`_SYS`/`_PS`/…) survive. Per record: iterate
`(record_id, timestamp, xml)` → parse XML with ElementTree → lift `System` fields (EventID,
Computer, TimeCreated, the SID) and `EventData`/`UserData` fields. Named `<Data Name=…>` keep their
names; **unnamed** `<Data>` (classic providers like Application Error, MsiInstaller, SCM) are
captured positionally as `Data1`, `Data2`, …. The summary leads with `_KEY_FIELDS` (the most
triage-useful fields) then the rest. A per-channel heartbeat updates in place during long scans.
Locator `event_logs:<rel>:<record_id>`.

**`registry` — hives** (`SOFTWARE`/`SYSTEM`/`SAM`/`NTUSER.DAT`/`Amcache.hve`, binary; backend
python-registry). `_hive_type()` routes each hive by filename (SECURITY/UsrClass are skipped). Like
EVTX, it's an **allowlist of high-value keys**, not a full dump: Run/RunOnce persistence, Uninstall
→ installed software, `CurrentVersion` → OS build/owner/install-date, `NetworkList` → network
profiles, services (surfaced only when the `ImagePath` trips a suspicious-location heuristic and
isn't under a standard system prefix), plus account/device/user-activity keys. `raw` holds *every*
value under the emitted subkey. **`Amcache.hve`** is parsed in the same module but emitted under a
distinct `source="amcache"` (program-execution evidence with SHA-1 hashes). Locator
`registry:<rel>:<keypath>\<value-or-subkey>` (amcache rows use an `amcache:` prefix).

**`lnk` — shortcuts** (`*.lnk`, especially under `Recent/`; backend LnkParse3). One event per
shortcut, lifting the target's **full path, MAC timestamps, size, and volume type** (local /
network / removable) — i.e. evidence that a user opened a specific file/share. `raw` is the full
parsed record. Locator `lnk:<rel>`.

**`srum` — System Resource Usage Monitor** (`SRUDB.dat`, an ESE database; backend dissect.esedb).
Parses two high-value tables by GUID: *Application Resource Usage* — **aggregated per app** (the raw
table is thousands of ~hourly rows, so a per-app rollup of active-window time + disk I/O is the
triage signal) — and *Network Connectivity* (one event per record). App/user IDs are resolved
through `SruDbIdMapTable`; the OLE-automation `TimeStamp` is decoded to ISO. Locator
`srum:<rel>:app:<i>` / `srum:<rel>:net:<id>`.

**On-demand (not bulk-parsed): `$MFT` and the memory image.** Both are too large to materialize up
front. `mft_lookup` resolves a filename/USN reference to its full path/MAC times against `$MFT`, and
`vol_run` runs a Volatility3 plugin against the memory image — each materializing only the rows it
returns into `events`. See §6, on-demand tools.

---

## 5. Layer B — the agent topology

Three roles, all coordinating through the Case File:

```
                         ┌───────────────────────────────────────────┐
                         │  ORCHESTRATOR  (src/agents/orchestrator.py)│
                         │  the lead-queue engine                     │
                         └───────────────────────────────────────────┘
   (optional) RANK            │  pop highest-priority lead
   ROUTER  ──────────────────▶│  set in_progress
   src/agents/router.py       │  spawn a sub-agent for THIS lead
                              ▼
                         ┌───────────────────────────────────────────┐
       files a new lead  │  SUB-AGENT  (src/agents/subagent.py)       │
      ◀──────────────────┤  one lead → conclusion, in its OWN context │
                         │  reads data + writes findings/answers       │
                         └───────────────────────────────────────────┘
                              │  via TOOLS (src/tools/registry.py)
                              ▼
                         ┌───────────────────────────────────────────┐
                         │  CASE FILE (case.db)  — the shared bus      │
                         └───────────────────────────────────────────┘
```

### 5a. Orchestrator — `src/agents/orchestrator.py`

A small, deterministic **queue engine** (it does *not* call the LLM itself):

1. `reset_in_progress_leads()` — re-open anything left mid-flight by a prior crash (resume).
2. `seed()` — enqueue leads:
   - one **question lead** per CTF question (`priority 70`),
   - one **coverage lead** per present bucket (priority from a curated per-bucket table, or a
     question-ranked override from the router; see 5c).
3. Loop: `next_lead()` (highest `priority`, then `id`) → mark `in_progress` → `subagent.run(...)`
   → mark `closed` → if it was a coverage lead, mark the bucket `analyzed`. Repeat until the
   queue drains or a safety cap (`max_total_leads + 50`) trips.

The orchestrator and sub-agents never call each other directly. A sub-agent that wants more
work calls the `file_lead` tool, which inserts an `agent`-sourced row into `leads`; the
orchestrator picks it up on a later iteration. **Coordination is the queue.**

### 5b. Sub-agent — `src/agents/subagent.py`

One **generic** sub-agent, run once per lead in a **fresh LLM context**. It "eats" the raw
tool output locally so the orchestrator never has to hold it — this keeps each context small.

- **Specialization is by playbook, not code.** For a coverage lead the sub-agent is told to
  `kb_read('playbooks/<bucket>.md')` first (the `_PLAYBOOKS` dir-code→doc map). The same code
  investigates PowerShell, registry, or memory — the playbook supplies the domain knowledge.
- **The loop** (up to `budgets.max_subagent_steps`, default 25):
  ```
  history = [task]
  for step in 1..max:
      resp = llm.complete("subagent", system, history, tools=TOOL_SCHEMAS)
      history.append(resp.assistant_turn)
      if resp.stop_reason != "tool_use": break
      for call in resp.tool_calls:
          out, is_err = dispatch(ctx, call.name, call.input)   # run the tool
          history.append(tool_result)
  _conclude_unresolved(...)   # safety net
  ```
- **System prompt** (`_RULES` + the case's question list): answer-or-point-never-guess; cite a
  real locator for every claim; exact verbatim tokens; call `find_flags` early; read the
  playbook; `list_findings` before recording (dedup); act then stop.
- **Cross-agent awareness:** a sub-agent sees prior sub-agents' work by calling `list_findings`
  (reading the ledger) — again, via the blackboard, not direct messaging.
- **Never-blank discipline:** `_conclude_unresolved()` ensures a *question* lead that ends with
  no recorded answer writes an honest `unresolved` (with what it searched) instead of silently
  producing nothing — so a gap is distinguishable from a crash.
- **Resilience:** an LLM/API exception aborts only the current lead (logged), not the run.

### 5c. Router — `src/agents/router.py` (optional)

A single LLM call (role `orchestrator`) that ranks the present buckets by relevance to the
questions. It returns a JSON array of dir-codes that drives:
- **lead priority** (which buckets a default run examines first — coverage is still
  guaranteed), and
- **bucket selection** under `--relevant-only` (only ranked buckets are examined).

With no questions and no `--relevant-only`, the router is skipped and the static per-bucket
priority in the orchestrator applies.

---

## 6. The tool layer (`src/tools/registry.py`)

Tools are the *only* way a sub-agent touches data. `TOOL_SCHEMAS` is sent to the model;
`dispatch(ctx, name, input)` runs the handler and returns `(text, is_error)`. Result payloads
are JSON capped at 12 KB. Every **read** tool calls `case.emit_locator()` on what it returns
(so it becomes citable); every **write** tool validates citations. A handler exception is
caught and surfaced to the model as a tool-error string — it never crashes the run.

| Category | Tools |
|----------|-------|
| **Read / search** | `kb_read`, `query_timeline`, `grep_artifact`, `find_flags`, `list_files`, `read_file`, `get_raw_event` |
| **On-demand (lazy, expensive)** | `mft_lookup`, `vol_run` |
| **Write / control** | `list_findings`, `record_finding`, `answer_question`, `file_lead`, `mark_examined` |

### Read / search

**`kb_read(doc)`** → playbook/reference text (≤12 KB). `doc` is relative to `knowledge_base/`,
e.g. `"playbooks/registry.md"`. Path-escape guarded. No locators.

**`query_timeline(source?, user?, contains?, limit=100)`** → `{count, rows:[{locator, user, ts,
text}], truncated?, total_matched?}`. SQL filter over `events` (`source_artifact=`, `user LIKE`,
`summary LIKE %contains%`), `ORDER BY id`, **cap 500**. No offset — narrow with filters. Emits a
locator per row. The primary "pull only what matters" tool.

**`grep_artifact(pattern, source?, limit=100)`** → `{count, rows:[{locator, user, text}],
truncated?, total_matched?}`. Case-insensitive **regex** over `events.summary` (optionally one
source). Counts all matches for `total_matched`; **cap 500**. Emits per row.

**`find_flags()`** → `{count, flags:[{flag, locator}]}`. Deterministic scan of all `events`
(summary+raw) **and** readable text files for CTF markers `btv{…}/flag{…}/FL4G={…}/key{…}/ctf{…}`
(`_FLAG_RX`); dedup by value, cap 100. Emits the first locator per flag. No LLM. Call early.

**`list_files(query?, artifact?, limit=50)`** → `{count, files:[{locator:"file:<path>", path,
owner, size, mtime, ctime, readable}], truncated?, total_matched?}`. Searches the `files`
catalog (`path LIKE`, `artifact=`), **cap 200**. Emits `file:` locators — how you find candidate
files to POINT at.

**`read_file(path, offset=0, limit=200)`** → `{path, total_lines, rows:[{locator:"file:<path>:
<line>", line, text}]}`. Slices a **text** file (BOM-aware decode). **Cap 500** lines. Refuses
binaries; for a file in a *parsed* bucket (Evt/Reg/Brw/Lnk/RawData/Sys) it returns a redirect to
`query_timeline`/`get_raw_event` instead of suggesting POINT. Emits `file_line` locators.

**`get_raw_event(locator)`** → `{locator, fields}` (full JSON field set from `events.raw`) or
`{locator, summary}` if no extra fields. Use when a summary ends `[+N more fields …]`. The
locator lookup is **backslash-tolerant** (`_resolve_locator` collapses over-escaped registry
`\\`) so a real citation isn't rejected on a formatting quirk. Emits the (canonical) locator.

### On-demand (lazy, expensive — materialize into `events`)

These query the artifacts too big to bulk-parse and write their results into the *same*
`events` table with citable locators, so the rest of the pipeline treats them like any other
row. So **"the memory agent" is not a separate process** — it's the generic sub-agent, pointed
at `playbooks/memory.md`, calling `vol_run`.

**`mft_lookup(filename, limit=20)`** → `{query, count, results:[{locator:"mft:…", path, deleted,
size, si_times, fn_times}]}`. Resolves a name (substring, case-insensitive) against the `$MFT` —
full path + `$SI/$FN` MAC times (timestomp check). First call builds an in-process index (~secs);
**cap 100**. Materializes `source="mft"` rows and emits their locators.

**`vol_run(plugin, contains?, pid?)`** → Volatility3 results as citable `source="memory"` rows.
Runs **one** plugin (e.g. `windows.netscan.NetScan`, `windows.pslist`, `windows.cmdline`,
`windows.malfind`) against the `MemDump` image; `contains` filters rows, `pid` restricts to a
process. Reads `budgets["memory"]` (vol_cmd, cache_dir); disk-caches per (image, plugin, args) in
`output/_memcache`. Volatility runs in its own venv (`.venv-vol`); the tool shells out to it.
SLOW (tens of seconds–minutes). If memory is disabled/absent it says so → POINT at the image. No
hashdump/lsadump plugin in this build.

### Write / control (validated)

**`list_findings()`** → `{count, findings:[{id, severity, technique, title}]}`. Read the ledger
before recording, to add to an existing finding instead of duplicating.

**`record_finding(title, severity, evidence[], confidence?, attack_technique?, description?)`** →
`{recorded_finding: id}` or `{merged_into_finding: id}`. `evidence` is `[{locator, excerpt?}]`,
**non-empty**, and **every locator must be in `emitted_locators`** or the call is rejected. If a
finding with the **same `attack_technique` and a shared locator** exists, the new evidence is
**merged** in (no duplicate).

**`answer_question(question_id, status, …)`** resolves a question; `status` ∈:
- `answered` → requires `answer` + non-empty validated `evidence` (same emitted-locator check).
- `pointer` → requires `candidate_files:[{path, reason?}]`; **each path must exist in `files`**.
- `unresolved` → requires `reasoning` (what was searched).
Optional `confidence`. Duplicate answers (same value) are skipped; **distinct** candidate
answers are kept side-by-side for the analyst.

**`file_lead(title, reason?)`** → enqueues a new `source="agent"` lead for the orchestrator (don't
chase it yourself). Honors `allow_expansion`, `max_total_leads`, `max_lead_depth`, and `dedup_key`
(returns "duplicate" if already queued).

**`mark_examined(artifact)`** → sets that bucket's `coverage.status="analyzed"`. The run finishes
only when no present bucket is still `unexamined`.

### The citation-enforcement mechanism (the anti-hallucination core)

```
read tool returns rows ──▶ each locator is recorded via case.emit_locator()
                                       │
                                       ▼  (emitted_locators table)
record_finding / answer_question ──▶ _check_evidence(): reject any cited
                                       locator NOT in emitted_locators
                                       │
                                       ▼  (stored finding/answer evidence)
layer C verifier ──────────────────▶ re-resolve every cited locator against
                                       events/files; flag any that don't exist
```

So a sub-agent cannot fabricate evidence: it can only cite something a tool literally returned
to it this run, and the report independently re-checks it.

### Cross-cutting tool rules

- **Truncation is explicit:** capped read tools return `truncated`/`total_matched` so a slice is
  never mistaken for the whole set.
- **Errors don't crash the run:** any handler exception becomes a tool-error string the model
  sees and adapts to.

---

## 7. The LLM layer (`src/llm/`)

- **`LLMClient.complete(role, system, messages, tools)`** routes a **role** to a configured
  provider+model (`config/config.yaml :: models`). Roles: `subagent` (the investigation loop)
  and `orchestrator` (the router ranking) actually call the LLM; `report`/`verifier` are
  configured but their work is deterministic. Backends are imported lazily, so you only need
  the SDK for the provider you use.
- **Providers:** Anthropic (default, most-tested), OpenAI, Gemini — `src/llm/backends/`.
- **Anthropic backend** (`anthropic_backend.py`): streaming, **adaptive thinking** +
  per-role **effort**, and **prompt caching** with three breakpoints — the tool schemas, the
  system prompt, and a rolling breakpoint on the last message block — so the (large, repeated)
  prefix of a 25-step tool loop is read from cache instead of re-billed each round.
- Assistant turns are stored as raw provider content so thinking-block signatures survive the
  tool loop.

---

## 8. Layer C — report + verification (`src/report/`)

Deterministic, no LLM. `generator.py` renders Markdown from **only** the ledger/answers/
coverage (never the chat history), and `verifier.py :: resolves()` re-checks every cited
locator against `events`/`files`, marking any failure `⚠️UNVERIFIED`. `report_html.py`
(in `scripts/`, reused by `main.py`) builds the self-contained interactive dashboard from the
same `case.db`.

---

## 9. Above one host: process-level orchestration

The agent topology above is **per host** (one `case.db` per host). Multi-host work is plain
process parallelism, not a higher-order agent:

- **`run_hosts.py`** — runs `main.py investigate` for N hosts as separate processes
  (`ThreadPoolExecutor`, bounded by `--jobs`), streaming each host's tagged output to the
  console. Each child `main.py` writes its own **timestamped** `output/<host>/run.log` (the log
  is owned by the investigate process, so single-host runs get one too). Then it auto-generates
  the combined views.
- **`scripts/aggregate.py`** — reads every host's `case.db` and writes a combined answer sheet
  (routing table + best answer per question).
- **`scripts/report_html.py`** — the interactive cross-host (or single-host) dashboard.

There is currently **no cross-host *investigating* agent** — hosts are investigated
independently and the results are combined after the fact (the union/aggregate step). A single
agent reasoning across hosts jointly is the open roadmap item.

---

## 10. Invariants & guarantees (what keeps it honest and terminating)

- **No uncited assertion** — structural (emit→check→verify), §6.
- **Termination** — coverage leads force every bucket to `analyzed`; `dedup_key` blocks
  re-filing identical leads; `depth`/`max_lead_depth` caps agent-filed lead chains;
  `max_subagent_steps` caps each lead; a global safety cap bounds total leads.
- **Never-blank** — a question lead always ends with answered/pointer/unresolved.
- **Resumable & idempotent** — durable SQLite state; `meta.ingested` skips re-parse;
  `reset_in_progress_leads` retries interrupted work; questions are content-hashed (`_qid`) so
  unchanged ones keep their answers, and an answer snapshots its `question_text` so it survives
  a later question-set change.
- **Graceful degradation** — a missing parser, an absent bucket, or a disabled memory env all
  degrade to POINTER/coverage-only rather than erroring.

---

## 11. End-to-end trace (one host, with questions)

```
main.py cmd_investigate
 ├─ ingest()                         # layer A: parse → events/files/coverage
 ├─ router.rank_buckets()            # (if questions) LLM ranks buckets
 ├─ orchestrator.run()               # layer B
 │   ├─ seed leads (questions + coverage)
 │   └─ while queue not empty:
 │        lead = next_lead()         # by priority
 │        subagent.run(lead)         # fresh context
 │          ├─ kb_read playbook
 │          ├─ query_timeline / grep_artifact / get_raw_event / read_file / mft_lookup / vol_run
 │          │    └─ each read → emit_locator()        # citation registry
 │          ├─ list_findings (dedup)
 │          ├─ record_finding / answer_question        # rejected if uncited
 │          ├─ file_lead (→ back onto the queue)
 │          └─ mark_examined (coverage lead)
 ├─ write_report() + verify           # layer C: Markdown + citation check
 └─ report_html.py                    # interactive dashboard
```

---

## 12. Where to look in the code

| Concern | File |
|---------|------|
| Phase orchestration / CLI | `main.py` |
| Parse + catalog | `src/extraction/ingest.py`, `src/extraction/*.py`, `src/textutil.py` |
| Case File (schema + accessors) | `src/store/schema.sql`, `src/store/case_db.py` |
| Lead-queue engine | `src/agents/orchestrator.py` |
| Generic sub-agent | `src/agents/subagent.py` |
| Bucket ranking | `src/agents/router.py` |
| Tools + dispatch + citation enforcement | `src/tools/registry.py` |
| LLM routing / caching / providers | `src/llm/client.py`, `src/llm/backends/*` |
| Report + verification | `src/report/generator.py`, `src/report/verifier.py` |
| Agent domain knowledge | `knowledge_base/playbooks/*.md`, `knowledge_base/tool_cookbook.md` |
| Multi-host | `run_hosts.py`, `scripts/aggregate.py`, `scripts/report_html.py` |
