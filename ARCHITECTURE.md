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
This is the single most important structural fact about the system.

Schema (`src/store/schema.sql`, wrapped by `src/store/case_db.py :: CaseDB`):

| Table | Role |
|-------|------|
| `events` | The normalized timeline. One row per parsed record; columns `ts, source_artifact, user, summary, locator, raw`. **`locator` is the stable citation handle.** |
| `files` | Metadata for **every** file (incl. binaries the tool can't read) — powers POINTER answers. |
| `coverage` | One row per artifact bucket: `present`, `parser`, `status` (`unexamined → analyzed`). The run isn't done until no bucket is `unexamined`. |
| `leads` | **The work queue / engine.** `source` ∈ {question, coverage, agent}, `priority`, `depth`, `status` (open→in_progress→closed), `dedup_key UNIQUE`. |
| `findings` / `finding_evidence` | The findings ledger and its citations. |
| `questions` / `answers` / `answer_evidence` / `answer_candidates` | CTF questions and their resolutions (answered/pointer/unresolved). |
| `emitted_locators` | **Every locator any tool has returned.** The citation-enforcement table. |
| `meta` | Key/value (e.g. `ingested=1`) for idempotent ingest + resume. |

Because all state is durable in SQLite, the run is **resumable** (re-run with the same
`--case-id`) and **idempotent** (parsing is skipped if `meta.ingested=1`).

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
   `case.add_event(...)`, each with a **stable `locator`** of the form
   `"<source>:<relpath>:<record-id|line|keypath>"`.

Two artifacts are deliberately **not** bulk-parsed (too large): the full `$MFT` and the memory
image. They're queried lazily during layer B (see §7, on-demand tools).

Parsers read fields **by name** (DictReader / EVTX `EventData Name=` / ESE columns), so new
columns or fields in a newer collector are ignored, not fatal.

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
`dispatch(ctx, name, input)` runs the handler and returns `(text, is_error)`. A handler
exception is caught and surfaced to the model as a tool error (never crashes the run).

| Category | Tools |
|----------|-------|
| **Read / search** | `kb_read` (playbooks), `query_timeline` (filtered timeline), `grep_artifact` (regex over event text), `find_flags` (deterministic CTF-marker scan), `list_files` (file catalog), `read_file` (text slice; refuses binaries, and **redirects** to `query_timeline` for parsed buckets), `get_raw_event` (full field set for a row) |
| **On-demand (lazy, expensive)** | `mft_lookup` (resolve a name→path + `$SI/$FN` times from `$MFT`), `vol_run` (one Volatility3 plugin against the memory image) |
| **Write / control** | `record_finding`, `answer_question` (answered/pointer/unresolved), `file_lead` (enqueue new work), `list_findings`, `mark_examined` |

Result sets carry a **truncation signal** (`truncated`, `total_matched`) so the model never
mistakes a capped page for the whole set.

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
to it this run, and the report independently re-checks it. `_resolve_locator()` tolerantly
canonicalizes over-escaped registry backslashes (`\\` ↔ `\`) so a real citation isn't rejected
on a formatting quirk.

### On-demand vs bulk-parsed

`mft_lookup` and `vol_run` materialize their results into the *same* `events` table
(`source="mft"` / `source="memory"`) with citable locators, and cache to disk
(`vol_run` → `output/_memcache`). So "the memory agent" is **not** a separate process — it's
the generic sub-agent, pointed at `playbooks/memory.md`, calling the `vol_run` tool. Volatility
runs in its own venv (`.venv-vol`); the tool just shells out to it.

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
  (`ThreadPoolExecutor`, bounded by `--jobs`), tees each host's streamed output to
  `output/<host>/run.log`, then auto-generates the combined views.
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
