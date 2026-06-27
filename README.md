# forensic-investigator

A tool that **investigates a compromised Windows machine for you and writes a report**.

You point it at a folder of evidence collected from a Windows host (the kind a responder
grabs during an incident — event logs, registry hives, PowerShell history, etc.). It
parses that evidence, then an AI agent investigates it — reading the data, following
leads, and answering questions — and produces a Markdown report where **every statement
is backed by a citation to the exact source record**. If it can't find an answer, it
says so, or points you at the files to check by hand. It never makes things up.

It's useful for incident response triage and for forensics **CTF** challenges (where you
have a list of questions to answer about an evidence image).

---

## Quick start

New here? The whole happy path in four steps (each is explained in detail below):

```bash
# 1. One-time setup — creates the Python env and a .env file for your API key
python install.py
#    ...then open the .env it created and paste in:  ANTHROPIC_API_KEY=sk-ant-...

# 2. Activate the env (do this in every new terminal)
.venv\Scripts\Activate.ps1            # Windows PowerShell
#    macOS / Linux:  source .venv/bin/activate

# 3. Run a cheap first investigation (--only Psh = just PowerShell history)
python main.py investigate "PATH/TO/ACQ-IR-<host>" --case-id test --only Psh

# 4. Read the result
#    output/test/report.md   (open in any editor)
#    output/test/report.html (open in a browser: searchable, sortable)
```

That third command is deliberately cheap. When you're ready: drop `--only Psh` for a **full**
investigation, add `--questions questions.txt` to answer **specific questions**, or jump to
**[CTF_PLAYBOOK.md](CTF_PLAYBOOK.md)** for a whole multi-host CTF. Keep reading for the details.

---

## Table of contents

1. [What you need](#1-what-you-need)
2. [Install (step by step)](#2-install-step-by-step)
3. [Run your first investigation](#3-run-your-first-investigation)
4. [Asking specific questions](#4-asking-specific-questions)
5. [Understanding the output](#5-understanding-the-output)
6. [Querying the database yourself](#6-querying-the-database-yourself)
7. [Run modes (controlling cost & scope)](#7-run-modes-controlling-cost--scope)
8. [Resuming a run](#8-resuming-a-run)
9. [Choosing a different AI provider](#9-choosing-a-different-ai-provider)
10. [Memory-image analysis (optional)](#10-memory-image-analysis-optional)
11. [Configuration files](#11-configuration-files)
12. [How it works (under the hood)](#12-how-it-works-under-the-hood)
13. [Status & roadmap](#13-status--roadmap)

---

## 1. What you need

- **Python 3.10 or newer** installed. Check with `python --version`.
- **An AI API key.** By default the tool uses Anthropic (Claude). You need an
  `ANTHROPIC_API_KEY` (or an OpenAI / Gemini key — see [section 9](#9-choosing-a-different-ai-provider)).
  Running an investigation makes paid API calls, so a key with some credit is required.
- **A folder of Windows evidence** to investigate. This tool is built for
  **AChoirX-style triage collections**: a folder with subfolders named by short
  codes like `Evt` (event logs), `Reg` (registry), `Psh` (PowerShell history), etc. A
  typical folder is named like `ACQ-IR-<hostname>-<date>`. The folder is only ever **read**
  — the tool never modifies your evidence.

> Don't have a collection handy? This tool was built against the DC33 "OBSIDIAN" CTF
> dataset, but it works on any folder using the same dir-code layout (see
> `config/artifact_map.yaml` for the full list of recognized codes).

---

## 2. Install (step by step)

### Quick setup (one command)

From the project folder, run the bootstrapper — it creates the virtualenv, installs
dependencies, and seeds your `.env`:

```bash
python install.py              # full setup: core tool + Volatility memory analysis (section 10)
python install.py --no-memory  # core tool only (skip Volatility)
```

Then add your API key to the `.env` it created and you're ready ([section 3](#3-run-your-first-investigation)).
It's cross-platform, stdlib-only, and safe to re-run. Prefer to do it by hand? The manual
steps are below.

### Manual setup

Open a terminal **in the project folder** (the one containing `main.py`) and run:

```bash
# 1. Create an isolated Python environment (recommended, keeps things tidy)
python -m venv .venv

# 2. Activate it
#    Windows (PowerShell):
.venv\Scripts\Activate.ps1
#    macOS / Linux:
source .venv/bin/activate

# 3. Install the tool and its dependencies
pip install -r requirements.txt
```

### Add your API key

Create a file named `.env` in the project folder (copy the template):

```bash
cp .env.example .env
```

Open `.env` in a text editor and fill in your key:

```
ANTHROPIC_API_KEY=sk-ant-...your key here...
```

That's it — the tool loads `.env` automatically. (The `.env` file is git-ignored, so your
key won't be committed.) If you prefer, you can instead set the variable in your shell:
`export ANTHROPIC_API_KEY=...` (PowerShell: `$env:ANTHROPIC_API_KEY="..."`).

---

## 3. Run your first investigation

The basic command is:

```bash
python main.py investigate "PATH/TO/EVIDENCE/FOLDER" --case-id myfirstcase
```

- Replace `PATH/TO/EVIDENCE/FOLDER` with the path to your evidence folder (the one with
  `Evt`, `Reg`, `Psh`, … inside it). **Keep the quotes** — paths often contain spaces.
- `--case-id` is just a label you choose for this investigation. Results are saved under
  `output/myfirstcase/`.

Example (Windows path):

```bash
python main.py investigate "C:/Users/me/Downloads/ACQ-IR-namtws001-20250702-0113" --case-id ws001
```

You'll see progress printed as it works:

```
🔍 Ingesting namtws001-20250702-0113 ...
    📂 parsing Evt (event_logs) ...
    ✅ [evtx] parsed 20 high-value channels, emitted 24630 events (backend: evtx)
    📊 cataloged 686 files, 26657 timeline events
🧠 Investigating (run to completion) ...
  🔎 lead #1 [coverage] Explore the Psh (powershell_history) artifacts
       step 1: kb_read(...)
       ...
📝 Writing report ...
✅ Done. Report: .../output/ws001/report.md
```

When it finishes, open **`output/ws001/report.md`** — that's your investigation report.

> ⚠️ A full run examines **every** evidence category and can make many AI calls. To keep
> your first run cheap, see [Run modes](#7-run-modes-controlling-cost--scope) — e.g. add
> `--only Psh` to investigate just one category.

> **Output notes:** in a terminal the output is colorized and parsing shows a live
> progress line that updates in place; when redirected to a file it's plain text (no color
> codes). Long runs automatically keep the machine from **idle-sleeping** (Windows — but
> keep a laptop **lid open**, which the power plan controls separately). Set `NO_COLOR=1`
> or `NO_EMOJI=1` for plain output.

---

## 4. Asking specific questions

For CTF-style work, give the tool the exact questions you need answered. Put **one
question per line** in a plain text file, e.g. `questions.txt`:

```
What remote-access tool did the attacker install, and how?
What is the IP address of the command-and-control server?
Which user account did the attacker add to the Administrators group?
```

Then point the tool at it:

```bash
python main.py investigate "PATH/TO/EVIDENCE" --case-id ws001 --questions questions.txt
```

For a quick one-off you don't need a file — pass the question inline with **`--question`**
(repeatable, and combinable with `--questions`):

```bash
python main.py investigate "PATH/TO/EVIDENCE" --case-id ws001 --question "What is the C2 IP?"
python main.py investigate "PATH/TO/EVIDENCE" --case-id ws001 \
    --question "What is the C2 IP?" --question "Which RAT was installed?"
```

> **`--question` adds to the case's question set; `--questions FILE` replaces it.** So asking
> another inline question on the same `--case-id` later *keeps* the earlier ones (they
> accumulate) — whereas re-running with a `--questions` file makes that file the new set (a
> line you removed is dropped). Use a file when you want the file to be the source of truth.

The report will contain an **answer sheet** addressing each question. When questions are
provided, the AI also automatically figures out which evidence categories are most
relevant to them and examines those first.

> **CTF helpers (automatic):** the agent scans every artifact for planted flag markers —
> `btv{...}`, `flag{...}`, `FL4G={...}` — and surfaces them as answers, and it returns
> filenames/commands/paths **verbatim** (e.g. `AdFind.exe`, not `AdFind`) so they match an
> exact-match grader. No flags to set.

For a full **live-CTF runbook** — multi-host parsing, routing questions to hosts, the prep
checklist, and troubleshooting — see **[CTF_PLAYBOOK.md](CTF_PLAYBOOK.md)**.

---

## 5. Understanding the output

Each run produces a folder `output/<case-id>/` containing:

| File | What it is |
|------|------------|
| `report.md` | The human-readable report (open this). |
| `report.html` | A self-contained, offline **interactive** version of the report — open in a browser to search, filter, and sort the answers/findings/coverage (click a row for cited evidence). Same dashboard the multi-host `report.html` uses, scoped to this host. |
| `case.db` | A SQLite database with all the parsed evidence and findings (query it — see [section 6](#6-querying-the-database-yourself)). |

Generated automatically each run. To **rebuild `report.html`** anytime from the existing
`case.db` (it reads the database, not the markdown): `python scripts/report_html.py output/<case-id>`
(add `--open` to open it). Omit the path to rebuild the cross-host combined dashboard instead.

The **report** has these sections:

- **Answer sheet** (if you gave questions) — each question resolved as one of:
  - **ANSWERED** — a direct answer, with a citation to the exact source record. If more
    than one well-supported answer turns up, all are shown as candidates for you to choose.
  - **POINTER** — the tool can't read the answer itself (e.g. it's inside an image or a
    binary it doesn't parse), so it points you at the file(s) to inspect by hand. *It does
    not guess.*
  - **UNRESOLVED** — it searched but found nothing; it records **what it looked at** (even
    if a lead used up its step budget, so a gap is never left silently blank).
- **Findings** — notable things it discovered (with severity, an ATT&CK technique where
  relevant, and citations).
- **Coverage & gaps** — a table of every evidence category, whether it was parsed, and
  whether it was examined. This tells you what was and wasn't looked at.

**Citations** look like `` `event_logs:Evt/.../Security.evtx:269584` `` — that's a stable
pointer back to the exact record. Every claim has one; anything the tool couldn't verify
is flagged. (See the next section to look the citation up yourself.)

---

## 6. Querying the database yourself

Everything the tool parsed and concluded lives in `output/<case-id>/case.db`, a standard
**SQLite** database. You can explore it directly — useful for digging deeper than the
report, or verifying a citation.

### Easiest: the bundled `query.py` helper

The repo ships **`scripts/query.py`** — it takes the database path as an argument (so it
works on any host's `case.db`) and opens it **read-only** (a stray write can't touch your
evidence). With no SQL it lists the tables and row counts:

```bash
python scripts/query.py output/ws001/case.db                                  # list tables
python scripts/query.py output/ws001/case.db "SELECT severity, title FROM findings"
python scripts/query.py output/ws001/case.db "SELECT * FROM answers" --limit 5
```

Or, with no file at all, a Python one-liner (SQLite is built into Python):

```bash
python -c "import sqlite3; c=sqlite3.connect('output/ws001/case.db'); [print(r) for r in c.execute('SELECT severity, title FROM findings')]"
```

### The `scripts/` helper tools

The repo ships a handful of small, **read-only** helpers (no AI, no cost). One reference:

| Script | What it does |
|--------|--------------|
| `python scripts/query.py <case.db> ["SQL"]` | Run SQL against one case (read-only). No SQL → lists tables + row counts. |
| `python scripts/search.py <term> [more…]` | Rank hosts that mention term(s) — find which host a question is about. Multiple terms = **AND** by default; `--any` = OR. |
| `python scripts/whoanswered.py` | List which host answered which question. |
| `python scripts/aggregate.py` | Build the cross-host **combined answer sheet** (`output/_combined/answer_sheet.md`). |
| `python scripts/report_html.py [output/<case-id>]` | (Re)build the **interactive HTML dashboard** — one host, or all hosts combined with no argument. `--open` opens it. |

The multi-host ones (`search`, `whoanswered`, `aggregate`, `report_html`) are used in
[CTF_PLAYBOOK.md](CTF_PLAYBOOK.md) §4 to route questions to hosts and read results.

### Or use the sqlite3 command-line tool

If you have the `sqlite3` CLI installed:

```bash
sqlite3 output/ws001/case.db
```

Then at the `sqlite>` prompt, turn on readable output and run queries:

```sql
.mode box
.headers on
SELECT severity, title FROM findings;
```

### Or use a free GUI

[DB Browser for SQLite](https://sqlitebrowser.org/) lets you open `case.db` and
browse/query tables by clicking around — nice if you're not comfortable with SQL.

### The tables you'll care about

| Table | What's in it |
|-------|--------------|
| `events` | The normalized timeline — one row per parsed record (PowerShell command, event-log entry, registry value…). Columns: `ts`, `source_artifact`, `user`, `event_type`, `summary`, `locator`. |
| `findings` | What the AI concluded. Columns: `severity`, `confidence`, `attack_technique`, `title`, `description`. |
| `finding_evidence` | Citations for each finding (`finding_id`, `locator`, `excerpt`). |
| `answers` | Resolutions to your questions (`question_id`, `status`, `answer`, `confidence`). |
| `answer_evidence` / `answer_candidates` | Citations / pointed-at files for each answer. |
| `questions` | The questions you supplied (`id`, `text`). |
| `coverage` | Each evidence category and whether it was examined (`artifact`, `parser`, `status`). |
| `files` | Metadata for **every** file in the collection (even ones not parsed) — `path`, `owner`, `size`, timestamps. This is how the tool can point at files it can't read. |
| `leads` | The investigation queue (what was investigated and in what order). |

> The `events.source_artifact` column says which parser produced a row. Values:
> `powershell_history`, `event_logs`, `registry`, `amcache`, `browser`, `lnk`, `usn`,
> `srum`, plus the on-demand `mft` (from `mft_lookup`) and `memory` (from Volatility).

### Useful example queries

```sql
-- All findings, most severe first
SELECT severity, attack_technique, title FROM findings;

-- Show the evidence (citations) behind finding #4
SELECT locator, excerpt FROM finding_evidence WHERE finding_id = 4;

-- Search the whole timeline for an IP / keyword
SELECT source_artifact, user, summary, locator
FROM events WHERE summary LIKE '%13.58.222.12%';

-- How many timeline events came from each source?
SELECT source_artifact, COUNT(*) FROM events GROUP BY source_artifact;

-- See every PowerShell command in the timeline
SELECT user, summary FROM events WHERE source_artifact = 'powershell_history';

-- The answers to your questions, with confidence
SELECT q.text, a.status, a.answer, a.confidence
FROM answers a JOIN questions q ON q.id = a.question_id;

-- Which evidence categories were examined vs skipped?
SELECT artifact, parser, status FROM coverage WHERE present = 1;

-- Look up what a citation in the report points to
SELECT summary FROM events WHERE locator = 'event_logs:Evt/Sys32/Windows/System32/winevt/Logs/Security.evtx:269584';

-- Find candidate files by name (e.g. images that might hold an answer)
SELECT path, owner, size, mtime FROM files WHERE path LIKE '%.png';
```

---

## 7. Run modes (controlling cost & scope)

A full run examines every evidence category and can be slow/expensive. These flags
control how much work it does:

| Command | What it does | When to use |
|---------|--------------|-------------|
| *(no flags)* | Examines **every** category. With questions, an AI ranks categories by relevance and examines the most relevant first. | Thorough investigation; you want nothing missed. |
| `--only Psh,Evt` | Examines **only** the listed categories. Doesn't chase leads into others. | Cheapest / fastest. Great for a first try or a focused look. |
| `--only Psh,Evt --expand` | Same, but lets the AI follow leads into other categories when needed. | Focused, but allows cross-evidence correlation. |
| `--relevant-only` | An AI picks which categories are relevant to your questions and examines only those. | Focused questions. (Note: for *broad* questions it may still pick almost everything — use `--only` to truly limit.) |
| `--ingest-only` | **Parses** the evidence into `case.db` and stops — no AI, no cost. | Pre-build a parsed base once, then reuse it for many cheap runs without re-parsing the (slow) artifacts each time. |
| `--reingest` | Forces a fresh re-parse even if this case was already ingested. | After changing a parser, or if a collection changed. |

Examples:

```bash
# Cheapest possible first run — just PowerShell history:
python main.py investigate "PATH" --case-id test --only Psh

# Focused on the questions, let the AI decide scope:
python main.py investigate "PATH" --case-id ws001 --questions questions.txt --relevant-only

# Parse once with no AI, then reuse that parsed case.db for repeat runs:
python main.py investigate "PATH" --case-id base --ingest-only
#   ...later, copy output/base/case.db to output/run1/case.db and investigate run1
#   (it sees the parse is done and skips straight to investigating — no re-parse).
```

The category codes (`Psh`, `Evt`, `Reg`, …) are listed in `config/artifact_map.yaml`.

### Many hosts at once (parallel)

For a multi-host case (e.g. a whole CTF), `run_hosts.py` runs several hosts **in parallel**
— each its own process and `case.db`, bounded by `--jobs`. It accepts the same flags as
`investigate` (each host's console output goes to `output/<host>/run.log`):

```bash
# parse every host once, 4 at a time (no AI):
python run_hosts.py "PATH/TO/FORENSICS/ACQ-IR-*" --ingest-only --jobs 4

# then investigate them all against one question set, 3 at a time:
python run_hosts.py "PATH/TO/FORENSICS/ACQ-IR-*" --questions questions.txt --relevant-only --jobs 3
```

Each host's step-by-step output **streams live to the console, tagged `[host]`** (and is also
saved to `output/<host>/run.log`), so you can see it's progressing — pass `--quiet` for just a
one-line summary as each host finishes.

**Don't know which host owns which question?** Just run every question on every host (above) —
a question is answered if *any* host answers it. When the investigation sweep finishes,
`run_hosts.py` **auto-writes two combined views** (regenerate either anytime, read-only/no cost):

- **`output/_combined/answer_sheet.md`** — a routing table (question → which host answered) plus
  the best answer per question, collated across all hosts. (`python scripts/aggregate.py`)
- **`output/_combined/report.html`** — a **self-contained, offline interactive dashboard**: open
  it in a browser to **search, filter, and sort** across all hosts' Answers, Findings, and
  Coverage (click a row to expand its cited evidence). No network or dependencies — the data is
  embedded. (`python scripts/report_html.py --open`)

---

## 8. Resuming a run

Re-running with the **same `--case-id`** continues where it left off instead of starting
over:

- Parsing is **not** repeated (it's saved). Add `--reingest` to force a fresh re-parse.
- If a run crashed or you stopped it, unfinished work is retried.
- **Questions are matched by their text.** If you re-run with a question unchanged, its
  existing answer is kept (not redone). If you **change** a question (or add a new one),
  it's investigated fresh — using the already-parsed evidence, so you don't pay to re-parse
  just to ask a follow-up. Pass `--questions` to set the current question list.

```bash
# First run answers some questions, then you add a new question to questions.txt:
python main.py investigate "PATH" --case-id ws001 --questions questions.txt
# (edit questions.txt, add a line)
python main.py investigate "PATH" --case-id ws001 --questions questions.txt   # only the new question is investigated
```

---

## 9. Choosing a different AI provider

The tool supports **Anthropic (Claude)**, **OpenAI**, and **Gemini**. Anthropic is the
default and most-tested. To switch, edit `config/config.yaml` and install that provider's
SDK.

```yaml
# config/config.yaml — the "subagent" role does the investigating
models:
  subagent: { provider: anthropic, model: claude-sonnet-4-6 }  # default (use claude-opus-4-8 for max accuracy)
  # subagent: { provider: openai,  model: gpt-5 }
  # subagent: { provider: gemini,  model: gemini-2.5-pro }
```

Install the matching SDK and set the matching key:

| Provider | Install | Env var |
|----------|---------|---------|
| Anthropic | (included) | `ANTHROPIC_API_KEY` |
| OpenAI | `pip install -e ".[openai]"` | `OPENAI_API_KEY` |
| Gemini | `pip install -e ".[gemini]"` | `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) |

You only need the SDK for the provider you actually use. **The OpenAI and Gemini backends
follow each SDK's documented format but are less battle-tested than Anthropic — verify on
your first run.**

---

## 10. Memory-image analysis (optional)

If a collection includes a RAM capture (a `MemDump/` folder with a `.raw`/`.mem`/`.dmp`
image), the agent can analyze it with **Volatility3** to answer questions whose answers
only live in memory — running processes, active network connections, injected code, or
commands typed at a console.

**`python install.py` sets this up for you by default** (it builds the `.venv-vol`
environment described below). This section explains what that is — useful for manual
setup, a second machine, Docker, or if you installed with `--no-memory`.

Volatility is kept in its **own virtual environment** so its dependencies never collide
with the core tool's; the tool just shells out to it. If memory isn't set up the tool
degrades gracefully (memory questions become POINTERs) — though because `config.yaml`
ships with `enabled: true`, you'll see Volatility errors until you either set it up or set
`memory.enabled: false`.

### Set it up manually (one time, per machine)

```bash
# from the repo root
python -m venv .venv-vol

# install Volatility into it
.venv-vol/Scripts/pip install -r requirements-memory.txt   # Windows
.venv-vol/bin/pip install -r requirements-memory.txt       # macOS / Linux
```

Verify it runs:

```bash
.venv-vol/Scripts/vol --help     # Windows
.venv-vol/bin/vol --help         # macOS / Linux
```

> First time it analyzes an image it downloads Windows **symbol tables** from Microsoft
> (needs internet once), then caches them. Volatility3's core is pure-Python, so it
> installs cleanly even on the newest Python versions.

### Turn it on

In `config/config.yaml`, enable it and point `vol_cmd` at that machine's executable:

```yaml
memory:
  enabled: true
  vol_cmd: [".venv-vol/Scripts/vol.exe"]    # Windows
  # vol_cmd: [".venv-vol/bin/vol"]          # macOS / Linux
  cache_dir: output/_memcache               # per-image plugin cache (a re-run is free)
```

The first list element resolves against the repo root. It's a list, so you can also run
Volatility via Docker instead: `vol_cmd: ["docker","run","--rm","-v","...","volatility3"]`.

> **Why isn't `.venv-vol/` committed?** A venv is machine-, OS-, and Python-version
> specific (it bakes in absolute paths and platform binaries), so committing it wouldn't
> work on another machine anyway. The portable artifact is the **recipe** —
> `requirements-memory.txt` plus these two commands — which rebuilds it anywhere.

### What it does during a run

When a question needs volatile evidence, the agent calls the `vol_run` tool on a specific
Volatility plugin (e.g. `windows.netscan`, `windows.pslist`, `windows.malfind`,
`windows.cmdline`/`consoles`), and each result row becomes a normal, **citable** timeline
record (`source="memory"`). Memory is slow, so the agent uses it targeted — only when disk
artifacts can't answer — and results are cached per plugin.

> One limitation: this Volatility build has **no credential-dump plugin**
> (no hashdump/lsadump). For a *typed* secret, the agent tries `consoles`/`cmdline`;
> otherwise it POINTs at the image.

---

## 11. Configuration files

| File | Purpose |
|------|---------|
| `config/config.yaml` | Which AI model each role uses, effort level, safety budgets (max steps/leads), and the `memory:` block (Volatility settings — see [section 10](#10-memory-image-analysis-optional)). |
| `config/artifact_map.yaml` | Maps evidence folder codes (`Evt`, `Reg`, …) to a type and a parser — **the adapter for a collection's layout**. Edit it (or pass `--artifact-map`) to support a differently-organized collection. |
| `config/artifact_map.stock.yaml` | Ready-made layout map for **stock AChoirX** output (vs. the DC33 custom layout). Use via `--artifact-map`. |
| `knowledge_base/` | Plain-Markdown "playbooks" and references the AI reads while investigating. **You can improve the tool's behavior by editing these — no coding required.** |
| `.env` (from `.env.example`) | Your API key(s). Loaded automatically; git-ignored. |
| `requirements.txt` / `requirements-memory.txt` | Core dependencies / the optional Volatility dependency for memory analysis. |

### Using it on a different collection or a newer collector

The tool is built around **AChoirX**-style triage collections (the DC33 dataset used a
*custom* AChoirX collector). It isn't hardwired to one layout: `artifact_map.yaml` maps each
top-level **folder code** to a type + parser, so adapting to a different layout is usually a
**YAML edit, not code**.

**Check a collection before a full run** (deterministic, no AI, no cost):

```bash
python main.py check "PATH/TO/COLLECTION"
```

It reports which folder codes are recognized, whether each parser finds its expected input
(and for the CSV parsers, whether the columns match), and a verdict — **COMPATIBLE /
PARTIAL / UNRECOGNIZED**. Run this first on a collection from a new source: the parsers
degrade *silently* on an unfamiliar layout (skip missing files, emit 0), so an almost-empty
result can otherwise look like it "worked." `check` makes that explicit.

**Use a different layout map** with `--artifact-map` (works on both `check` and `investigate`):

```bash
python main.py check      --artifact-map config/artifact_map.stock.yaml "PATH/TO/COLLECTION"
python main.py investigate --artifact-map config/artifact_map.stock.yaml "PATH" --case-id x
```

A ready-made **`config/artifact_map.stock.yaml`** is included for **stock AChoirX** output and
has been **validated against a real stock collection (AChoirX 2026)** — all parsers run and
`check` reports COMPATIBLE. Stock is ~95% the same as the DC33 layout (same bundled export tools,
so the browser/USN CSV formats match; standard binary formats), differing only in a few folder
codes: autoruns `Arn`→`ASEP` (CSV), sysinfo `Sys`→`SYS`, real prefetch in `Prf` (plus run-program
copies still in `RanProg`), and a new `PCA` bucket (Program Compatibility Assistant — execution
evidence). For any other collector, copy `artifact_map.yaml`, rename/add codes to match what
`check` reports, and you're done.

---

## 12. How it works (under the hood)

```
Evidence folder (read-only)
  │
  ▼  [A] Parse (deterministic, no AI)   → normalized records saved in case.db
  │       Established forensic parsers turn binary artifacts into structured rows.
  │
  ▼  [B] Seed leads (your questions + one per evidence category)
  │
  ▼  [C] Agentic loop
  │       An orchestrator hands each lead to a sub-agent. The sub-agent reads the data
  │       with tools, writes findings/answers (each with a citation), and can file new
  │       leads. Runs until everything is examined and the queue is empty.
  │
  ▼  [D] Report: write Markdown from the findings, then verify every citation resolves.
```

Some evidence is analyzed **on demand** instead of bulk-parsed in step [A]: the full
`$MFT` (via the `mft_lookup` tool) and the memory image (via `vol_run` / Volatility) are
far too large to parse wholesale, so they're queried lazily during [C] only when a lead
needs them — and their results join the same cited timeline (`source="mft"` / `"memory"`).

**Key design rule:** the AI never parses raw binaries (event logs, registry hives,
memory dumps). Trusted forensic parsers extract structured records first; the AI only
reasons over that normalized data and must cite a real record for every claim. This is
what keeps it from hallucinating.

---

## 13. Status & roadmap

Parsers and features marked done are working and tested on real evidence.

- [x] Core engine: parsing → timeline (`case.db`) → agentic loop → cited Markdown report
- [x] Citation enforcement + verification (no uncited claims)
- [x] `Psh` (PowerShell history) parser
- [x] `Evt` (Windows event logs / EVTX) parser — Rust-backed (`evtx`), fast; curated
      high-value channels & IDs incl. Kerberos/NTLM, AD group management, file-share access,
      WMI/BITS/AppLocker/RDP-client/SMB/Directory-Service
- [x] `Reg` (registry) parser — persistence, accounts, software, devices, user activity
- [x] Amcache parser (`source="amcache"`) — program execution evidence + SHA1 hashes
- [x] `Brw` (browser) parser — history & downloads (`source="browser"`)
- [x] `Lnk` (shortcut/LNK) parser — recently-opened files: target path, MAC times, volume
- [x] USN journal parser (`source="usn"`) — curated file create/delete/rename timeline
- [x] On-demand `$MFT` lookup tool — resolves a file's full path + $SI/$FN timestamps by
      name (the full `$MFT` is intentionally not bulk-parsed; this is targeted/lazy)
- [x] `Sys` SRUM parser (`source="srum"`) — app activity windows + network connectivity
- [x] Multi-provider AI (Anthropic / OpenAI / Gemini), resume, question-driven scoping
- [x] The agent can also read text/CSV evidence (e.g. `Conn/CPorts.csv`, `Sys/LastActivity.csv`)
      directly, even without a dedicated parser
      (note: in this dataset `Ranprog` holds executable *copies*, not `.pf` prefetch)
- [x] Memory-image analysis (Volatility3) — on-demand `vol_run` tool over an isolated venv
      (optional; see [section 10](#10-memory-image-analysis-optional))
- [x] Collection-compatibility `check` command + `--artifact-map` layout adapter — incl. a
      ready-made map **validated on a real stock AChoirX (2026) collection** (all parsers run;
      new buckets `ASEP`/`PCA`/`Prf` cataloged + playbook-guided, read on demand)
- [x] Parallel multi-host runs (`run_hosts.py`, live-streamed) + CTF helpers (deterministic
      planted-flag scan via `find_flags`, verbatim-token answers, inline `--question`)
- [x] Cross-host combined **answer sheet** + interactive **HTML dashboard** (search / filter /
      sort across all hosts; per-host `report.html` too) — `aggregate.py` / `report_html.py`
- [ ] Cross-host correlation — a single agent investigating the whole domain *jointly* (today
      each host is investigated separately and the results are combined after the fact)
