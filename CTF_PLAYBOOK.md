# CTF Day-Of Playbook

Operational runbook for using **forensic-investigator** during a live, timed CTF. The tool
is a force-multiplier on **host disk + memory** questions (cited, no hallucination); you own
flag submission, the POINTER/UNRESOLVED items, and the categories the tool doesn't cover.

---

## TL;DR — the command cheat sheet

```bash
# (once) set up the machine
python install.py                       # core tool + Volatility memory env
#   then paste ANTHROPIC_API_KEY into .env

# (every new terminal) activate the core venv
.venv\Scripts\Activate.ps1              # Windows  (POSIX: source .venv/bin/activate)

# (per collection) sanity-check the layout BEFORE spending anything
python main.py check "<FORENSICS>/ACQ-IR-<host>-<date>"
#   stock AChoirX?      add:  --artifact-map config/artifact_map.stock.yaml
#   Linux/Ubuntu host?  add:  --artifact-map config/artifact_map.linux.yaml   (add to EVERY command below)

# parse ALL hosts once (fast, no AI), 4 at a time
python run_hosts.py "<FORENSICS>/ACQ-IR-*" --ingest-only --jobs 4

# investigate ALL hosts against the questions (reuses the parse), 3 at a time
python run_hosts.py "<FORENSICS>/ACQ-IR-*" --questions questions.txt --relevant-only --jobs 3

# read results
#   output/_combined/report.html    (open in a browser: search/filter/sort ALL hosts)
#   output/_combined/answer_sheet.md (routing table: which host answered which question)
#   output/<host>/report.md          (one host's answer sheet + findings)
#   output/<host>/run.log            (that host's console, timestamped — every run writes one)
```

`<FORENSICS>` = the folder that contains the `ACQ-IR-*` host collections.

> The sweep above is the **simplest** path but the **priciest** (every question × every host).
> When you can tell which host a question belongs to, §5 / §8 show a cheaper *route-then-target*
> flow. New to the tool? Read the README's Quick start first, then come back here.

---

## 0. Before the day (prep — don't do this under the clock)

- [ ] **Install & verify** on the machine you'll use (see §1). Run `python main.py check` on
      a known-good collection and confirm `COMPATIBLE`.
- [ ] **Top up API credits.** You pay for *two* LLM layers: the tool's own calls **and** any
      Claude operator session. The credit wall has bitten before.
- [ ] **Dry run** the full flow on last year's data (DC33) so the steps are muscle memory.
- [ ] **Confirm memory works** if you expect memory questions: `.venv-vol/Scripts/vol --help`.
- [ ] Keep the machine **plugged in, lid open** (idle-sleep is auto-prevented; lid-close is not).

---

## 1. Install on a new machine

```bash
git clone <repo-url> && cd forensic-investigator
python install.py            # creates .venv + .venv-vol, installs deps, seeds .env
#   --no-memory  to skip Volatility (memory analysis) if you don't need it
# install.py creates .env for you — open it and set: ANTHROPIC_API_KEY=sk-ant-...

# activate the core venv (do this in every new terminal before running the tool):
.venv\Scripts\Activate.ps1    # Windows (PowerShell)
source .venv/bin/activate     # macOS / Linux
```

> Every `python main.py ...` / `python run_hosts.py ...` command below assumes the `.venv`
> is **activated** in that shell. (You don't activate `.venv-vol` — the tool shells out to
> it on its own.) Re-activate after opening a new terminal.

Verify:
```bash
python main.py check "<FORENSICS>/ACQ-IR-<any-host>"     # should print COMPATIBLE
```

Requirements: Python 3.10+ (works on 3.14), internet (first memory run downloads symbols),
and an API key with credit. Everything is pure-Python except the Volatility venv.

---

## 2. Start of the event — get oriented

1. Get the **collections** (the `ACQ-IR-*` folders) and the **question list**.
2. Put the questions in `questions.txt`, **one per line**. If the questions come grouped by
   "problem" / category, **keep the grouping** — leave a blank line between groups (this lets
   you propagate a host to a whole category later).
3. **Check the layout** on one host before committing:
   ```bash
   python main.py check "<FORENSICS>/ACQ-IR-<host>-<date>"
   ```
   - `COMPATIBLE` → proceed.
   - Unknown dir-codes / `PARTIAL` → it's a different collector. Try
     `--artifact-map config/artifact_map.stock.yaml`; if still off, copy that YAML, rename the
     codes to match what `check` lists, and pass your new map everywhere with `--artifact-map`.
   - **Linux/Ubuntu host** (`VarLog`, `Proc`, `Etc`, `Home` dir-codes) → use
     `--artifact-map config/artifact_map.linux.yaml`, and **add that flag to every command below**
     (`check`, `--ingest-only`, `investigate`, `run_hosts.py`). The tool auto-detects Linux and
     uses Linux parsers (auth/syslog, dpkg/apt, bodyfile timeline, process snapshot, shell history)
     + Linux playbooks. Linux **memory** is manual (needs a per-kernel Volatility ISF) → POINTER.

---

## 3. Parse all hosts once (and reuse)

Parsing is the slow, CPU part; **do it once per host and reuse the `case.db`.**

```bash
python run_hosts.py "<FORENSICS>/ACQ-IR-*" --ingest-only --jobs 4
```
- Builds `output/<host>/case.db` for every host (no AI, no cost).
- Each host's case-id is its folder name, so the **investigation step reuses this parse**
  automatically (it sees the parse is done and skips straight to investigating).
- Add `--artifact-map config/artifact_map.stock.yaml` if the layout needed it.

---

## 4. Identify which host owns which question

You rarely know up front which host a question is about. Use these signals (cheap → strong):

**a) The question names the host.** Many do (`On namtws003,…`, `NAMTWS04 …`, `workstation #1`).
Pull them out:
```bash
grep -niE "namtws[0-9]+|namtdc[0-9]+|namtsh[0-9]+|workstation ?#?[0-9]" questions.txt
```

**b) Content match (after the parse).** For un-named questions, search each host's parsed
data for a distinctive term from the question (a username, filename, IP, tool). The host with
the most hits owns it. Use the bundled **`scripts/search.py`**:
```bash
python scripts/search.py olivia.parker        # -> ranks hosts by hits; top one is the owner
python scripts/search.py 13.58.222.12         # works for IPs, filenames, tool names, …
# multiple keywords: AND (default) = ONE entry (row) must contain ALL terms; --any = OR:
python scripts/search.py olivia.parker 13.58.222.12     # the exact event/file tying both together
python scripts/search.py olivia.parker mimikatz --show  # --show prints the matching rows + locators
python scripts/search.py --any AdFind SharpHound BloodHound   # host mentions ANY, ranked by hits
#   default prints per-host counts + a bucket breakdown (event_logs / browser / file:Reg …);
#   quote multi-word terms; --root DIR / --glob 'PATTERN' if case.db isn't under ./output/<host>/
```

**c) Answer evidence (after a run).** Whichever host *answered* a question is, by definition,
its host — the answer lives in that host's `case.db`. Use **`scripts/whoanswered.py`**:
```bash
python scripts/whoanswered.py                 # host | question -> answer  (ANSWERED only)
python scripts/whoanswered.py --question kerberos   # filter to matching questions
python scripts/whoanswered.py --status any    # also show POINTER / UNRESOLVED
```

**d) Propagate by category (your rule of thumb).** Once one question in a problem/category is
pinned to host X (by any signal above), assign the **rest of that group** to X too.

---

## 5. Run investigations

Two viable modes:

**Targeted (cheapest)** — once §4 gives you a host→questions mapping, make a small
`q_<host>.txt` per host and run only its questions:
```bash
python main.py investigate "<FORENSICS>/ACQ-IR-<host>-<date>" --case-id ACQ-IR-<host>-<date> \
    --questions q_<host>.txt --relevant-only
```

**Broad (simplest — use this when you can't tell which host owns a question)** — run every
question on every host; a question is answered if *any* host answers it (union). Wasteful but
hands-off, and you **don't have to route questions to hosts first**:
```bash
python run_hosts.py "<FORENSICS>/ACQ-IR-*" --questions questions.txt --relevant-only --jobs 3
```
When it finishes it **auto-writes a combined answer sheet** that collates every host into one
file — so you don't open 11 reports to find the owner:
```
output/_combined/answer_sheet.md   # routing table (question -> host) + best answer per question
```
You can regenerate it anytime (read-only, free): `python scripts/aggregate.py`. Keep cost down
with `--relevant-only` (each host only investigates questions its data looks relevant to).

Tips: batch all of a host's questions into **one** run (not one-per-run). Use `--relevant-only`
or `--only <buckets>` to scope. The default model is Sonnet (cheap); bump `subagent` to
`claude-opus-4-8` in `config/config.yaml` for a final high-accuracy pass on hard ones.

---

## 6. Review, flags, and the miss→fix loop

- **Multi-host run?** Open **`output/_combined/report.html`** in a browser — a searchable,
  sortable, filterable dashboard over every host's Answers / Findings / Coverage (click a row for
  cited evidence). Or read **`output/_combined/answer_sheet.md`** for the routing table
  (question → which host answered). Either way, drill into a host's `output/<host>/report.md` for
  full detail. Single host: just open its `report.md` (ANSWERED / POINTER / UNRESOLVED).
  (Regenerate the dashboard anytime: `python scripts/report_html.py --open`.)
- **Submit the clean HITs.** The agent auto-runs `find_flags` (planted `btv{}`/`FL4G={}` markers)
  and answers filenames/commands **verbatim**, so those should be submission-ready.
- Work the **POINTER** (it nominated files it couldn't read — go look) and **UNRESOLVED** items
  (it tells you what it searched) by hand.
- **Miss → fix → re-run:** when you crack one manually, *encode it* and re-run that host:
  - answer was a specific event ID we don't capture → add it to `_SEC`/`_CHANNELS` in
    `src/extraction/evtx.py`
  - a routing/where-to-look gap → add a line to the relevant `knowledge_base/playbooks/*.md`
  - a layout/dir-code issue → edit the artifact map
  Re-running reuses the parse, so it's fast.

---

## 7. What the tool will NOT do (handle these yourself)

A large share of a BTV-style CTF lives **outside** the host collections. The tool POINTERs or
can't reach these — do them manually:
- Threat-intel / VirusTotal / OSINT lookups, image/screenshot trivia
- Web-app / API exploit logs, email/phishing headers, Wazuh dashboards
- Password cracking, external-service questions

Let the tool blitz the host-artifact questions (fast, cited) so your time goes to these.

---

## 8. Cost & speed discipline

**The #1 cost driver is broad mode** (every question × every host = ~11× the work). The combined
sheet / dashboard are for *reading* results cheaply — not a reason to investigate everything
everywhere. Prefer **route-then-target**:

```bash
# 1. parse all hosts once — free, no AI:
python run_hosts.py "<FORENSICS>/ACQ-IR-*" --ingest-only --jobs 4
# 2. route each question to its host (§4): host names in the text, then content match:
python scripts/search.py <distinctive-term>          # username / IP / filename / tool
# 3. investigate each host against ONLY its own questions (cheapest accurate path):
python main.py investigate "<FORENSICS>/ACQ-IR-<host>-<date>" --case-id ACQ-IR-<host>-<date> \
    --questions q_<host>.txt --relevant-only
# 4. only for the stubborn leftovers, fall back to a broad sweep (or bump to Opus).
```

This cuts cost up to ~11× vs. broad with little accuracy loss — most hosts have no signal for
most questions. Other levers:

- **Prompt caching is automatic** (system + tools + history are cached) — no action needed; it
  just makes every run cheaper. The parse is also reused across runs, so follow-ups are cheap.
- **Parse once, reuse** the `case.db` (§3). Never re-parse to ask a follow-up.
- **Batch** questions per host; don't run one-per-host-per-question (coverage work is shared).
- **Scope** with `--relevant-only` / `--only`; **Sonnet** for sweeps, Opus only for hard ones.
- **Budgets bound cost/time per host** (`config/config.yaml`): defaults are already tuned for a
  CTF — `max_subagent_steps 20`, `max_total_leads 60`, plus two runaway guards: a **per-question
  lead cap** (`max_leads_per_question 8`, so one unanswerable question can't fan out across every
  bucket) and a **wall-clock ceiling** (`max_host_minutes 25`, after which the host stops and
  writes its report — answers commit live, so nothing is lost). Lower these further for a cheaper
  sweep, but don't cut `max_subagent_steps` below ~18 (it starves the "rank all candidates" logic).
- **Parallelize** with `run_hosts.py --jobs N` (more jobs = faster but more API/min + CPU).
- Idle-sleep is auto-prevented; keep the **lid open**. `NO_COLOR=1` / `NO_EMOJI=1` for plain logs.

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| `credit balance too low` (400) | Top up at console.anthropic.com → Plans & Billing. |
| Run looks "hung" for minutes | Likely a big EVTX parse or API latency; check `output/<host>/run.log`. Answers commit to `case.db` as found, so a crash never loses them — regenerate the report from the db if needed. |
| `check` shows unknown dir-codes | Different collector layout. Use/adapt `--artifact-map` (copy `artifact_map.yaml`, rename codes). |
| EVTX emits 0 / `no backend` | Don't install `python-evtx` alongside `evtx` on Windows (they collide). Keep only `evtx`. |
| Memory questions → POINTER | Volatility not set up. `python install.py` (or set `memory.enabled: false`). |
| Machine slept and killed a run | Keep lid open / plugged in; idle-sleep is prevented but lid-close isn't. |

---

_See `README.md` for full feature docs, `eval/README.md` for scoring, and the project memory
(`live-ctf-playbook`, `ctf-eval-results`) for background._
