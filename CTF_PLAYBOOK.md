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

# (per collection) sanity-check the layout BEFORE spending anything
python main.py check "<FORENSICS>/ACQ-IR-<host>-<date>"
#   stock AChoirX?  add:  --artifact-map config/artifact_map.stock.yaml

# parse ALL hosts once (fast, no AI), 4 at a time
python run_hosts.py "<FORENSICS>/ACQ-IR-*" --ingest-only --jobs 4

# investigate ALL hosts against the questions (reuses the parse), 3 at a time
python run_hosts.py "<FORENSICS>/ACQ-IR-*" --questions questions.txt --relevant-only --jobs 3

# read results
#   output/<host>/report.md   (answer sheet + findings)
#   output/<host>/run.log     (that host's console)
```

`<FORENSICS>` = the folder that contains the `ACQ-IR-*` host collections.

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
python install.py            # creates .venv + .venv-vol, installs everything
#   --no-memory  to skip Volatility (memory analysis) if you don't need it
cp .env.example .env          # then edit: ANTHROPIC_API_KEY=sk-ant-...
```

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

**b) Content match (after the parse).** For un-named questions, grep each host's parsed data
for a distinctive term from the question (a username, filename, IP, tool). The host with hits
owns it:
```python
# save as search.py — ranks hosts that mention a term (run after the --ingest-only step)
import sqlite3, glob, sys
from pathlib import Path
term = sys.argv[1]
for db in sorted(glob.glob("output/*/case.db")):
    c = sqlite3.connect(db)
    n = c.execute("SELECT COUNT(*) FROM events WHERE summary LIKE ?", (f"%{term}%",)).fetchone()[0]
    n += c.execute("SELECT COUNT(*) FROM files  WHERE path    LIKE ?", (f"%{term}%",)).fetchone()[0]
    if n: print(f"{n:6}  {Path(db).parent.name}")
```
```bash
python search.py olivia.parker     # -> the host with the most hits is the owner
```

**c) Answer evidence (after a run).** Whichever host *answered* a question is, by definition,
its host — the answer lives in that host's `case.db`:
```python
# save as whoanswered.py — lists which host answered each question
import sqlite3, glob
from pathlib import Path
for db in sorted(glob.glob("output/*/case.db")):
    host = Path(db).parent.name
    c = sqlite3.connect(db); c.row_factory = sqlite3.Row
    for r in c.execute("SELECT q.text t, a.answer a FROM answers a JOIN questions q "
                        "ON q.id=a.question_id WHERE a.status='answered'"):
        print(f"{host:40} | {r['t'][:55]} -> {(r['a'] or '')[:40]}")
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

**Broad (simplest)** — run every question on every host; a question is answered if *any* host
answers it (union). Wasteful but hands-off:
```bash
python run_hosts.py "<FORENSICS>/ACQ-IR-*" --questions questions.txt --relevant-only --jobs 3
```

Tips: batch all of a host's questions into **one** run (not one-per-run). Use `--relevant-only`
or `--only <buckets>` to scope. The default model is Sonnet (cheap); bump `subagent` to
`claude-opus-4-8` in `config/config.yaml` for a final high-accuracy pass on hard ones.

---

## 6. Review, flags, and the miss→fix loop

- Open **`output/<host>/report.md`** → the **answer sheet** (ANSWERED / POINTER / UNRESOLVED).
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

- **Parse once, reuse** the `case.db` (§3). Never re-parse to ask a follow-up.
- **Batch** questions per host; don't run one-per-host-per-question.
- **Scope** with `--relevant-only` / `--only`; **Sonnet** for sweeps, Opus only for hard ones.
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
