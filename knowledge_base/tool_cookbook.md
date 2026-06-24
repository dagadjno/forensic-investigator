# Tool Cookbook

You investigate normalized forensic records, not raw artifacts. Use these tools.
Every finding or answer you record MUST cite an evidence locator that another tool
already returned to you — never invent a locator.

## Read / search
- `kb_read(doc)` — read a knowledge-base doc (e.g. a playbook). Read the relevant
  playbook before investigating a lead.
- `query_timeline(...)` — query the normalized event timeline (filter by source
  artifact, user, text, time range). Returns rows with a stable `locator`.
- `grep_artifact(pattern, artifact=None)` — regex over the parsed text of an
  artifact type. Returns matching lines with a `locator`.
- `read_file(path, offset=0, limit=200)` — read a slice of a parsed/text file by its
  catalog path. Use offset/limit; do not pull whole large files.
- `list_files(query=None)` — search the file-metadata catalog (every file, including
  binaries you cannot read). Returns path, owner, size, MAC timestamps. This is how
  you find candidate files to POINT at.

## Record results
- `list_findings()` — see findings already recorded (by you or other sub-agents). Check
  this before recording so you don't re-investigate or duplicate something already found.
- `record_finding(title, severity, evidence, ...)` — log a cited finding to the ledger.
  `evidence` is a non-empty list of locators you obtained from other tools. If a finding
  with the same ATT&CK technique already cites one of your locators, your evidence is
  merged into it (no duplicate is created) — so prefer reusing the same technique id.
- `answer_question(question_id, status, ...)` — resolve a CTF question:
  - `status="answered"` → provide `answer` + non-empty `evidence` (verified citations).
  - `status="pointer"` → provide `candidate_files` + `reasoning`. Use this when the
    answer lives in something you cannot read (an image/screenshot, a binary). Do NOT
    guess its contents. Example: "Maybe these tell you which cat Mike likes: ...".
  - `status="unresolved"` → provide `reasoning` describing what you searched.
  - Add `confidence` (low/medium/high). If a question already has an answer, only record
    another if yours is **different** or **better-supported** — don't restate the same one.
    Distinct candidate answers are kept and shown side-by-side for the analyst to choose.
- `file_lead(title, reason)` — queue a NEW line of investigation for the orchestrator
  (e.g. "decode the base64 command found in history line 47"). Don't chase it yourself.
- `mark_examined(artifact)` — mark an artifact bucket as fully triaged once you've
  looked at it. The run only finishes when every bucket is examined.

## Rules
- Answer or point — never guess. An assertion with no citation is not allowed.
- Prefer `query_timeline` / `grep_artifact` to pull only what matters; only `read_file`
  when you need surrounding context.
- When you have enough to act, act. Conclude the lead rather than over-exploring.
