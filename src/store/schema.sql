-- Case File schema. One SQLite db per host investigation (output/<case-id>/case.db).

-- Coverage manifest: every artifact bucket present in the collection.
-- status: unexamined -> triaged -> analyzed. The run finishes only when no bucket
-- is still 'unexamined'.
CREATE TABLE IF NOT EXISTS coverage (
    artifact   TEXT PRIMARY KEY,     -- dir-code, e.g. "Psh"
    type       TEXT NOT NULL,        -- e.g. "powershell_history"
    parser     TEXT,                 -- parser module name, or NULL
    present    INTEGER NOT NULL,     -- 1 if the dir exists in this collection
    status     TEXT NOT NULL DEFAULT 'unexamined'
);

-- Lead queue: the engine. Sub-agents may file new leads; orchestrator pops them.
-- status: open -> in_progress -> closed. priority: higher = sooner.
CREATE TABLE IF NOT EXISTS leads (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title      TEXT NOT NULL,
    reason     TEXT,
    source     TEXT,                 -- 'question' | 'coverage' | 'agent'
    question_id TEXT,                -- set when source='question'
    artifact   TEXT,                 -- target bucket when source='coverage'
    priority   INTEGER NOT NULL DEFAULT 50,
    depth      INTEGER NOT NULL DEFAULT 0,
    status     TEXT NOT NULL DEFAULT 'open',
    dedup_key  TEXT UNIQUE           -- prevents re-filing the same lead
);

-- Findings ledger: cited evidence is the report's only source of truth.
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    severity    TEXT,
    confidence  TEXT,
    attack_technique TEXT,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'corroborated',
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id  INTEGER NOT NULL REFERENCES findings(id),
    locator     TEXT NOT NULL,
    excerpt     TEXT
);

-- CTF questions and their resolutions.
CREATE TABLE IF NOT EXISTS questions (
    id    TEXT PRIMARY KEY,
    text  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS answers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id TEXT NOT NULL,
    status      TEXT NOT NULL,        -- answered | pointer | unresolved
    answer      TEXT,
    confidence  TEXT,                 -- low | medium | high
    reasoning   TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS answer_evidence (
    answer_id  INTEGER NOT NULL REFERENCES answers(id),
    locator    TEXT NOT NULL,
    excerpt    TEXT
);
CREATE TABLE IF NOT EXISTS answer_candidates (
    answer_id  INTEGER NOT NULL REFERENCES answers(id),
    path       TEXT NOT NULL,
    reason     TEXT
);

-- Normalized event timeline (parser output lands here).
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT,
    source_artifact TEXT NOT NULL,    -- e.g. "powershell_history"
    host            TEXT,
    user            TEXT,
    event_type      TEXT,
    summary         TEXT,             -- the human/agent-readable line
    locator         TEXT NOT NULL,    -- stable citation handle
    raw             TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_artifact);

-- File-metadata catalog: EVERY file, including binaries we can't read. Powers
-- POINTER answers (nominate candidate files via name/owner/timestamps).
CREATE TABLE IF NOT EXISTS files (
    path      TEXT PRIMARY KEY,       -- relative to the artifact root
    artifact  TEXT,                   -- owning dir-code
    name      TEXT,
    owner     TEXT,
    size      INTEGER,
    mtime     TEXT,
    ctime     TEXT,
    atime     TEXT,
    is_text   INTEGER NOT NULL DEFAULT 0
);

-- Small key/value store for case-level state (e.g. ingest-complete flag) — enables
-- idempotent ingest and resume.
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Every locator any tool has returned to the agent. A finding/answer may only cite
-- locators present here -> the no-uncited-assertions rule is structural, and the
-- verifier checks against this.
CREATE TABLE IF NOT EXISTS emitted_locators (
    locator TEXT PRIMARY KEY,
    kind    TEXT,
    detail  TEXT
);
