"""Case File: persistent SQLite store for one host investigation.

Holds the coverage manifest, lead queue, findings ledger, answers, normalized
timeline, file catalog, and the emitted-locators table that backs the citation rule.
Persistence makes the run resumable after a crash.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = Path(__file__).with_name("schema.sql")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_answer(text: str) -> str:
    """Normalize an answer for duplicate comparison: lowercase, collapse whitespace."""
    return " ".join((text or "").lower().split())


class CaseDB:
    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA.read_text(encoding="utf-8"))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ---- meta / resume --------------------------------------------------
    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?,?)", (key, value))
        self.conn.commit()

    def reset_in_progress_leads(self) -> int:
        """Re-open leads left mid-flight by a crash/interruption so they get retried."""
        cur = self.conn.execute("UPDATE leads SET status='open' WHERE status='in_progress'")
        self.conn.commit()
        return cur.rowcount

    def clear_events_and_files(self) -> None:
        """Wipe parsed data (used before a fresh/retried ingest to avoid duplicates)."""
        self.conn.execute("DELETE FROM events")
        self.conn.execute("DELETE FROM files")
        self.conn.commit()

    # ---- coverage -------------------------------------------------------
    def upsert_coverage(self, artifact: str, type_: str, parser: str | None, present: bool) -> None:
        self.conn.execute(
            "INSERT INTO coverage(artifact, type, parser, present) VALUES(?,?,?,?) "
            "ON CONFLICT(artifact) DO UPDATE SET type=excluded.type, parser=excluded.parser, "
            "present=excluded.present",
            (artifact, type_, parser, int(present)),
        )
        self.conn.commit()

    def set_coverage_status(self, artifact: str, status: str) -> None:
        self.conn.execute("UPDATE coverage SET status=? WHERE artifact=?", (status, artifact))
        self.conn.commit()

    def unexamined_present(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM coverage WHERE present=1 AND status='unexamined'"
        ).fetchall()

    def coverage_rows(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM coverage ORDER BY artifact").fetchall()

    # ---- leads ----------------------------------------------------------
    def add_lead(self, title: str, reason: str = "", source: str = "agent",
                 question_id: str | None = None, artifact: str | None = None,
                 priority: int = 50, depth: int = 0) -> int | None:
        """Insert a lead. Returns id, or None if it was a duplicate (dedup)."""
        dedup = f"{source}|{question_id or ''}|{artifact or ''}|{title.strip().lower()}"
        try:
            cur = self.conn.execute(
                "INSERT INTO leads(title, reason, source, question_id, artifact, priority, depth, dedup_key)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (title, reason, source, question_id, artifact, priority, depth, dedup),
            )
            self.conn.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return None  # already filed

    def next_lead(self) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM leads WHERE status='open' ORDER BY priority DESC, id ASC LIMIT 1"
        ).fetchone()

    def set_lead_status(self, lead_id: int, status: str) -> None:
        self.conn.execute("UPDATE leads SET status=? WHERE id=?", (status, lead_id))
        self.conn.commit()

    def total_leads(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM leads").fetchone()[0]

    # ---- emitted locators (citation backbone) ---------------------------
    def emit_locator(self, locator: str, kind: str, detail: str = "") -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO emitted_locators(locator, kind, detail) VALUES(?,?,?)",
            (locator, kind, detail),
        )
        self.conn.commit()

    def locator_exists(self, locator: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM emitted_locators WHERE locator=?", (locator,)
        ).fetchone() is not None

    # ---- findings -------------------------------------------------------
    def add_finding(self, title: str, severity: str, evidence: list[dict],
                    confidence: str = "", attack_technique: str = "",
                    description: str = "", status: str = "corroborated") -> int:
        cur = self.conn.execute(
            "INSERT INTO findings(title, severity, confidence, attack_technique, description, status, created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (title, severity, confidence, attack_technique, description, status, _now()),
        )
        fid = cur.lastrowid
        for ev in evidence:
            self.conn.execute(
                "INSERT INTO finding_evidence(finding_id, locator, excerpt) VALUES(?,?,?)",
                (fid, ev["locator"], ev.get("excerpt", "")),
            )
        self.conn.commit()
        return fid

    def findings(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM findings ORDER BY id").fetchall()

    def findings_summary(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT id, severity, attack_technique, title FROM findings ORDER BY id"
        ).fetchall()

    def find_duplicate_finding(self, attack_technique: str, locators: list[str]) -> int | None:
        """An existing finding is a duplicate if it shares the same ATT&CK technique
        (empty matches empty) AND at least one evidence locator. Deterministic merge key."""
        tech = (attack_technique or "").strip().lower()
        locset = set(locators)
        for r in self.conn.execute("SELECT id, attack_technique FROM findings"):
            if (r["attack_technique"] or "").strip().lower() != tech:
                continue
            ev = self.conn.execute(
                "SELECT locator FROM finding_evidence WHERE finding_id=?", (r["id"],)
            ).fetchall()
            if locset & {e["locator"] for e in ev}:
                return r["id"]
        return None

    def add_finding_evidence(self, finding_id: int, evidence: list[dict]) -> int:
        """Merge new evidence locators into an existing finding; returns count added."""
        existing = {e["locator"] for e in self.conn.execute(
            "SELECT locator FROM finding_evidence WHERE finding_id=?", (finding_id,))}
        added = 0
        for ev in evidence:
            if ev["locator"] not in existing:
                self.conn.execute(
                    "INSERT INTO finding_evidence(finding_id, locator, excerpt) VALUES(?,?,?)",
                    (finding_id, ev["locator"], ev.get("excerpt", "")))
                added += 1
        self.conn.commit()
        return added

    def finding_evidence(self, finding_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM finding_evidence WHERE finding_id=?", (finding_id,)
        ).fetchall()

    # ---- questions / answers -------------------------------------------
    def add_question(self, qid: str, text: str) -> None:
        self.conn.execute("INSERT OR REPLACE INTO questions(id, text) VALUES(?,?)", (qid, text))
        self.conn.commit()

    def questions(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM questions ORDER BY rowid").fetchall()

    def clear_questions(self) -> None:
        self.conn.execute("DELETE FROM questions")
        self.conn.commit()

    def add_answer(self, question_id: str, status: str, answer: str = "",
                   reasoning: str = "", evidence: list[dict] | None = None,
                   candidates: list[dict] | None = None, confidence: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO answers(question_id, status, answer, confidence, reasoning, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (question_id, status, answer, confidence, reasoning, _now()),
        )
        aid = cur.lastrowid
        for ev in evidence or []:
            self.conn.execute(
                "INSERT INTO answer_evidence(answer_id, locator, excerpt) VALUES(?,?,?)",
                (aid, ev["locator"], ev.get("excerpt", "")),
            )
        for c in candidates or []:
            self.conn.execute(
                "INSERT INTO answer_candidates(answer_id, path, reason) VALUES(?,?,?)",
                (aid, c["path"], c.get("reason", "")),
            )
        self.conn.commit()
        return aid

    def answers_for(self, question_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM answers WHERE question_id=? ORDER BY id", (question_id,)
        ).fetchall()

    def answer_evidence(self, answer_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM answer_evidence WHERE answer_id=?", (answer_id,)
        ).fetchall()

    def answer_candidates(self, answer_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM answer_candidates WHERE answer_id=?", (answer_id,)
        ).fetchall()

    def answer_is_duplicate(self, question_id: str, status: str, answer: str,
                            candidates: list[dict] | None) -> bool:
        """True if this answer merely restates one already recorded. Distinct values
        and better-supported alternatives are NOT duplicates — they're kept."""
        rows = self.answers_for(question_id)
        if status == "answered":
            norm = _norm_answer(answer)
            return any(r["status"] == "answered" and _norm_answer(r["answer"]) == norm for r in rows)
        if status == "pointer":
            newset = {c["path"] for c in (candidates or [])}
            for r in rows:
                if r["status"] == "pointer":
                    if {x["path"] for x in self.answer_candidates(r["id"])} == newset:
                        return True
            return False
        # unresolved is redundant the moment any answer exists for the question
        return bool(rows)

    def question_resolved(self, question_id: str) -> str | None:
        """Returns the best existing answer text/summary for a question, or None."""
        rows = self.answers_for(question_id)
        answered = [r for r in rows if r["status"] == "answered"]
        if answered:
            return answered[-1]["answer"]
        pointer = [r for r in rows if r["status"] == "pointer"]
        if pointer:
            return "(pointer: candidate files nominated)"
        return None

    # ---- events / files -------------------------------------------------
    def add_event(self, source_artifact: str, summary: str, locator: str,
                  ts: str = "", host: str = "", user: str = "",
                  event_type: str = "", raw: str = "") -> None:
        self.conn.execute(
            "INSERT INTO events(ts, source_artifact, host, user, event_type, summary, locator, raw)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (ts, source_artifact, host, user, event_type, summary, locator, raw),
        )

    def add_file(self, path: str, artifact: str, name: str, owner: str,
                 size: int, mtime: str, ctime: str, atime: str, is_text: bool) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO files(path, artifact, name, owner, size, mtime, ctime, atime, is_text)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (path, artifact, name, owner, size, mtime, ctime, atime, int(is_text)),
        )

    def commit(self) -> None:
        self.conn.commit()
