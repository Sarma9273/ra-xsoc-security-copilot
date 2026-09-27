from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any
from uuid import UUID

DEFAULT_DB = Path(os.getenv("RA_XSOC_DB_PATH", "runtime/ra_xsoc.db"))

class CaseStore:
    """Durable local case/review store.

    SQLite is the default development/runtime adapter. The schema is deliberately
    relational so a PostgreSQL adapter can replace it without changing API contracts.
    """

    def __init__(self, path: Path = DEFAULT_DB) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS cases (
                analysis_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                review_status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cases_incident_id ON cases(incident_id);
            CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at);
            CREATE TABLE IF NOT EXISTS feedback (
                feedback_id TEXT PRIMARY KEY,
                analysis_id TEXT NOT NULL,
                analyst_id TEXT NOT NULL,
                status TEXT NOT NULL,
                comments TEXT NOT NULL,
                corrected_attack_id TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_feedback_analysis_id ON feedback(analysis_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def save_analysis(self, payload: dict[str, Any]) -> None:
        with self._connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO cases
                   (analysis_id, incident_id, payload, review_status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, datetime('now'))""",
                (
                    str(payload["analysis_id"]),
                    str(payload["incident_id"]),
                    json.dumps(payload, default=str),
                    payload["review_status"],
                    payload["created_at"],
                ),
            )

    def get_analysis(self, analysis_id: UUID) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT payload FROM cases WHERE analysis_id = ?",
                (str(analysis_id),),
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def list_cases(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT payload FROM cases ORDER BY created_at DESC LIMIT ?",
                (min(max(limit, 1), 200),),
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def save_feedback(self, feedback: dict[str, Any]) -> None:
        with self._connect() as db:
            db.execute(
                """INSERT INTO feedback
                   (feedback_id, analysis_id, analyst_id, status, comments,
                    corrected_attack_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(feedback["feedback_id"]),
                    str(feedback["analysis_id"]),
                    str(feedback["analyst_id"]),
                    feedback["status"],
                    feedback["comments"],
                    feedback.get("corrected_attack_id"),
                    feedback["created_at"],
                ),
            )
