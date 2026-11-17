"""Lazy experiment-specific SQLite persistence, separate from the event ledger."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from threading import RLock

from app.experiments.models import ExperimentResult

ROOT = Path(__file__).resolve().parents[3]


class ExperimentStorage:
    def __init__(self, database_path: str | Path | None = None):
        self.path = Path(database_path or os.getenv("HONEYPOT_EXPERIMENT_DB_PATH") or ROOT / "data" / "experiments.sqlite3")
        self._lock = RLock()
        self._initialized = False

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(str(self.path), timeout=30)
        db.row_factory = sqlite3.Row
        return db

    def _init(self, db):
        if not self._initialized:
            db.execute("CREATE TABLE IF NOT EXISTS experiments (experiment_id TEXT PRIMARY KEY, result_json TEXT NOT NULL, created_at TEXT NOT NULL)")
            self._initialized = True

    def save(self, result: ExperimentResult) -> None:
        with self._lock, self._connect() as db:
            self._init(db)
            db.execute("INSERT INTO experiments(experiment_id,result_json,created_at) VALUES(?,?,?)", (result.experiment_id, result.model_dump_json(), result.created_at.isoformat()))

    def get(self, experiment_id: str) -> ExperimentResult | None:
        with self._lock, self._connect() as db:
            self._init(db)
            row = db.execute("SELECT result_json FROM experiments WHERE experiment_id=?", (experiment_id,)).fetchone()
        return ExperimentResult.model_validate_json(row[0]) if row else None

    def list(self, limit: int, offset: int) -> tuple[list[ExperimentResult], int]:
        with self._lock, self._connect() as db:
            self._init(db)
            total = db.execute("SELECT COUNT(*) FROM experiments").fetchone()[0]
            rows = db.execute("SELECT result_json FROM experiments ORDER BY created_at DESC,experiment_id LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return [ExperimentResult.model_validate_json(row[0]) for row in rows], total
