"""Separate lazy SQLite persistence for pseudonymous profiles and recommendations."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from threading import RLock

from app.profiling.models import AttackerBehaviorProfile, DeceptionRecommendation


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "attacker_profiles.sqlite3"
PROFILE_HISTORY_LIMIT = 20


class SQLiteProfileStorage:
    def __init__(self, database_path: str | Path | None = None) -> None:
        configured = database_path or os.getenv("HONEYPOT_PROFILE_DB_PATH") or DEFAULT_DATABASE_PATH
        self.database_path = Path(configured)
        self._initialized = False
        self._lock = RLock()

    @contextmanager
    def _connect(self):
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.database_path), timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self, connection: sqlite3.Connection) -> None:
        if self._initialized:
            return
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS attacker_profiles (
                profile_id TEXT PRIMARY KEY,
                profile_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attacker_profile_history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_profile_history ON attacker_profile_history(profile_id, history_id DESC);
            CREATE TABLE IF NOT EXISTS deception_recommendations (
                recommendation_id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL,
                status TEXT NOT NULL,
                recommendation_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_recommendation_status ON deception_recommendations(status, updated_at DESC);
        """)
        self._initialized = True

    def upsert_profile(self, profile: AttackerBehaviorProfile) -> None:
        serialized = profile.model_dump_json()
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            existing = connection.execute("SELECT profile_json FROM attacker_profiles WHERE profile_id=?", (profile.profile_id,)).fetchone()
            connection.execute("INSERT INTO attacker_profiles(profile_id,profile_json,updated_at) VALUES(?,?,?) ON CONFLICT(profile_id) DO UPDATE SET profile_json=excluded.profile_json, updated_at=excluded.updated_at", (profile.profile_id, serialized, profile.last_observed.isoformat()))
            if existing is None or existing["profile_json"] != serialized:
                history = profile.history[-1] if profile.history else None
                if history is not None:
                    connection.execute("INSERT INTO attacker_profile_history(profile_id,snapshot_json,recorded_at) VALUES(?,?,?)", (profile.profile_id, history.model_dump_json(), history.recorded_at.isoformat()))
                    connection.execute("DELETE FROM attacker_profile_history WHERE profile_id=? AND history_id NOT IN (SELECT history_id FROM attacker_profile_history WHERE profile_id=? ORDER BY history_id DESC LIMIT ?)", (profile.profile_id, profile.profile_id, PROFILE_HISTORY_LIMIT))

    def list_profiles(self, limit: int, offset: int = 0) -> tuple[list[AttackerBehaviorProfile], int]:
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            total = connection.execute("SELECT COUNT(*) FROM attacker_profiles").fetchone()[0]
            rows = connection.execute("SELECT profile_json FROM attacker_profiles ORDER BY updated_at DESC, profile_id LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return [AttackerBehaviorProfile.model_validate_json(row["profile_json"]) for row in rows], total

    def get_profile(self, profile_id: str) -> AttackerBehaviorProfile | None:
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            row = connection.execute("SELECT profile_json FROM attacker_profiles WHERE profile_id=?", (profile_id,)).fetchone()
        return AttackerBehaviorProfile.model_validate_json(row["profile_json"]) if row else None

    def get_profile_history(self, profile_id: str):
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            rows = connection.execute("SELECT snapshot_json FROM attacker_profile_history WHERE profile_id=? ORDER BY history_id DESC LIMIT ?", (profile_id, PROFILE_HISTORY_LIMIT)).fetchall()
        return [json.loads(row["snapshot_json"]) for row in rows]

    def list_recommendations(self, limit: int = 100, offset: int = 0) -> tuple[list[DeceptionRecommendation], int]:
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            total = connection.execute("SELECT COUNT(*) FROM deception_recommendations").fetchone()[0]
            rows = connection.execute("SELECT recommendation_json FROM deception_recommendations ORDER BY updated_at DESC, recommendation_id LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return [DeceptionRecommendation.model_validate_json(row["recommendation_json"]) for row in rows], total

    def get_recommendation(self, recommendation_id: str) -> DeceptionRecommendation | None:
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            row = connection.execute("SELECT recommendation_json FROM deception_recommendations WHERE recommendation_id=?", (recommendation_id,)).fetchone()
        return DeceptionRecommendation.model_validate_json(row["recommendation_json"]) if row else None

    def add_recommendation(self, recommendation: DeceptionRecommendation) -> bool:
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            cursor = connection.execute("INSERT OR IGNORE INTO deception_recommendations(recommendation_id,profile_id,status,recommendation_json,updated_at) VALUES(?,?,?,?,?)", (recommendation.recommendation_id, recommendation.profile_id, recommendation.status, recommendation.model_dump_json(), recommendation.status_history[-1].changed_at.isoformat()))
            return cursor.rowcount == 1

    def update_recommendation(self, recommendation: DeceptionRecommendation, *, allowed_states: tuple[str, ...]) -> bool:
        placeholders = ",".join("?" for _ in allowed_states)
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            cursor = connection.execute(f"UPDATE deception_recommendations SET status=?, recommendation_json=?, updated_at=? WHERE recommendation_id=? AND status IN ({placeholders})", (recommendation.status, recommendation.model_dump_json(), recommendation.status_history[-1].changed_at.isoformat(), recommendation.recommendation_id, *allowed_states))
            return cursor.rowcount == 1

    def stats(self) -> list[dict]:
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            rows = connection.execute("SELECT profile_json FROM attacker_profiles").fetchall()
        return [json.loads(row["profile_json"]) for row in rows]
