
import json
import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any


class SQLiteAdaptationStorage:
    """Persist adaptation decisions in a separate SQLite table."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database_path),
            timeout=30,
        )
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS adaptation_decisions (
                    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor_id TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    selected_strategy TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    observed_actions TEXT NOT NULL,
                    observed_decoys TEXT NOT NULL,
                    simulation_only INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_adaptation_actor_decision
                ON adaptation_decisions(actor_id, decision_id)
                """
            )

    def append_decision(self, decision: dict[str, Any]) -> dict[str, Any]:
        """Save a decision and return it with its ID and timestamp."""
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO adaptation_decisions (
                    actor_id,
                    event_count,
                    risk_level,
                    selected_strategy,
                    reason,
                    observed_actions,
                    observed_decoys,
                    simulation_only,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision["actor_id"],
                    decision["event_count"],
                    decision["risk_level"],
                    decision["selected_strategy"],
                    decision["reason"],
                    json.dumps(
                        decision["observed_actions"],
                        sort_keys=True,
                    ),
                    json.dumps(
                        decision["observed_decoys"],
                        sort_keys=True,
                    ),
                    int(decision["simulation_only"]),
                    decision["created_at"],
                ),
            )

            decision_id = cursor.lastrowid

        return {
            **decision,
            "decision_id": decision_id,
        }

    def list_decisions(
        self,
        actor_id: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return an actor's decisions from oldest to newest."""
        if limit < 1:
            raise ValueError("limit must be at least 1")

        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    decision_id,
                    actor_id,
                    event_count,
                    risk_level,
                    selected_strategy,
                    reason,
                    observed_actions,
                    observed_decoys,
                    simulation_only,
                    created_at
                FROM adaptation_decisions
                WHERE actor_id = ?
                ORDER BY decision_id DESC
                LIMIT ?
                """,
                (actor_id, limit),
            ).fetchall()

        decisions = []

        for row in reversed(rows):
            decisions.append(
                {
                    "decision_id": row["decision_id"],
                    "actor_id": row["actor_id"],
                    "event_count": row["event_count"],
                    "risk_level": row["risk_level"],
                    "selected_strategy": row["selected_strategy"],
                    "reason": row["reason"],
                    "observed_actions": json.loads(
                        row["observed_actions"]
                    ),
                    "observed_decoys": json.loads(
                        row["observed_decoys"]
                    ),
                    "simulation_only": bool(row["simulation_only"]),
                    "created_at": row["created_at"],
                }
            )

        return decisions
