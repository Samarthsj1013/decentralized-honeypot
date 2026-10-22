
import json
import sqlite3
from pathlib import Path
from threading import Lock
from datetime import datetime, timezone
from app.honeypot.generator import GeneratedDecoy


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATABASE_PATH = PROJECT_ROOT / "data" / "generated_decoys.sqlite3"


class GeneratedDecoyRegistry:
    """Persist generated synthetic decoys in a local SQLite database."""

    def __init__(self, database_path: Path | str = DATABASE_PATH) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._lock:
            with self._connect() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS generated_decoys (
                        decoy_id TEXT PRIMARY KEY,
                        actor_id TEXT NOT NULL,
                        decoy_type TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """
                )


    def save_many(
        self,
        decoys: list[GeneratedDecoy],
    ) -> list[GeneratedDecoy]:
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._connect() as connection:
                for decoy in decoys:
                    connection.execute(
                        """
                        INSERT INTO generated_decoys (
                            decoy_id,
                            actor_id,
                            decoy_type,
                            payload,
                            created_at
                        )
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(decoy_id) DO UPDATE SET
                            actor_id = excluded.actor_id,
                            decoy_type = excluded.decoy_type,
                            payload = excluded.payload
                        """,
                        (
                            decoy.decoy_id,
                            decoy.actor_id,
                            decoy.decoy_type,
                            json.dumps(decoy.model_dump()),
                            now,
                        ),
                    )

        return decoys


    def list_all(self) -> list[GeneratedDecoy]:
        with self._lock:
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM generated_decoys
                    ORDER BY rowid
                    """
                ).fetchall()

        return [
            GeneratedDecoy.model_validate(json.loads(row["payload"]))
            for row in rows
        ]

    def get(self, decoy_id: str) -> GeneratedDecoy | None:
        with self._lock:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT payload
                    FROM generated_decoys
                    WHERE decoy_id = ?
                    """,
                    (decoy_id,),
                ).fetchone()

        if row is None:
            return None

        return GeneratedDecoy.model_validate(json.loads(row["payload"]))


generated_decoy_registry = GeneratedDecoyRegistry()
