
import json
import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any


class SQLiteLedgerStorage:
    """Persist ledger entries in a local SQLite database."""

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
                CREATE TABLE IF NOT EXISTS ledger_entries (
                    sequence INTEGER PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    event_data TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    ledger_version TEXT NOT NULL
                )
                """
            )

    def load_entries(self) -> list[dict[str, Any]]:
        """Load persisted entries in their original sequence."""
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT sequence, event_id, event_data,
                       previous_hash, entry_hash, ledger_version
                FROM ledger_entries
                ORDER BY sequence ASC
                """
            ).fetchall()

        entries = []

        for row in rows:
            entries.append(
                {
                    "sequence": row["sequence"],
                    "event_id": row["event_id"],
                    "event_data": json.loads(row["event_data"]),
                    "previous_hash": row["previous_hash"],
                    "entry_hash": row["entry_hash"],
                    "ledger_version": row["ledger_version"],
                }
            )

        return entries

    def append_entry(self, entry: dict[str, Any]) -> None:
        """Persist a ledger entry."""
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO ledger_entries (
                    sequence, event_id, event_data,
                    previous_hash, entry_hash, ledger_version
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    entry["sequence"],
                    entry["event_id"],
                    json.dumps(
                        entry["event_data"],
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ),
                    entry["previous_hash"],
                    entry["entry_hash"],
                    entry["ledger_version"],
                ),
            )

    def clear(self) -> None:
        """Delete all stored entries. Intended for tests and development."""
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM ledger_entries")
