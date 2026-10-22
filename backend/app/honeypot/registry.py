
import json
import sqlite3
from pathlib import Path
from threading import Lock
from datetime import datetime, timezone
from app.honeypot.generator import GeneratedDecoy
from app.honeypot.bundles import BundleConsistencyValidator, SyntheticDecoyBundle


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
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS generated_bundles (
                        bundle_id TEXT PRIMARY KEY,
                        actor_id TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """CREATE INDEX IF NOT EXISTS idx_generated_bundle_actor
                       ON generated_bundles(actor_id, created_at)"""
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

    def save_bundle(
        self,
        bundle: SyntheticDecoyBundle,
        decoys: list[GeneratedDecoy],
    ) -> bool:
        """Atomically persist a validated bundle and its listable decoys.

        Returns False for an identical already stored bundle. ID collisions
        with different content are rejected rather than overwriting records.
        """
        validation = BundleConsistencyValidator().validate(bundle)
        if not validation.valid:
            raise ValueError(
                "Invalid synthetic bundle: "
                + ", ".join(issue.code for issue in validation.issues)
            )
        if any(decoy.actor_id != bundle.actor_id for decoy in decoys):
            raise ValueError("Bundle decoys must belong to the bundle actor")

        payload = bundle.model_dump_json()
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as connection:
            existing = connection.execute(
                "SELECT payload FROM generated_bundles WHERE bundle_id = ?",
                (bundle.bundle_id,),
            ).fetchone()
            if existing is not None:
                stored = SyntheticDecoyBundle.model_validate_json(existing["payload"])
                if stored.model_dump(mode="json") != bundle.model_dump(mode="json"):
                    raise ValueError("Bundle ID already exists with different content")
                for decoy in decoys:
                    row = connection.execute(
                        "SELECT payload FROM generated_decoys WHERE decoy_id = ?",
                        (decoy.decoy_id,),
                    ).fetchone()
                    candidate_payload = json.dumps(decoy.model_dump())
                    if row is None:
                        connection.execute(
                            """INSERT INTO generated_decoys
                               (decoy_id, actor_id, decoy_type, payload, created_at)
                               VALUES (?, ?, ?, ?, ?)""",
                            (decoy.decoy_id, decoy.actor_id, decoy.decoy_type,
                             candidate_payload, now),
                        )
                    elif json.loads(row["payload"]) != decoy.model_dump():
                        raise ValueError(
                            "Bundle asset ID already exists with different content"
                        )
                return False

            connection.execute(
                "INSERT INTO generated_bundles(bundle_id, actor_id, payload, created_at) "
                "VALUES (?, ?, ?, ?)",
                (bundle.bundle_id, bundle.actor_id, payload, now),
            )
            for decoy in decoys:
                connection.execute(
                    """INSERT INTO generated_decoys
                       (decoy_id, actor_id, decoy_type, payload, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (decoy.decoy_id, decoy.actor_id, decoy.decoy_type,
                     json.dumps(decoy.model_dump()), now),
                )
        return True

    def get_bundle(self, bundle_id: str) -> SyntheticDecoyBundle | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM generated_bundles WHERE bundle_id = ?",
                (bundle_id,),
            ).fetchone()
        return None if row is None else SyntheticDecoyBundle.model_validate_json(row["payload"])

    def list_bundles(self, actor_id: str | None = None) -> list[SyntheticDecoyBundle]:
        with self._lock, self._connect() as connection:
            if actor_id is None:
                rows = connection.execute(
                    "SELECT payload FROM generated_bundles ORDER BY rowid"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT payload FROM generated_bundles WHERE actor_id = ? ORDER BY rowid",
                    (actor_id,),
                ).fetchall()
        return [SyntheticDecoyBundle.model_validate_json(row["payload"]) for row in rows]


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
