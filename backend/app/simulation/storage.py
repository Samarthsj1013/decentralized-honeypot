import json
import sqlite3
from pathlib import Path
from threading import Lock

from app.simulation.models import SimulationRunSummary


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATABASE_PATH = PROJECT_ROOT / "data" / "simulation_runs.sqlite3"


class SQLiteSimulationStorage:
    """Persist completed synthetic simulation summaries."""

    def __init__(self, database_path: str | Path = DATABASE_PATH) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.database_path), timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simulation_runs (
                    simulation_id TEXT PRIMARY KEY,
                    actor_id TEXT NOT NULL UNIQUE,
                    summary TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

    def get(self, simulation_id: str) -> SimulationRunSummary | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT summary FROM simulation_runs WHERE simulation_id = ?",
                (simulation_id,),
            ).fetchone()

        if row is None:
            return None
        return SimulationRunSummary.model_validate(json.loads(row["summary"]))

    def actor_has_run(self, actor_id: str) -> bool:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM simulation_runs WHERE actor_id = ? LIMIT 1",
                (actor_id,),
            ).fetchone()
        return row is not None

    def save(self, summary: SimulationRunSummary) -> None:
        payload = summary.model_dump_json()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO simulation_runs(
                    simulation_id, actor_id, summary, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    summary.simulation_id,
                    summary.actor_id,
                    payload,
                    summary.started_at.isoformat(),
                ),
            )
