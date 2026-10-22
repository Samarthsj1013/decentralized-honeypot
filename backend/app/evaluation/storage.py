import json
import sqlite3
from pathlib import Path
from threading import Lock

from app.evaluation.models import EvaluationSummary


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATABASE_PATH = PROJECT_ROOT / "data" / "evaluation_runs.sqlite3"


class SQLiteEvaluationStorage:
    """Persist evaluation summaries in an evaluation-specific SQLite file."""

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
                CREATE TABLE IF NOT EXISTS evaluations (
                    evaluation_id TEXT PRIMARY KEY,
                    summary TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

    def get(self, evaluation_id: str) -> EvaluationSummary | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT summary FROM evaluations WHERE evaluation_id = ?",
                (evaluation_id,),
            ).fetchone()

        if row is None:
            return None
        return EvaluationSummary.model_validate(json.loads(row["summary"]))

    def save(self, summary: EvaluationSummary) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO evaluations(evaluation_id, summary, created_at)
                VALUES (?, ?, ?)
                """,
                (
                    summary.evaluation_id,
                    summary.model_dump_json(),
                    summary.started_at.isoformat(),
                ),
            )
