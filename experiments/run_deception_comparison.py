"""Run paired seeded deception experiments with an isolated temporary SQLite store."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.experiments.models import ExperimentRequest  # noqa: E402
from app.experiments.service import ExperimentService  # noqa: E402
from app.experiments.storage import ExperimentStorage  # noqa: E402
from app.simulation.adversary import SCENARIOS  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New JSON artifact path; existing files are not overwritten")
    parser.add_argument("--seed", type=int, default=20261127)
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("output file already exists; choose a new path")
    request = ExperimentRequest(
        experiment_id="dahin-paired-20261127",
        scenarios=list(SCENARIOS),
        repetitions=args.repetitions,
        seed=args.seed,
        modes=["baseline", "adaptive", "closed_loop"],
    )
    with tempfile.TemporaryDirectory(prefix="dahin-paired-experiment-") as directory:
        storage = ExperimentStorage(Path(directory) / "experiments.sqlite3")
        result = ExperimentService(storage).run(request)
    artifact = result.model_dump(mode="json")
    artifact["created_at_utc"] = datetime.now(timezone.utc).isoformat()
    artifact["evaluation_scope"] = "Seeded synthetic scenarios only; not operational detection or defense effectiveness."
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "experiment_id": result.experiment_id,
        "scenario_count": len(result.scenarios),
        "repetitions": result.repetitions,
        "run_count": len(result.scenario_results),
        "mode_metrics": [row.model_dump(mode="json") for row in result.mode_metrics],
        "comparison": result.comparison.model_dump(mode="json"),
        "database_lifetime": "temporary directory removed after successful run",
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
