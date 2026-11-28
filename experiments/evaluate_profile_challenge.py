"""Evaluate fixed profile models on a separate synthetic shift challenge."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.profiling.challenge import evaluate_challenge  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New result file; existing files are not overwritten")
    parser.add_argument("--samples-per-category", type=int, default=120)
    parser.add_argument("--train-seed", type=int, default=20301127)
    parser.add_argument("--test-seed", type=int, default=20301128)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output file already exists; choose a new path")
    result = evaluate_challenge(
        samples_per_category=args.samples_per_category,
        train_seed=args.train_seed,
        test_seed=args.test_seed,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "train_rows": result["train_rows"],
        "test_rows": result["test_rows"],
        "unique_test_feature_rows": result["test_unique_feature_rows"],
        "models": {name: {"accuracy": row["accuracy"], "macro_f1": row["macro_f1"]} for name, row in result["models"].items()},
        "real_world_effectiveness_claimed": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
