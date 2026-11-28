"""Compare profile classifiers on seeded, independently generated synthetic splits."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.profiling.evaluation import evaluate_synthetic_profile_models  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New JSON result path; existing files are not overwritten")
    parser.add_argument("--samples-per-category", type=int, default=200)
    parser.add_argument("--train-seed", type=int, default=20261127)
    parser.add_argument("--validation-seed", type=int, default=20261128)
    parser.add_argument("--test-seed", type=int, default=20261129)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("output file already exists; choose a new path")
    result = evaluate_synthetic_profile_models(
        samples_per_category=args.samples_per_category,
        train_seed=args.train_seed,
        validation_seed=args.validation_seed,
        test_seed=args.test_seed,
    )
    result["created_at"] = datetime.now(timezone.utc).isoformat()
    result["model_candidates"] = {
        "random_forest": "n_estimators 80/160; min_samples_leaf 1/2; balanced classes",
        "decision_tree": "max_depth 4/8/unbounded; min_samples_leaf 1/3; balanced classes",
        "logistic_regression": "C 0.1/1/10; StandardScaler; balanced classes; max_iter 2000",
        "evidence_rules": "Fixed class-defining thresholds; no fitted parameters",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "samples_per_category_per_split": args.samples_per_category,
        "split_sizes": result["split_sizes"],
        "models": {
            name: {
                "macro_f1": entry["test_metrics"]["macro_f1"],
                "accuracy": entry["test_metrics"]["accuracy"],
                "macro_false_positive_rate_ovr": entry["test_metrics"]["macro_false_positive_rate_ovr"],
                "macro_false_negative_rate_ovr": entry["test_metrics"]["macro_false_negative_rate_ovr"],
            }
            for name, entry in result["models"].items()
        },
        "real_world_effectiveness_claimed": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
