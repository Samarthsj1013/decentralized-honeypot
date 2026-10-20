
"""Generate reproducible synthetic honeypot behavior scenarios.

These are simulated examples, not real network telemetry.
"""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


FEATURE_COLUMNS = [
    "event_count",
    "unique_decoys_accessed",
    "unique_actions",
    "login_attempts",
    "database_queries",
    "interactions_per_minute",
    "category_coverage",
]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "experiments" / "datasets" / "behavior_dataset.csv"


def generate_scenario(
    rng: np.random.Generator,
    suspicious: bool,
) -> dict[str, int | float | str]:
    """Generate one synthetic actor behavior scenario."""

    if suspicious:
        event_count = int(rng.integers(2, 16))
        unique_decoys = int(
            rng.integers(1, min(4, event_count + 1))
        )
        unique_actions = int(rng.integers(1, 5))

        login_attempts = int(
            rng.binomial(event_count, rng.uniform(0.10, 0.55))
        )
        database_queries = int(
            rng.binomial(event_count, rng.uniform(0.10, 0.50))
        )

        rate = float(rng.lognormal(mean=1.5, sigma=0.8))
        interactions_per_minute = min(rate, 40.0)

        category_coverage = int(
            rng.integers(1, min(4, unique_decoys + 1))
        )

        # Keep event counts consistent with the generated features.
        # Overlap with benign behavior is already introduced by the
        # shared ranges and the independent feature distributions.

    else:
        event_count = int(rng.integers(1, 9))
        unique_decoys = int(
            rng.integers(1, min(4, event_count + 1))
        )
        unique_actions = int(rng.integers(1, 4))

        login_attempts = int(
            rng.binomial(event_count, rng.uniform(0.0, 0.12))
        )
        database_queries = int(
            rng.binomial(event_count, rng.uniform(0.0, 0.12))
        )

        rate = float(rng.lognormal(mean=0.2, sigma=0.8))
        interactions_per_minute = min(rate, 20.0)

        category_coverage = int(
            rng.integers(1, min(4, unique_decoys + 1))
        )

        # Include some unusual benign scenarios to create overlap.
        if rng.random() < 0.15:
            event_count = int(rng.integers(5, 10))
            interactions_per_minute = float(
                rng.uniform(2.0, 10.0)
            )

    return {
        "event_count": event_count,
        "unique_decoys_accessed": unique_decoys,
        "unique_actions": unique_actions,
        "login_attempts": login_attempts,
        "database_queries": database_queries,
        "interactions_per_minute": round(
            interactions_per_minute, 4
        ),
        "category_coverage": category_coverage,
        "label": "suspicious" if suspicious else "benign",
    }


def generate_dataset(
    samples_per_class: int = 1500,
    seed: int = 42,
) -> pd.DataFrame:
    """Create a balanced dataset with a reproducible random seed."""

    if samples_per_class < 10:
        raise ValueError("samples_per_class must be at least 10")

    rng = np.random.default_rng(seed)

    rows = []

    for suspicious in (False, True):
        for _ in range(samples_per_class):
            rows.append(generate_scenario(rng, suspicious))

    dataset = pd.DataFrame(rows)
    dataset = dataset.sample(
        frac=1,
        random_state=seed,
    ).reset_index(drop=True)

    return dataset


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic honeypot behavior data."
    )
    parser.add_argument(
        "--samples-per-class",
        type=int,
        default=1500,
        help="Number of examples for each label.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Destination CSV path.",
    )

    args = parser.parse_args()

    dataset = generate_dataset(
        samples_per_class=args.samples_per_class,
        seed=args.seed,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_csv(args.output, index=False)

    print(f"Dataset saved to: {args.output}")
    print(f"Total scenarios: {len(dataset)}")
    print("\nLabel distribution:")
    print(dataset["label"].value_counts().to_string())
    print("\nFeature columns:")
    print(", ".join(FEATURE_COLUMNS))


if __name__ == "__main__":
    main()
