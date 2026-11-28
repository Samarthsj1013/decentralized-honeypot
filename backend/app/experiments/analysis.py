"""Paired, scenario-cluster analysis for stored synthetic experiment results."""

from __future__ import annotations

import json
import random
import statistics
from collections import defaultdict
from pathlib import Path


def analyze_paired_comparison(path: Path, *, bootstrap_samples: int = 20_000, seed: int = 20301128) -> dict:
    """Analyze paired run results without treating repetitions as scenarios."""
    if type(bootstrap_samples) is not int or not 100 <= bootstrap_samples <= 1_000_000:
        raise ValueError("bootstrap_samples must be between 100 and 1000000")
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError("seed must be an unsigned 32-bit integer")
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data["scenario_results"]
    scenarios = data["scenarios"]
    repetitions = data["repetitions"]
    modes = data["modes"]
    indexed = {(row["scenario"], row["repetition"], row["mode"]): row for row in rows}
    expected = len(scenarios) * repetitions * len(modes)
    if len(indexed) != expected or len(scenarios) != len(set(scenarios)) or len(modes) != len(set(modes)):
        raise ValueError("input must contain exactly one unique row per scenario/repetition/mode")
    if not all(row.get("completed") for row in rows):
        raise ValueError("input contains incomplete runs")

    comparisons = {}
    for metric, getter in {
        "engagement": lambda row: int(bool(row["simulated_attacker_engaged"])) if row.get("simulated_attacker_engaged") is not None else None,
        "detection_coverage": lambda row: row["true_positives"] / row["suspicious_events"] if row.get("true_positives") is not None and row.get("suspicious_events") else None,
    }.items():
        metric_result = {}
        for left, right in (("baseline", "adaptive"), ("adaptive", "closed_loop"), ("baseline", "closed_loop")):
            if left not in modes or right not in modes:
                continue
            grouped = defaultdict(list)
            scenario_deltas = {}
            for scenario in scenarios:
                values = []
                for repetition in range(1, repetitions + 1):
                    a = getter(indexed[(scenario, repetition, left)])
                    b = getter(indexed[(scenario, repetition, right)])
                    if a is not None and b is not None:
                        values.append(float(b) - float(a))
                grouped[scenario] = values
                scenario_deltas[scenario] = statistics.mean(values) if values else None
            observations = [value for values in grouped.values() for value in values]
            rng = random.Random(seed)
            bootstrap = []
            for _ in range(bootstrap_samples):
                chosen_scenarios = [rng.choice(scenarios) for _ in scenarios]
                chosen = [value for scenario in chosen_scenarios for value in grouped[scenario]]
                if chosen:
                    bootstrap.append(statistics.mean(chosen))
            bootstrap.sort()
            metric_result[f"{left}_to_{right}"] = {
                "paired_run_count": len(observations),
                "mean_paired_delta": statistics.mean(observations) if observations else None,
                "scenario_cluster_bootstrap_95_ci": [bootstrap[int(.025 * (len(bootstrap) - 1))], bootstrap[int(.975 * (len(bootstrap) - 1))]] if bootstrap else None,
                "scenario_mean_deltas": scenario_deltas,
            }
        comparisons[metric] = metric_result
    return {
        "schema_version": 1,
        "source_experiment_id": data["experiment_id"],
        "paired_run_count_per_mode_pair": len(scenarios) * repetitions,
        "bootstrap": {"method": "resample scenario clusters with replacement; retain within-scenario repetitions", "samples": bootstrap_samples, "seed": seed},
        "comparisons": comparisons,
        "limitations": ["Runs and labels are synthetic; intervals quantify variation under this scenario generator only.", "Few scenario clusters yield coarse uncertainty intervals; they do not generalize to real attackers."],
    }
