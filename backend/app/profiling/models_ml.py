"""Reproducible synthetic training and inference models for profile v1."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from app.profiling.features import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION


MODEL_ARTIFACT_VERSION = 1
MODEL_VERSION = "attacker-profile-synthetic-v1"
BEHAVIOR_CATEGORIES = (
    "reconnaissance", "authentication_probing", "repeated_connection",
    "suspicious_session", "multi_protocol", "unknown",
)


class ProfileModelError(ValueError):
    """A locally generated behavior model is missing or incompatible."""


def generate_synthetic_dataset(samples_per_category: int = 80, random_seed: int = 2026) -> tuple[list[dict[str, float]], list[str]]:
    """Create explicit synthetic labels; this function never labels real telemetry."""
    if type(samples_per_category) is not int or not 10 <= samples_per_category <= 2000:
        raise ValueError("samples_per_category must be between 10 and 2000")
    if type(random_seed) is not int or not 0 <= random_seed <= 2**32 - 1:
        raise ValueError("random_seed must be an integer between 0 and 4294967295")
    rng = np.random.default_rng(random_seed)
    rows: list[dict[str, float]] = []
    labels: list[str] = []
    for category in BEHAVIOR_CATEGORIES:
        for _ in range(samples_per_category):
            row = {name: 0.0 for name in FEATURE_COLUMNS}
            row["event_count"] = float(rng.integers(1, 8))
            row["protocol_other_count"] = row["event_count"]
            if category == "reconnaissance":
                row.update(connection_count=float(rng.integers(5, 35)), unique_destination_ports=float(rng.integers(3, 18)), protocol_tcp_count=float(rng.integers(5, 35)), protocol_other_count=0.0)
            elif category == "authentication_probing":
                row.update(failed_auth_count=float(rng.integers(3, 28)), unique_usernames_attempted=float(rng.integers(2, 20)), session_count=float(rng.integers(1, 9)), protocol_ssh_count=float(rng.integers(3, 28)), protocol_other_count=0.0)
            elif category == "repeated_connection":
                row.update(event_count=float(rng.integers(12, 60)), connection_count=float(rng.integers(10, 55)), connections_per_minute=float(rng.uniform(4, 55)), unique_destination_ports=float(rng.integers(1, 5)), protocol_tcp_count=float(rng.integers(8, 50)), protocol_other_count=0.0)
            elif category == "suspicious_session":
                row.update(event_count=float(rng.integers(5, 30)), session_count=float(rng.integers(1, 6)), command_attempt_count=float(rng.integers(3, 24)), mean_session_duration_seconds=float(rng.uniform(10, 900)), session_duration_available=1.0, protocol_ssh_count=float(rng.integers(4, 25)), protocol_other_count=0.0)
            elif category == "multi_protocol":
                row.update(event_count=float(rng.integers(8, 40)), sensor_count=float(rng.integers(2, 6)), unique_protocol_count=float(rng.integers(3, 5)), protocol_tcp_count=float(rng.integers(1, 15)), protocol_udp_count=float(rng.integers(1, 15)), protocol_icmp_count=float(rng.integers(1, 12)), protocol_ssh_count=float(rng.integers(1, 12)), protocol_other_count=0.0, behavioral_diversity=float(rng.uniform(.45, 1)))
            elif category == "unknown":
                row.update(event_count=float(rng.integers(1, 4)), protocol_other_count=float(row["event_count"]), unique_protocol_count=1.0)
            row["suricata_alert_count"] = float(rng.integers(0, 5) if category in {"reconnaissance", "multi_protocol"} else rng.integers(0, 2))
            row["alert_severity_medium"] = row["suricata_alert_count"]
            row["unique_protocol_count"] = max(row["unique_protocol_count"], float(sum(row[f"protocol_{proto}_count"] > 0 for proto in ("ssh", "tcp", "udp", "icmp"))))
            row["sensor_count"] = max(row["sensor_count"], 1.0)
            rows.append(row)
            labels.append(category)
    return rows, labels


def train_profile_models(samples_per_category: int = 80, random_seed: int = 2026) -> dict[str, Any]:
    """Train RF labels, IsolationForest anomaly baseline, and KMeans clusters on synthetic rows."""
    rows, labels = generate_synthetic_dataset(samples_per_category, random_seed)
    matrix = np.asarray([[row[name] for name in FEATURE_COLUMNS] for row in rows], dtype=np.float64)
    scaler = StandardScaler().fit(matrix)
    scaled = scaler.transform(matrix)
    classifier = RandomForestClassifier(n_estimators=160, class_weight="balanced", random_state=random_seed, n_jobs=1, min_samples_leaf=2)
    classifier.fit(matrix, labels)
    anomaly = IsolationForest(n_estimators=150, contamination="auto", random_state=random_seed, n_jobs=1)
    anomaly.fit(scaled)
    clusterer = KMeans(n_clusters=5, n_init=10, random_state=random_seed)
    clusterer.fit(scaled)
    baseline_scores = anomaly.score_samples(scaled)
    metadata = {
        "artifact_version": MODEL_ARTIFACT_VERSION,
        "model_version": MODEL_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_columns": list(FEATURE_COLUMNS),
        "categories": list(BEHAVIOR_CATEGORIES),
        "training_source": "explicit_synthetic_labeled_dataset",
        "samples_per_category": samples_per_category,
        "training_sample_count": len(labels),
        "random_seed": random_seed,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "anomaly_baseline_p05": float(np.quantile(baseline_scores, .05)),
        "anomaly_baseline_p95": float(np.quantile(baseline_scores, .95)),
    }
    return {"metadata": metadata, "classifier": classifier, "scaler": scaler, "anomaly_detector": anomaly, "clusterer": clusterer}


def save_model_bundle(bundle: dict[str, Any], output_path: str | Path) -> Path:
    validate_model_bundle(bundle)
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, target)
    return target


def validate_model_bundle(bundle: Any) -> dict[str, Any]:
    if not isinstance(bundle, dict) or set(bundle) != {"metadata", "classifier", "scaler", "anomaly_detector", "clusterer"}:
        raise ProfileModelError("profile model artifact structure is invalid")
    metadata = bundle.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("artifact_version") != MODEL_ARTIFACT_VERSION or metadata.get("feature_schema_version") != FEATURE_SCHEMA_VERSION or metadata.get("feature_columns") != list(FEATURE_COLUMNS) or metadata.get("training_source") != "explicit_synthetic_labeled_dataset":
        raise ProfileModelError("profile model artifact metadata is unsupported")
    categories = metadata.get("categories")
    if metadata.get("model_version") != MODEL_VERSION or not isinstance(categories, list) or any(type(item) is not str for item in categories) or set(categories) != set(BEHAVIOR_CATEGORIES):
        raise ProfileModelError("profile model category or version metadata is unsupported")
    if not isinstance(bundle.get("classifier"), RandomForestClassifier) or not isinstance(bundle.get("scaler"), StandardScaler) or not isinstance(bundle.get("anomaly_detector"), IsolationForest) or not isinstance(bundle.get("clusterer"), KMeans):
        raise ProfileModelError("profile model artifact contains unexpected model types")
    if not hasattr(bundle["classifier"], "classes_") or bundle["classifier"].n_features_in_ != len(FEATURE_COLUMNS) or bundle["scaler"].n_features_in_ != len(FEATURE_COLUMNS) or bundle["anomaly_detector"].n_features_in_ != len(FEATURE_COLUMNS) or bundle["clusterer"].n_features_in_ != len(FEATURE_COLUMNS):
        raise ProfileModelError("profile model artifact is unfitted or has an incompatible feature width")
    try:
        p05 = float(metadata["anomaly_baseline_p05"])
        p95 = float(metadata["anomaly_baseline_p95"])
        sample_count = metadata["training_sample_count"]
        samples_per_category = metadata["samples_per_category"]
        if not np.isfinite(p05) or not np.isfinite(p95) or p95 < p05 or type(sample_count) is not int or sample_count < 60 or type(samples_per_category) is not int or samples_per_category < 10:
            raise ValueError
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ProfileModelError("profile model training or anomaly baseline metadata is invalid") from None
    return bundle


def load_model_bundle(path: str | Path) -> dict[str, Any]:
    try:
        bundle = joblib.load(Path(path))
    except Exception:
        raise ProfileModelError("profile model artifact could not be loaded") from None
    try:
        return validate_model_bundle(bundle)
    except ProfileModelError:
        raise
    except Exception:
        raise ProfileModelError("profile model artifact is malformed") from None


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Train synthetic-data attacker behavior profile models")
    parser.add_argument("--output", type=Path, required=True, help="Output path for a locally trusted joblib model artifact")
    parser.add_argument("--samples-per-category", type=int, default=80)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--dataset-output", type=Path, help="Optional CSV export of the synthetic labeled rows")
    args = parser.parse_args(argv)
    bundle = train_profile_models(args.samples_per_category, args.seed)
    save_model_bundle(bundle, args.output)
    if args.dataset_output:
        import csv
        rows, labels = generate_synthetic_dataset(args.samples_per_category, args.seed)
        args.dataset_output.parent.mkdir(parents=True, exist_ok=True)
        with args.dataset_output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=[*FEATURE_COLUMNS, "label"])
            writer.writeheader()
            writer.writerows({**row, "label": label} for row, label in zip(rows, labels))
    print(f"Saved {MODEL_VERSION} trained on {bundle['metadata']['training_sample_count']} explicitly synthetic rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
