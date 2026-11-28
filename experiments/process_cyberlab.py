"""Create a privacy-filtered, unlabeled session feature export from CyberLab."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.experiments.real_cowrie import DatasetValidationError, process_cyberlab_archive  # noqa: E402
from app.profiling.models_ml import train_profile_models  # noqa: E402
from app.profiling.service import AttackerProfileService  # noqa: E402


ZENODO_RECORD = "https://zenodo.org/records/3687527"
SOURCE_DOI = "10.5281/zenodo.3687527"
SOURCE_LICENSE = "CC-BY-4.0"
SAMPLE_NAME = "cyberlab_2019-05-18.json.gz"
SAMPLE_URL = "https://zenodo.org/api/records/3687527/files/cyberlab_2019-05-18.json.gz/content"
SAMPLE_MD5 = "6428bc0c9e4c83eecd78a1c01728f171"


def _quantiles(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"median": None, "p05": None, "p95": None}
    ordered = sorted(values)

    def at(fraction: float) -> float:
        position = (len(ordered) - 1) * fraction
        lower = int(position)
        upper = min(lower + 1, len(ordered) - 1)
        weight = position - lower
        return ordered[lower] * (1 - weight) + ordered[upper] * weight

    return {"median": statistics.median(ordered), "p05": at(.05), "p95": at(.95)}


def analyze_archive(input_path: Path) -> tuple[list[dict], dict]:
    features, stats = process_cyberlab_archive(input_path)
    bundle = train_profile_models(samples_per_category=80, random_seed=2026)
    columns = bundle["metadata"]["feature_columns"]
    raw_predictions: dict[str, int] = {}
    gated_predictions: dict[str, int] = {}
    matrix = np.asarray([[float(row[name]) for name in columns] for row in features], dtype=np.float64)
    predictions = bundle["classifier"].predict(matrix)
    probabilities = bundle["classifier"].predict_proba(matrix)
    vote_values: list[float] = []
    for row, predicted, probability_row in zip(features, predictions, probabilities, strict=True):
        prediction = str(predicted)
        vote = float(max(probability_row))
        gated = AttackerProfileService._classification_with_evidence_gate(
            prediction, row, int(row["event_count"])
        )
        raw_predictions[prediction] = raw_predictions.get(prediction, 0) + 1
        gated_predictions[gated] = gated_predictions.get(gated, 0) + 1
        vote_values.append(vote)
    summary = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "name": "CyberLab honeynet dataset, one daily Cowrie export",
            "record_url": ZENODO_RECORD,
            "doi": SOURCE_DOI,
            "license": SOURCE_LICENSE,
            "file": SAMPLE_NAME,
            "download_url": SAMPLE_URL,
            "published_md5": SAMPLE_MD5,
            "observed_md5": hashlib.md5(input_path.read_bytes()).hexdigest(),
            "observed_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
            "provenance": "Cowrie logs collected by the University of Ljubljana CyberLab honeynet from May 2019 to February 2020; source record describes approximately 50 university/company nodes and pseudonymized honeypot destination IPs.",
            "selection": "Smallest archive file in the record at metadata review time; a single date sample, not a representative or independent test set.",
        },
        **stats,
        "model_review": {
            "model_version": bundle["metadata"]["model_version"],
            "training_source": bundle["metadata"]["training_source"],
            "training_samples": bundle["metadata"]["training_sample_count"],
            "training_seed": bundle["metadata"]["random_seed"],
            "raw_synthetic_model_vote_counts_unlabeled": dict(sorted(raw_predictions.items())),
            "evidence_gated_category_counts_unlabeled": dict(sorted(gated_predictions.items())),
            "maximum_vote_fraction_descriptive_only": _quantiles(vote_values),
            "accuracy_precision_recall_f1": "Unavailable: the dataset has no trusted behavioral ground-truth labels.",
            "interpretation": "Model output counts are an unlabeled domain review only. The synthetic-trained model vote fraction is not calibrated confidence, and no category count is a verified attack label.",
        },
    }
    return features, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Local CyberLab .json.gz file; do not use attacker-provided data")
    parser.add_argument("--features-output", type=Path, help="Optional anonymous numeric per-session CSV; no session keys or text fields are included")
    parser.add_argument("--summary-output", type=Path, required=True, help="Aggregate JSON summary output path")
    args = parser.parse_args(argv)
    try:
        features, summary = analyze_archive(args.input)
    except DatasetValidationError as exc:
        parser.error(str(exc))
    args.summary_output.parent.mkdir(parents=True, exist_ok=True)
    args.summary_output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if args.features_output:
        from app.profiling.features import FEATURE_COLUMNS

        args.features_output.parent.mkdir(parents=True, exist_ok=True)
        with args.features_output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FEATURE_COLUMNS)
            writer.writeheader()
            writer.writerows(features)
    print(json.dumps({
        "summary_output": str(args.summary_output),
        "features_output": str(args.features_output) if args.features_output else None,
        "processed_sessions": summary["processed_sessions"],
        "raw_event_count": summary["raw_event_count"],
        "labels_available": summary["labels_available"],
        "evaluation_metrics": summary["model_review"]["accuracy_precision_recall_f1"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
