"""Leakage-aware evaluation helpers for synthetic profile classifiers.

Every label evaluated here is emitted by ``generate_synthetic_dataset``. The
result is a reproducible check of the generator's category boundaries, not a
measurement of real-world attack detection.
"""

from __future__ import annotations

from typing import Any
from time import perf_counter

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from app.profiling.features import FEATURE_COLUMNS
from app.profiling.models_ml import BEHAVIOR_CATEGORIES, generate_synthetic_dataset


def evidence_rule_category(row: dict[str, int | float]) -> str:
    """Apply explicit class-defining thresholds as a simple baseline."""
    if row.get("failed_auth_count", 0) >= 3 and row.get("unique_usernames_attempted", 0) >= 2:
        return "authentication_probing"
    if row.get("event_count", 0) >= 12 and row.get("connection_count", 0) >= 10:
        return "repeated_connection"
    if row.get("connection_count", 0) >= 5 and row.get("unique_destination_ports", 0) >= 3:
        return "reconnaissance"
    if row.get("command_attempt_count", 0) >= 3:
        return "suspicious_session"
    if row.get("unique_protocol_count", 0) >= 3:
        return "multi_protocol"
    return "unknown"


def classification_metrics(
    actual: list[str],
    predicted: list[str],
    labels: list[str],
    probabilities: np.ndarray | None = None,
    probability_labels: list[str] | None = None,
) -> dict[str, Any]:
    """Return class metrics with undefined rates represented as null."""
    if not actual or len(actual) != len(predicted):
        raise ValueError("actual and predicted labels must have the same non-zero length")
    if not labels or len(labels) != len(set(labels)):
        raise ValueError("labels must be non-empty and unique")
    if not set(actual).issubset(labels) or not set(predicted).issubset(labels):
        raise ValueError("actual and predicted categories must be allowlisted")
    matrix = confusion_matrix(actual, predicted, labels=labels)
    total = int(matrix.sum())
    per_category: dict[str, dict[str, Any]] = {}
    for index, label in enumerate(labels):
        tp = int(matrix[index, index])
        fn = int(matrix[index, :].sum() - tp)
        fp = int(matrix[:, index].sum() - tp)
        tn = total - tp - fn - fp
        positive = tp + fn
        negative = fp + tn
        predicted_positive = tp + fp
        per_category[label] = {
            "support": positive,
            "precision": tp / predicted_positive if predicted_positive else None,
            "recall": tp / positive if positive else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
            "false_positive_rate": fp / negative if negative else None,
            "false_negative_rate": fn / positive if positive else None,
        }

    result: dict[str, Any] = {
        "samples": total,
        "accuracy": float(accuracy_score(actual, predicted)),
        "balanced_accuracy": None,
        "macro_precision": None,
        "macro_recall": None,
        "macro_false_positive_rate_ovr": None,
        "macro_false_negative_rate_ovr": None,
        "macro_f1": float(f1_score(actual, predicted, labels=labels, average="macro", zero_division=0)),
        "per_category": per_category,
        "confusion_matrix_labels": labels,
        "confusion_matrix": matrix.tolist(),
        "macro_roc_auc_ovr": None,
        "macro_average_precision_ovr": None,
    }
    # Use per-class values to calculate macro precision/recall while retaining
    # null for categories with no support/predictions instead of fabricating 0.
    precision_values = [item["precision"] for item in per_category.values() if item["precision"] is not None]
    recall_values = [item["recall"] for item in per_category.values() if item["recall"] is not None]
    false_positive_rates = [item["false_positive_rate"] for item in per_category.values() if item["false_positive_rate"] is not None]
    false_negative_rates = [item["false_negative_rate"] for item in per_category.values() if item["false_negative_rate"] is not None]
    result["macro_precision"] = float(np.mean(precision_values)) if precision_values else None
    result["macro_recall"] = float(np.mean(recall_values)) if recall_values else None
    result["balanced_accuracy"] = result["macro_recall"]
    result["macro_false_positive_rate_ovr"] = float(np.mean(false_positive_rates)) if false_positive_rates else None
    result["macro_false_negative_rate_ovr"] = float(np.mean(false_negative_rates)) if false_negative_rates else None

    if probabilities is not None and probability_labels is not None:
        from sklearn.metrics import average_precision_score, roc_auc_score
        from sklearn.preprocessing import label_binarize

        probability_array = np.asarray(probabilities, dtype=np.float64)
        if probability_array.shape != (total, len(probability_labels)):
            raise ValueError("probability matrix does not match labels and sample count")
        if set(probability_labels) != set(labels):
            raise ValueError("probability categories do not match evaluation labels")
        column_indexes = [probability_labels.index(label) for label in labels]
        probability_array = probability_array[:, column_indexes]
        binary_actual = label_binarize(actual, classes=labels)
        if binary_actual.shape[1] == len(labels) and all(binary_actual.sum(axis=0)):
            result["macro_roc_auc_ovr"] = float(roc_auc_score(binary_actual, probability_array, average="macro", multi_class="ovr"))
            result["macro_average_precision_ovr"] = float(average_precision_score(binary_actual, probability_array, average="macro"))
    return result


def _matrix(rows: list[dict[str, float]]) -> np.ndarray:
    return np.asarray([[row[name] for name in FEATURE_COLUMNS] for row in rows], dtype=np.float64)


def _candidates(family: str, seed: int):
    if family == "random_forest":
        for estimators in (80, 160):
            for leaf in (1, 2):
                yield {"n_estimators": estimators, "min_samples_leaf": leaf}, RandomForestClassifier(
                    n_estimators=estimators, min_samples_leaf=leaf, class_weight="balanced",
                    random_state=seed, n_jobs=1,
                )
    elif family == "decision_tree":
        for depth in (4, 8, None):
            for leaf in (1, 3):
                yield {"max_depth": depth, "min_samples_leaf": leaf}, DecisionTreeClassifier(
                    max_depth=depth, min_samples_leaf=leaf, class_weight="balanced", random_state=seed,
                )
    elif family == "logistic_regression":
        for regularization in (0.1, 1.0, 10.0):
            yield {"C": regularization}, make_pipeline(
                StandardScaler(),
                LogisticRegression(C=regularization, max_iter=2000, class_weight="balanced", random_state=seed),
            )
    else:
        raise ValueError("unsupported model family")


def evaluate_synthetic_profile_models(
    *, samples_per_category: int = 200, train_seed: int = 20261127,
    validation_seed: int = 20261128, test_seed: int = 20261129,
) -> dict[str, Any]:
    """Tune on generated validation data and report an independent generated test set.

    Train, validation, and test rows are generated from separate seeds rather
    than splitting one fixed table. This avoids row reuse but still tests only
    the same synthetic label generator.
    """
    seeds = (train_seed, validation_seed, test_seed)
    if any(type(seed) is not int or not 0 <= seed <= 2**32 - 1 for seed in seeds):
        raise ValueError("seeds must be unsigned 32-bit integers")
    if len(set(seeds)) != len(seeds):
        raise ValueError("train, validation, and test seeds must be distinct")
    train_rows, train_labels = generate_synthetic_dataset(samples_per_category, train_seed)
    validation_rows, validation_labels = generate_synthetic_dataset(samples_per_category, validation_seed)
    test_rows, test_labels = generate_synthetic_dataset(samples_per_category, test_seed)
    split_rows = {"train": train_rows, "validation": validation_rows, "test": test_rows}
    split_labels = {"train": train_labels, "validation": validation_labels, "test": test_labels}
    feature_label_maps: dict[str, dict[tuple[float, ...], set[str]]] = {}
    within_split_conflicts = {}
    for name in split_rows:
        label_map: dict[tuple[float, ...], set[str]] = {}
        for row, label in zip(split_rows[name], split_labels[name], strict=True):
            label_map.setdefault(tuple(row[column] for column in FEATURE_COLUMNS), set()).add(label)
        feature_label_maps[name] = label_map
        within_split_conflicts[name] = sum(len(labels) > 1 for labels in label_map.values())
    overlap_pairs = {}
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        shared = set(feature_label_maps[left]) & set(feature_label_maps[right])
        overlap_pairs[f"{left}_{right}"] = {
            "shared_feature_vectors": len(shared),
            "shared_vectors_with_label_conflict": sum(
                feature_label_maps[left][key].isdisjoint(feature_label_maps[right][key])
                for key in shared
            ),
        }
    x_train, x_validation, x_test = map(_matrix, (train_rows, validation_rows, test_rows))
    y_train, y_validation = np.asarray(train_labels), np.asarray(validation_labels)
    y_test = test_labels
    family_results: dict[str, Any] = {}

    for family in ("random_forest", "decision_tree", "logistic_regression"):
        best: tuple[float, dict[str, Any], Any] | None = None
        validation_trials = []
        for parameters, candidate in _candidates(family, train_seed):
            candidate.fit(x_train, y_train)
            validation_prediction = candidate.predict(x_validation)
            score = float(f1_score(y_validation, validation_prediction, labels=list(BEHAVIOR_CATEGORIES), average="macro", zero_division=0))
            validation_trials.append({"parameters": parameters, "macro_f1": score})
            if best is None or score > best[0]:
                best = (score, parameters, candidate)
        assert best is not None
        combined_x = np.concatenate((x_train, x_validation), axis=0)
        combined_y = np.concatenate((y_train, y_validation), axis=0)
        parameters = best[1]
        final_model = next(model for candidate_parameters, model in _candidates(family, train_seed) if candidate_parameters == parameters)
        fit_started = perf_counter()
        final_model.fit(combined_x, combined_y)
        fit_seconds = perf_counter() - fit_started
        prediction_started = perf_counter()
        test_prediction = final_model.predict(x_test)
        probabilities = final_model.predict_proba(x_test)
        inference_seconds = perf_counter() - prediction_started
        family_results[family] = {
            "validation_selection": {
                "selected_parameters": parameters,
                "selected_macro_f1": best[0],
                "trials": validation_trials,
            },
            "test_metrics": classification_metrics(
                y_test, list(test_prediction), list(BEHAVIOR_CATEGORIES),
                np.asarray(probabilities), list(final_model.classes_),
            ),
            "timing_seconds": {
                "refit_train_plus_validation": round(fit_seconds, 6),
                "vectorized_test_prediction": round(inference_seconds, 6),
            },
        }

    rule_predictions = [evidence_rule_category(row) for row in test_rows]
    family_results["evidence_rules"] = {
        "description": "Fixed class-defining feature thresholds; no data-fitted parameters.",
        "test_metrics": classification_metrics(y_test, rule_predictions, list(BEHAVIOR_CATEGORIES)),
        "timing_seconds": {"fit": 0.0},
    }
    return {
        "schema_version": 1,
        "evaluation_kind": "synthetic_label_holdout",
        "label_source": "generate_synthetic_dataset explicit category labels",
        "category_labels_are_ground_truth_for_real_telemetry": False,
        "seed_plan": {"train": train_seed, "validation": validation_seed, "test": test_seed},
        "samples_per_category_per_split": samples_per_category,
        "split_sizes": {
            "train": len(train_labels), "validation": len(validation_labels), "test": len(test_labels),
            "train_plus_validation_refit": len(train_labels) + len(validation_labels),
        },
        "feature_overlap_audit": {
            "unique_rows_per_split": {name: len(feature_label_maps[name]) for name in feature_label_maps},
            "within_split_vectors_with_label_conflicts": within_split_conflicts,
            "exact_cross_split_collisions": overlap_pairs,
            "interpretation": "Exact feature collisions can occur across independently seeded generator splits; counts and label conflicts are reported to make this limitation visible.",
        },
        "selection_method": "Per-family macro F1 on independent generated validation rows; refit selected parameters on train plus validation; report once on independent generated test rows.",
        "models": family_results,
        "limitations": [
            "All train, validation, and test rows come from the same synthetic generator; metrics do not estimate real-world detection performance.",
            "The real CyberLab sample has no trusted behavioral labels and is evaluated only as an unlabeled distribution review.",
            "Model probability outputs and vote fractions are not calibrated risk probabilities.",
            "Timing is machine-dependent and excludes dataset discovery/download.",
        ],
    }
