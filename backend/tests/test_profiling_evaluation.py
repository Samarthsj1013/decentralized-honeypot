from __future__ import annotations

import numpy as np
import pytest

from app.profiling.evaluation import classification_metrics, evidence_rule_category


def test_classification_metrics_calculate_one_vs_rest_false_positive_and_negative_rates():
    result = classification_metrics(
        ["a", "a", "b", "b"], ["a", "b", "b", "a"], ["a", "b"]
    )

    assert result["accuracy"] == 0.5
    assert result["per_category"]["a"]["false_positive_rate"] == 0.5
    assert result["per_category"]["a"]["false_negative_rate"] == 0.5
    assert result["macro_false_positive_rate_ovr"] == 0.5
    assert result["macro_false_negative_rate_ovr"] == 0.5
    assert result["macro_roc_auc_ovr"] is None


def test_classification_metrics_keep_undefined_positive_rate_unavailable():
    result = classification_metrics(["a", "a"], ["a", "a"], ["a", "b"])

    assert result["per_category"]["b"]["support"] == 0
    assert result["per_category"]["b"]["false_negative_rate"] is None
    assert result["per_category"]["b"]["false_positive_rate"] == 0


def test_classification_metrics_validate_probability_shape_and_category_domain():
    with pytest.raises(ValueError, match="probability matrix"):
        classification_metrics(["a", "b"], ["a", "b"], ["a", "b"], np.zeros((2, 2)), ["a", "b", "c"])
    with pytest.raises(ValueError, match="allowlisted"):
        classification_metrics(["a", "c"], ["a", "c"], ["a", "b"])


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        ({"failed_auth_count": 3, "unique_usernames_attempted": 2}, "authentication_probing"),
        ({"event_count": 12, "connection_count": 10}, "repeated_connection"),
        ({"connection_count": 5, "unique_destination_ports": 3}, "reconnaissance"),
        ({"command_attempt_count": 3}, "suspicious_session"),
        ({"unique_protocol_count": 3}, "multi_protocol"),
        ({}, "unknown"),
    ],
)
def test_evidence_rule_baseline_uses_explicit_feature_gates(row, expected):
    assert evidence_rule_category(row) == expected


def test_synthetic_evaluation_requires_distinct_unsigned_seeds():
    from app.profiling.evaluation import evaluate_synthetic_profile_models

    with pytest.raises(ValueError, match="distinct"):
        evaluate_synthetic_profile_models(samples_per_category=10, train_seed=1, validation_seed=1, test_seed=2)


def test_synthetic_evaluation_reports_exact_feature_overlap_between_seeded_splits():
    from app.profiling.evaluation import evaluate_synthetic_profile_models

    result = evaluate_synthetic_profile_models(
        samples_per_category=10, train_seed=101, validation_seed=102, test_seed=103
    )

    audit = result["feature_overlap_audit"]
    assert set(audit["unique_rows_per_split"]) == {"train", "validation", "test"}
    assert set(audit["exact_cross_split_collisions"]) == {
        "train_validation", "train_test", "validation_test"
    }
    assert all(value == 0 for value in audit["within_split_vectors_with_label_conflicts"].values())
    assert all(
        row["shared_vectors_with_label_conflict"] == 0
        for row in audit["exact_cross_split_collisions"].values()
    )
