from app.profiling.challenge import evaluate_challenge, generate_challenge_dataset
from app.profiling.features import FEATURE_COLUMNS
from app.profiling.models_ml import BEHAVIOR_CATEGORIES


def test_challenge_labels_are_balanced_and_features_reproducible():
    rows_a, labels_a = generate_challenge_dataset(samples_per_category=20, seed=31)
    rows_b, labels_b = generate_challenge_dataset(samples_per_category=20, seed=31)

    assert labels_a == labels_b
    assert rows_a == rows_b
    assert len(rows_a) == len(BEHAVIOR_CATEGORIES) * 20
    assert {label: labels_a.count(label) for label in BEHAVIOR_CATEGORIES} == {
        label: 20 for label in BEHAVIOR_CATEGORIES
    }
    assert all(tuple(row) == FEATURE_COLUMNS for row in rows_a)
    assert len({tuple(row[name] for name in FEATURE_COLUMNS) for row in rows_a}) > 20


def test_challenge_evaluation_compares_all_models_and_rules_on_same_rows():
    result = evaluate_challenge(samples_per_category=20, train_seed=41, test_seed=42)

    assert result["evaluation_kind"] == "independent_synthetic_shift_challenge"
    assert result["train_rows"] == result["test_rows"] == 120
    assert set(result["models"]) == {
        "random_forest", "decision_tree", "logistic_regression", "evidence_rules"
    }
    assert all(metrics["samples"] == 120 for metrics in result["models"].values())
    assert all(0 <= metrics["accuracy"] <= 1 for metrics in result["models"].values())
    assert all(0 <= metrics["macro_f1"] <= 1 for metrics in result["models"].values())
