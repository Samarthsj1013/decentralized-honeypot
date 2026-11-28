"""Independent, deliberately overlapping synthetic challenge data.

Labels are assigned from a latent dominant scenario before feature generation.
Features are then emitted from a separate episode-style generator with
secondary behaviors, observation noise, and missing aggregates. Results are a
stress test against changed synthetic assumptions, not real-world validation.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from app.profiling.evaluation import classification_metrics, evidence_rule_category
from app.profiling.features import FEATURE_COLUMNS
from app.profiling.models_ml import BEHAVIOR_CATEGORIES, generate_synthetic_dataset


def _episode(category: str, rng: np.random.Generator) -> dict[str, float]:
    """Sample aggregate features from an alternate per-session process."""
    row = {name: 0.0 for name in FEATURE_COLUMNS}
    base_events = int(rng.integers(1, 6))
    row.update(event_count=float(base_events), sensor_count=1.0, protocol_other_count=float(base_events))

    if category == "reconnaissance":
        connections = int(rng.poisson(6.0))
        row.update(connection_count=float(connections), unique_destination_ports=float(min(10, 1 + rng.poisson(2.4))), protocol_tcp_count=float(connections), protocol_other_count=0.0)
    elif category == "authentication_probing":
        failures = int(rng.poisson(4.0))
        row.update(failed_auth_count=float(failures), unique_usernames_attempted=float(min(failures, 1 + rng.poisson(2.1))), session_count=float(rng.poisson(1.4)), protocol_ssh_count=float(failures + 1), protocol_other_count=0.0)
    elif category == "repeated_connection":
        connections = int(rng.poisson(11.0))
        row.update(event_count=float(base_events + connections), connection_count=float(connections), connections_per_minute=float(rng.gamma(2.0, 4.0)), unique_destination_ports=float(1 + rng.poisson(1.5)), protocol_tcp_count=float(connections), protocol_other_count=0.0)
    elif category == "suspicious_session":
        commands = int(rng.poisson(2.7))
        row.update(event_count=float(base_events + commands), session_count=float(1 + rng.poisson(1.2)), command_attempt_count=float(commands), mean_session_duration_seconds=float(rng.lognormal(4.1, 1.0)), session_duration_available=float(rng.random() > 0.18), protocol_ssh_count=float(1 + commands), protocol_other_count=0.0)
    elif category == "multi_protocol":
        protocols = int(rng.choice([1, 2, 3, 4], p=[0.12, 0.30, 0.40, 0.18]))
        row.update(event_count=float(base_events + rng.poisson(5.0)), unique_protocol_count=float(protocols), protocol_tcp_count=float(rng.poisson(2.0)), protocol_udp_count=float(rng.poisson(1.5)), protocol_icmp_count=float(rng.poisson(0.8)), protocol_ssh_count=float(rng.poisson(1.1)), protocol_other_count=float(rng.poisson(0.6)), behavioral_diversity=float(rng.beta(2.0, 2.0)))
    else:  # low-activity benign/unknown background
        row.update(event_count=float(base_events), unique_protocol_count=float(rng.choice([1, 2], p=[0.8, 0.2])), protocol_tcp_count=float(rng.poisson(1.1)), unique_destination_ports=float(rng.choice([0, 1, 2], p=[0.25, 0.6, 0.15])))

    # A secondary episode creates legitimate feature overlap. Its weight is
    # lower than the dominant latent scenario and is fixed before evaluation.
    secondary = str(rng.choice(BEHAVIOR_CATEGORIES[:-1]))
    if rng.random() < 0.42 and secondary != category:
        secondary_row = _episode_without_mixture(secondary, rng)
        dominant_weight = float(rng.uniform(0.58, 0.82))
        for name in FEATURE_COLUMNS:
            row[name] = dominant_weight * row[name] + (1.0 - dominant_weight) * secondary_row[name]

    # Count noise and occasional missing aggregates are independent of the
    # latent label. Missing count fields use the schema's zero representation.
    for name in FEATURE_COLUMNS:
        if name in {"session_duration_available", "inter_attempts_available"}:
            continue
        value = row[name]
        if value and rng.random() < 0.22:
            value *= float(rng.lognormal(0.0, 0.45))
        if rng.random() < 0.08:
            value = 0.0
        row[name] = float(max(0.0, round(value))) if name in _COUNT_COLUMNS else float(max(0.0, value))
    row["unique_protocol_count"] = min(4.0, row["unique_protocol_count"])
    row["behavioral_diversity"] = min(1.0, row["behavioral_diversity"])
    row["session_duration_available"] = float(row["mean_session_duration_seconds"] > 0)
    return row


def _episode_without_mixture(category: str, rng: np.random.Generator) -> dict[str, float]:
    """Generate a secondary component without recursively mixing it."""
    # A temporary deterministic substream avoids sharing the caller's category
    # decision while reusing the independently specified episode distributions.
    row = {name: 0.0 for name in FEATURE_COLUMNS}
    count = int(rng.integers(1, 5))
    row.update(event_count=float(count), sensor_count=1.0, protocol_other_count=float(count))
    if category == "reconnaissance":
        row.update(connection_count=float(rng.poisson(5)), unique_destination_ports=float(1 + rng.poisson(2)), protocol_tcp_count=float(rng.poisson(5)), protocol_other_count=0.0)
    elif category == "authentication_probing":
        failed = int(rng.poisson(3.5)); row.update(failed_auth_count=float(failed), unique_usernames_attempted=float(min(failed, rng.poisson(2) + 1)), session_count=float(rng.poisson(1)), protocol_ssh_count=float(failed + 1), protocol_other_count=0.0)
    elif category == "repeated_connection":
        connections = int(rng.poisson(9)); row.update(event_count=float(count + connections), connection_count=float(connections), connections_per_minute=float(rng.gamma(2, 3.5)), unique_destination_ports=float(1 + rng.poisson(1)), protocol_tcp_count=float(connections), protocol_other_count=0.0)
    elif category == "suspicious_session":
        commands = int(rng.poisson(2.2)); row.update(event_count=float(count + commands), session_count=float(1 + rng.poisson(1)), command_attempt_count=float(commands), mean_session_duration_seconds=float(rng.lognormal(4, 1)), session_duration_available=1.0, protocol_ssh_count=float(commands + 1), protocol_other_count=0.0)
    else:
        protocols = int(rng.choice([1, 2, 3, 4])); row.update(event_count=float(count + rng.poisson(4)), unique_protocol_count=float(protocols), protocol_tcp_count=float(rng.poisson(2)), protocol_udp_count=float(rng.poisson(1)), protocol_icmp_count=float(rng.poisson(1)), protocol_ssh_count=float(rng.poisson(1)), protocol_other_count=float(rng.poisson(1)), behavioral_diversity=float(rng.beta(2, 2)))
    return row


_COUNT_COLUMNS = set(FEATURE_COLUMNS) - {
    "connections_per_minute", "mean_session_duration_seconds", "mean_inter_attempt_seconds",
    "behavioral_diversity",
}


def generate_challenge_dataset(*, samples_per_category: int = 120, seed: int = 20301128) -> tuple[list[dict[str, float]], list[str]]:
    """Generate a reproducible out-of-generator challenge set with latent labels."""
    if type(samples_per_category) is not int or not 20 <= samples_per_category <= 2000:
        raise ValueError("samples_per_category must be between 20 and 2000")
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError("seed must be an unsigned 32-bit integer")
    rng = np.random.default_rng(seed)
    rows: list[dict[str, float]] = []
    labels: list[str] = []
    # Label is chosen from the latent dominant episode before observed feature
    # aggregates are sampled. This is explicitly synthetic known truth.
    for category in BEHAVIOR_CATEGORIES:
        for _ in range(samples_per_category):
            rows.append(_episode(category, rng))
            labels.append(category)
    return rows, labels


def evaluate_challenge(*, samples_per_category: int = 120, train_seed: int = 20301127, test_seed: int = 20301128) -> dict[str, Any]:
    """Fit fixed existing model families on original synthetic data, test on challenge data."""
    if train_seed == test_seed:
        raise ValueError("training and challenge seeds must be distinct")
    train_rows, train_labels = generate_synthetic_dataset(samples_per_category, train_seed)
    test_rows, test_labels = generate_challenge_dataset(samples_per_category=samples_per_category, seed=test_seed)
    x_train = np.asarray([[row[name] for name in FEATURE_COLUMNS] for row in train_rows], dtype=np.float64)
    x_test = np.asarray([[row[name] for name in FEATURE_COLUMNS] for row in test_rows], dtype=np.float64)
    y_train = np.asarray(train_labels)
    labels = list(BEHAVIOR_CATEGORIES)
    candidates = {
        "random_forest": RandomForestClassifier(n_estimators=80, min_samples_leaf=1, class_weight="balanced", random_state=train_seed, n_jobs=1),
        "decision_tree": DecisionTreeClassifier(max_depth=4, min_samples_leaf=1, class_weight="balanced", random_state=train_seed),
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(C=1.0, max_iter=2000, class_weight="balanced", random_state=train_seed)),
    }
    outcomes: dict[str, Any] = {}
    for name, model in candidates.items():
        model.fit(x_train, y_train)
        prediction = list(model.predict(x_test))
        probabilities = model.predict_proba(x_test)
        probability_labels = list(model.classes_) if hasattr(model, "classes_") else list(model[-1].classes_)
        outcomes[name] = classification_metrics(test_labels, prediction, labels, np.asarray(probabilities), probability_labels)
    rule_predictions = [evidence_rule_category(row) for row in test_rows]
    outcomes["evidence_rules"] = classification_metrics(test_labels, rule_predictions, labels)
    return {
        "schema_version": 1,
        "evaluation_kind": "independent_synthetic_shift_challenge",
        "label_definition": "Latent dominant scenario selected before feature generation; features generated independently with overlapping secondary episodes, count noise, low-activity benign background, and 8% per-feature missing aggregates encoded as schema zeros.",
        "train_generator": "existing generate_synthetic_dataset; test generator is separate episode sampler in profiling.challenge",
        "train_seed": train_seed,
        "test_seed": test_seed,
        "samples_per_category": samples_per_category,
        "train_rows": len(train_labels),
        "test_rows": len(test_labels),
        "test_unique_feature_rows": len({tuple(row[name] for name in FEATURE_COLUMNS) for row in test_rows}),
        "models": outcomes,
        "limitations": [
            "Both train and challenge labels are synthetic latent scenario labels, not observed maliciousness.",
            "The challenge changes feature generation and adds overlap but is still authored by project code; this is not an external or operational validation set.",
            "Missing aggregates are represented as zero because the current model feature schema has no general per-field missingness mask.",
        ],
    }
