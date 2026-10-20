
"""Train and evaluate the synthetic behavioral classifier."""

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = (
    PROJECT_ROOT / "experiments" / "datasets" / "behavior_dataset.csv"
)
RESULTS_DIR = PROJECT_ROOT / "experiments" / "results"
MODEL_PATH = RESULTS_DIR / "behavior_model.joblib"
METRICS_PATH = RESULTS_DIR / "metrics.json"
CONFUSION_PATH = RESULTS_DIR / "confusion_matrix.csv"

FEATURE_COLUMNS = [
    "event_count",
    "unique_decoys_accessed",
    "unique_actions",
    "login_attempts",
    "database_queries",
    "interactions_per_minute",
    "category_coverage",
]

TARGET_COLUMN = "label"


def main() -> None:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}. "
            "Run simulator/generate_dataset.py first."
        )

    dataset = pd.read_csv(DATASET_PATH)

    required_columns = set(FEATURE_COLUMNS + [TARGET_COLUMN])
    missing_columns = required_columns - set(dataset.columns)

    if missing_columns:
        raise ValueError(
            f"Dataset is missing required columns: "
            f"{sorted(missing_columns)}"
        )

    if dataset[FEATURE_COLUMNS].isnull().any().any():
        raise ValueError("Dataset contains missing feature values.")

    if not set(dataset[TARGET_COLUMN].unique()).issubset(
        {"benign", "suspicious"}
    ):
        raise ValueError("Dataset contains unsupported labels.")

    X = dataset[FEATURE_COLUMNS].astype(float)
    y = dataset[TARGET_COLUMN].astype(str)

    if y.nunique() != 2:
        raise ValueError(
            "Training requires both benign and suspicious examples."
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)

    suspicious_index = list(model.classes_).index("suspicious")
    suspicious_probabilities = probabilities[:, suspicious_index]

    metrics = {
        "experiment": "synthetic_behavior_classifier",
        "dataset": str(DATASET_PATH.relative_to(PROJECT_ROOT)),
        "dataset_rows": int(len(dataset)),
        "training_rows": int(len(X_train)),
        "testing_rows": int(len(X_test)),
        "random_seed": 42,
        "model": "RandomForestClassifier",
        "features": FEATURE_COLUMNS,
        "target": TARGET_COLUMN,
        "positive_class": "suspicious",
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(
            precision_score(
                y_test,
                predictions,
                pos_label="suspicious",
                zero_division=0,
            )
        ),
        "recall": float(
            recall_score(
                y_test,
                predictions,
                pos_label="suspicious",
                zero_division=0,
            )
        ),
        "f1_score": float(
            f1_score(
                y_test,
                predictions,
                pos_label="suspicious",
                zero_division=0,
            )
        ),
        "roc_auc": float(
            roc_auc_score(
                (y_test == "suspicious").astype(int),
                suspicious_probabilities,
            )
        ),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=["benign", "suspicious"],
            output_dict=True,
            zero_division=0,
        ),
        "limitations": [
            "Evaluation uses synthetic scenarios only.",
            "Labels reflect simulator assumptions, not verified real attacks.",
            "Results do not establish real-world detection performance.",
        ],
    }

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=["benign", "suspicious"],
    )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    METRICS_PATH.write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8",
    )

    pd.DataFrame(
        matrix,
        index=["actual_benign", "actual_suspicious"],
        columns=["predicted_benign", "predicted_suspicious"],
    ).to_csv(CONFUSION_PATH)

    print("\n=== Synthetic Behavioral Classifier ===")
    print(f"Dataset rows: {len(dataset)}")
    print(f"Training rows: {len(X_train)}")
    print(f"Testing rows: {len(X_test)}")
    print(f"Accuracy:  {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"F1-score:  {metrics['f1_score']:.4f}")
    print(f"ROC-AUC:   {metrics['roc_auc']:.4f}")

    print("\nConfusion matrix:")
    print(
        pd.DataFrame(
            matrix,
            index=["actual_benign", "actual_suspicious"],
            columns=["predicted_benign", "predicted_suspicious"],
        )
    )

    print(f"\nModel saved: {MODEL_PATH}")
    print(f"Metrics saved: {METRICS_PATH}")
    print(f"Confusion matrix saved: {CONFUSION_PATH}")


if __name__ == "__main__":
    main()
