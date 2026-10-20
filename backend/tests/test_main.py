
import pytest
from fastapi.testclient import TestClient

from backend.app.events.store import event_store
from backend.app.ledger.service import event_ledger
from backend.app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_events():
    event_store.clear()
    event_ledger.clear()
    yield
    event_store.clear()
    event_ledger.clear()


def record_interaction(actor_id, decoy_id, action):
    return client.post(
        f"/api/v1/decoys/{decoy_id}/interactions",
        json={"actor_id": actor_id, "action": action},
    )


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "running"


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_list_decoys():
    response = client.get("/api/v1/decoys")
    assert response.status_code == 200

    decoys = response.json()
    assert len(decoys) == 3

    decoy_ids = {decoy["decoy_id"] for decoy in decoys}
    assert "decoy-finance-001" in decoy_ids
    assert "decoy-credential-001" in decoy_ids
    assert "decoy-database-001" in decoy_ids


def test_record_interaction():
    response = record_interaction(
        "simulator-001", "decoy-credential-001", "read"
    )

    assert response.status_code == 201
    event = response.json()
    assert event["decoy_id"] == "decoy-credential-001"
    assert event["actor_id"] == "simulator-001"
    assert event["action"] == "read"
    assert event["event_type"] == "decoy_interaction"
    assert event["event_id"]


def test_event_appears_in_event_history():
    created = record_interaction(
        "simulator-002", "decoy-finance-001", "view"
    )

    assert created.status_code == 201
    event_id = created.json()["event_id"]

    response = client.get("/api/v1/events")
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["event_id"] == event_id


def test_unknown_decoy_returns_404():
    response = record_interaction(
        "simulator-003", "unknown-decoy", "read"
    )
    assert response.status_code == 404


def test_invalid_interaction_is_rejected():
    response = record_interaction(
        "simulator-004", "decoy-finance-001", "delete_everything"
    )
    assert response.status_code == 422


def test_unknown_event_returns_404():
    response = client.get("/api/v1/events/nonexistent-event")
    assert response.status_code == 404


def test_fingerprint_for_unknown_actor_returns_404():
    response = client.get(
        "/api/v1/intelligence/fingerprints/unknown-actor"
    )
    assert response.status_code == 404


def test_fingerprint_summarizes_actor_behavior():
    interactions = [
        ("decoy-finance-001", "read"),
        ("decoy-credential-001", "attempt_login"),
        ("decoy-database-001", "query"),
    ]

    for decoy_id, action in interactions:
        response = record_interaction(
            "simulator-risk-test", decoy_id, action
        )
        assert response.status_code == 201

    response = client.get(
        "/api/v1/intelligence/fingerprints/simulator-risk-test"
    )

    assert response.status_code == 200
    fingerprint = response.json()
    assert fingerprint["actor_id"] == "simulator-risk-test"
    assert fingerprint["event_count"] == 3
    assert fingerprint["unique_decoys_accessed"] == 3
    assert fingerprint["unique_actions"] == 3
    assert fingerprint["risk_score"] == 80
    assert fingerprint["risk_level"] == "high"
    assert fingerprint["assessment_type"] == "heuristic_baseline"


def test_fingerprint_list_is_empty_without_events():
    response = client.get("/api/v1/intelligence/fingerprints")
    assert response.status_code == 200
    assert response.json() == []


def test_ml_assessment_for_unknown_actor_returns_404():
    response = client.get("/api/v1/intelligence/ml/unknown-actor")
    assert response.status_code == 404


def test_ml_assessment_returns_prediction():
    interactions = [
        ("decoy-finance-001", "read"),
        ("decoy-credential-001", "attempt_login"),
        ("decoy-database-001", "query"),
    ]

    for decoy_id, action in interactions:
        response = record_interaction(
            "simulator-ml-test", decoy_id, action
        )
        assert response.status_code == 201

    response = client.get(
        "/api/v1/intelligence/ml/simulator-ml-test"
    )

    assert response.status_code == 200
    assessment = response.json()

    assert assessment["actor_id"] == "simulator-ml-test"
    assert assessment["event_count"] == 3
    assert assessment["predicted_class"] in {"benign", "suspicious"}
    assert 0.0 <= assessment["suspicious_probability"] <= 1.0
    assert assessment["model_name"] == "RandomForestClassifier"
    assert assessment["assessment_type"] == "synthetic_model_inference"
    assert "event_count" in assessment["features"]
    assert "limitations" in assessment


# Adaptive Honeypot tests

def test_adaptation_for_unknown_actor_returns_404():
    response = client.get(
        "/api/v1/adaptation/unknown-adaptation-actor"
    )
    assert response.status_code == 404


def test_adaptation_selects_neutral_strategy_for_read_only_activity():
    response = record_interaction(
        "simulator-neutral", "decoy-finance-001", "read"
    )
    assert response.status_code == 201

    response = client.get("/api/v1/adaptation/simulator-neutral")

    assert response.status_code == 200
    decision = response.json()
    assert decision["actor_id"] == "simulator-neutral"
    assert decision["event_count"] == 1
    assert decision["risk_level"] == "low"
    assert decision["selected_strategy"] == "neutral_response"
    assert decision["simulation_only"] is True


def test_adaptation_selects_credential_strategy_for_login_attempt():
    response = record_interaction(
        "simulator-login", "decoy-credential-001", "attempt_login"
    )
    assert response.status_code == 201

    response = client.get("/api/v1/adaptation/simulator-login")

    assert response.status_code == 200
    decision = response.json()
    assert decision["risk_level"] == "medium"
    assert decision["selected_strategy"] == "credential_decoy"
    assert "attempt_login" in decision["observed_actions"]


def test_adaptation_selects_database_strategy_for_query():
    response = record_interaction(
        "simulator-query", "decoy-database-001", "query"
    )
    assert response.status_code == 201

    response = client.get("/api/v1/adaptation/simulator-query")

    assert response.status_code == 200
    decision = response.json()
    assert decision["risk_level"] == "medium"
    assert decision["selected_strategy"] == "database_decoy"
    assert "query" in decision["observed_actions"]


def test_adaptation_selects_expanded_path_for_combined_activity():
    interactions = [
        ("decoy-finance-001", "read"),
        ("decoy-credential-001", "attempt_login"),
        ("decoy-database-001", "query"),
    ]

    for decoy_id, action in interactions:
        response = record_interaction(
            "simulator-adaptive-high", decoy_id, action
        )
        assert response.status_code == 201

    response = client.get(
        "/api/v1/adaptation/simulator-adaptive-high"
    )

    assert response.status_code == 200
    decision = response.json()
    assert decision["actor_id"] == "simulator-adaptive-high"
    assert decision["event_count"] == 3
    assert decision["risk_level"] == "high"
    assert decision["selected_strategy"] == "expanded_decoy_path"
    assert len(decision["observed_decoys"]) == 3
    assert {"read", "attempt_login", "query"}.issubset(
        set(decision["observed_actions"])
    )
    assert decision["simulation_only"] is True


# Event Ledger API tests

def test_interaction_is_added_to_ledger():
    response = record_interaction(
        "ledger-api-test", "decoy-finance-001", "read"
    )

    assert response.status_code == 201

    entries_response = client.get("/api/v1/ledger")
    assert entries_response.status_code == 200

    entries = entries_response.json()
    assert len(entries) == 1
    assert entries[0]["event_id"] == response.json()["event_id"]
    assert entries[0]["sequence"] == 1


def test_ledger_verify_endpoint_reports_valid_chain():
    for action in ("read", "attempt_login"):
        response = record_interaction(
            "ledger-verify-test",
            "decoy-credential-001",
            action,
        )
        assert response.status_code == 201

    response = client.get("/api/v1/ledger/verify")

    assert response.status_code == 200
    result = response.json()
    assert result["valid"] is True
    assert result["entries_checked"] == 2


def test_ledger_verify_endpoint_accepts_empty_ledger():
    response = client.get("/api/v1/ledger/verify")

    assert response.status_code == 200
    assert response.json()["valid"] is True
    assert response.json()["entries_checked"] == 0


def test_ledger_list_limit_is_respected():
    for index in range(3):
        response = record_interaction(
            f"ledger-limit-{index}",
            "decoy-finance-001",
            "read",
        )
        assert response.status_code == 201

    response = client.get("/api/v1/ledger?limit=2")

    assert response.status_code == 200
    entries = response.json()
    assert len(entries) == 2
    assert [entry["sequence"] for entry in entries] == [3, 2]
