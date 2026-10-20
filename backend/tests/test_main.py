
import pytest
from fastapi.testclient import TestClient

from backend.app.events.store import event_store
from backend.app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_events():
    event_store.clear()
    yield
    event_store.clear()


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
    response = client.post(
        "/api/v1/decoys/decoy-credential-001/interactions",
        json={"actor_id": "simulator-001", "action": "read"},
    )

    assert response.status_code == 201
    event = response.json()
    assert event["decoy_id"] == "decoy-credential-001"
    assert event["actor_id"] == "simulator-001"
    assert event["action"] == "read"
    assert event["event_type"] == "decoy_interaction"
    assert event["event_id"]


def test_event_appears_in_event_history():
    created = client.post(
        "/api/v1/decoys/decoy-finance-001/interactions",
        json={"actor_id": "simulator-002", "action": "view"},
    )

    assert created.status_code == 201
    event_id = created.json()["event_id"]

    response = client.get("/api/v1/events")
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["event_id"] == event_id


def test_unknown_decoy_returns_404():
    response = client.post(
        "/api/v1/decoys/unknown-decoy/interactions",
        json={"actor_id": "simulator-003", "action": "read"},
    )

    assert response.status_code == 404


def test_invalid_interaction_is_rejected():
    response = client.post(
        "/api/v1/decoys/decoy-finance-001/interactions",
        json={
            "actor_id": "simulator-004",
            "action": "delete_everything",
        },
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
        response = client.post(
            f"/api/v1/decoys/{decoy_id}/interactions",
            json={"actor_id": "simulator-risk-test", "action": action},
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
    assert len(fingerprint["reasons"]) >= 1


def test_fingerprint_list_is_empty_without_events():
    response = client.get("/api/v1/intelligence/fingerprints")

    assert response.status_code == 200
    assert response.json() == []
