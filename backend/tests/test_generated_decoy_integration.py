from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.routes import (
    adaptive_honeypot_service,
    generated_decoy_registry,
)
from app.main import app

client = TestClient(app)


def test_generated_decoy_is_listed_and_retrievable():
    actor_id = "integration-generator-001"

    # Record behavior so the actor has a fingerprint.
    interaction = client.post(
        "/api/v1/decoys/decoy-credential-001/interactions",
        json={
            "actor_id": actor_id,
            "action": "attempt_login",
        },
    )
    assert interaction.status_code == 201

    # Generate behavior-conditioned decoys.
    generated = client.post(
        f"/api/v1/decoys/generate/{actor_id}",
        params={"limit": 2},
    )
    assert generated.status_code == 200

    decoys = generated.json()
    assert len(decoys) == 2

    generated_id = decoys[0]["decoy_id"]

    # Verify that the generated decoy is listed.
    listing = client.get("/api/v1/decoys")
    assert listing.status_code == 200

    listed_ids = {
        decoy["decoy_id"] for decoy in listing.json()
    }
    assert generated_id in listed_ids

    # Verify lookup by ID.
    detail = client.get(f"/api/v1/decoys/{generated_id}")
    assert detail.status_code == 200
    assert detail.json()["decoy_id"] == generated_id


def test_generated_decoy_interaction_is_recorded():
    actor_id = "integration-interaction-001"

    # Create the behavioral history needed for generation.
    initial = client.post(
        "/api/v1/decoys/decoy-credential-001/interactions",
        json={
            "actor_id": actor_id,
            "action": "attempt_login",
        },
    )
    assert initial.status_code == 201

    generated = client.post(
        f"/api/v1/decoys/generate/{actor_id}",
        params={"limit": 1},
    )
    assert generated.status_code == 200

    generated_id = generated.json()[0]["decoy_id"]

    # Interact with the generated decoy.
    response = client.post(
        f"/api/v1/decoys/{generated_id}/interactions",
        json={
            "actor_id": actor_id,
            "action": "read",
        },
    )
    assert response.status_code == 201

    event = response.json()
    assert event["decoy_id"] == generated_id
    assert event["actor_id"] == actor_id
    assert event["action"] == "read"

    # Confirm the interaction reached the event API.
    events = client.get("/api/v1/events")
    assert events.status_code == 200
    assert any(
        item["event_id"] == event["event_id"]
        for item in events.json()
    )

    # Confirm it reached the ledger API.
    ledger = client.get("/api/v1/ledger")
    assert ledger.status_code == 200
    assert any(
        item["event_id"] == event["event_id"]
        for item in ledger.json()
    )


def test_read_then_login_generates_persisted_decoys_once():
    actor_id = f"integration-strategy-change-{uuid4().hex}"
    history_storage = adaptive_honeypot_service._history_storage

    decoys_before = {
        decoy.decoy_id
        for decoy in generated_decoy_registry.list_all()
        if decoy.actor_id == actor_id
    }
    assert not decoys_before

    initial_listing = client.get("/api/v1/decoys")
    assert initial_listing.status_code == 200
    initial_ids = {
        decoy["decoy_id"] for decoy in initial_listing.json()
    }

    first = client.post(
        "/api/v1/decoys/decoy-finance-001/interactions",
        json={"actor_id": actor_id, "action": "read"},
    )
    assert first.status_code == 201
    assert history_storage.get_observed_strategy(actor_id) == "neutral_response"

    # Reading is the actor's baseline strategy; a login attempt changes it.
    changed = client.post(
        "/api/v1/decoys/decoy-credential-001/interactions",
        json={"actor_id": actor_id, "action": "attempt_login"},
    )
    assert changed.status_code == 201
    assert history_storage.get_observed_strategy(actor_id) == "credential_decoy"

    actor_decoys = [
        decoy
        for decoy in generated_decoy_registry.list_all()
        if decoy.actor_id == actor_id
    ]
    assert len(actor_decoys) == 2

    listed = client.get("/api/v1/decoys")
    assert listed.status_code == 200
    after_change = {
        decoy["decoy_id"]
        for decoy in listed.json()
        if decoy["decoy_id"].startswith("generated-")
        and decoy["decoy_id"] not in initial_ids
    }
    generated_ids = {decoy.decoy_id for decoy in actor_decoys}
    assert after_change == generated_ids
    assert generated_ids.isdisjoint(initial_ids)

    # GET adaptation records a decision but does not replace the trigger state.
    decision = client.get(f"/api/v1/adaptation/{actor_id}")
    assert decision.status_code == 200
    assert decision.json()["selected_strategy"] == "credential_decoy"
    assert history_storage.get_observed_strategy(actor_id) == "credential_decoy"

    repeated = client.post(
        "/api/v1/decoys/decoy-credential-001/interactions",
        json={"actor_id": actor_id, "action": "attempt_login"},
    )
    assert repeated.status_code == 201
    assert repeated.json()["decoy_id"] == "decoy-credential-001"

    listed_again = client.get("/api/v1/decoys")
    after_repeat = {
        decoy["decoy_id"]
        for decoy in listed_again.json()
        if decoy["decoy_id"].startswith("generated-")
        and decoy["decoy_id"] not in initial_ids
    }
    assert after_repeat == after_change

    # The recorded interactions feed both fingerprinting and adaptation.
    fingerprint = client.get(
        f"/api/v1/intelligence/fingerprints/{actor_id}"
    )
    assert fingerprint.status_code == 200
    assert fingerprint.json()["event_count"] == 3


def test_strategy_observations_are_isolated_by_actor():
    first_actor = "integration-isolated-actor-001"
    second_actor = "integration-isolated-actor-002"

    assert client.post(
        "/api/v1/decoys/decoy-finance-001/interactions",
        json={"actor_id": first_actor, "action": "read"},
    ).status_code == 201
    before_second_actor = {
        decoy["decoy_id"]
        for decoy in client.get("/api/v1/decoys").json()
    }

    response = client.post(
        "/api/v1/decoys/decoy-credential-001/interactions",
        json={"actor_id": second_actor, "action": "attempt_login"},
    )
    assert response.status_code == 201

    after_second_actor = {
        decoy["decoy_id"]
        for decoy in client.get("/api/v1/decoys").json()
    }
    assert after_second_actor == before_second_actor
