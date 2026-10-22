from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api import routes
from app.events.store import EventStore
from app.intelligence.service import BehavioralFingerprint, BehavioralIntelligenceService
from app.intelligence.fingerprint_schema import (
    ACTION_CATEGORIES,
    DECOY_CATEGORIES,
    FINGERPRINT_SCHEMA_NAME,
    VECTOR_FEATURE_ORDER,
    BehavioralFingerprintVectorizer,
    FingerprintContractV1,
    canonical_serialize_export,
    contract_from_operational,
    export_digest,
    fingerprint_schema_metadata,
    to_shareable_export,
    validate_fingerprint_payload,
)
from app.main import app


def make_fingerprint(**updates):
    actor_id = "private-actor-example-001"
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = EventStore()
    event_values = [
        ("e-1", "decoy-finance-001", "read", start),
        ("e-2", "decoy-credential-001", "attempt_login", start + timedelta(seconds=30)),
    ]
    for event_id, decoy, action, timestamp in event_values:
        from app.events.models import HoneypotEvent
        store.add(HoneypotEvent(
            event_id=event_id, actor_id=actor_id, decoy_id=decoy,
            action=action, timestamp=timestamp,
        ))
    fingerprint = BehavioralIntelligenceService(store).analyze_actor(actor_id)
    return fingerprint.model_copy(update=updates)


def test_v1_contract_accepts_operational_fingerprint_and_legacy_payload():
    fingerprint = make_fingerprint()
    contract = contract_from_operational(fingerprint)
    assert contract.schema_name == FINGERPRINT_SCHEMA_NAME
    assert contract.schema_version == 1
    assert contract.action_frequencies == {"read": 1, "attempt_login": 1}

    legacy = fingerprint.model_dump(mode="json")
    validated, compatibility = validate_fingerprint_payload(legacy)
    assert validated.schema_version == 1
    assert compatibility == "legacy_fingerprint_v1"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_count", True),
        ("credential_probing", "true"),
        ("risk_score", 101),
        ("action_frequencies", {"read": 1}),
        ("elapsed_seconds", float("nan")),
        ("interactions_per_minute", float("inf")),
        ("action_sequence", ["read", 7]),
        ("elapsed_seconds", "0.5"),
        ("schema_version", 2),
    ],
)
def test_contract_rejects_invalid_types_ranges_timing_and_versions(field, value):
    payload = contract_from_operational(make_fingerprint()).model_dump(mode="python")
    payload[field] = value
    with pytest.raises(ValidationError):
        FingerprintContractV1.model_validate(payload)


def test_empty_fingerprint_and_missing_timing_are_explicit():
    empty = FingerprintContractV1(
        schema_name=FINGERPRINT_SCHEMA_NAME,
        schema_version=1,
        fingerprint_version=1,
        actor_id="empty-actor",
        event_count=0,
        unique_decoys_accessed=0,
        unique_actions=0,
        action_sequence=[],
        decoy_types_accessed=[],
        credential_probing=False,
        database_probing=False,
        file_probing=False,
        repeated_access=False,
        timing_reliable=False,
        risk_score=0,
        risk_level="low",
    )
    vector = BehavioralFingerprintVectorizer().vectorize(empty)
    assert len(vector.values) == len(VECTOR_FEATURE_ORDER)
    assert vector.values[vector.feature_order.index("elapsed_seconds.missing")] == 1
    assert vector.values[vector.feature_order.index("decoy_type_frequencies_available")] == 1

    unavailable = contract_from_operational(make_fingerprint())
    export = to_shareable_export(unavailable)
    assert export.timing_reliable is True
    assert export.elapsed_time_band == "under_1m"


def test_missing_legacy_decoy_counts_are_marked_unavailable_not_fabricated():
    fingerprint = make_fingerprint()
    fingerprint = fingerprint.model_copy(update={"decoy_type_frequencies": {}})
    contract = contract_from_operational(fingerprint)
    export = to_shareable_export(contract)
    vector = BehavioralFingerprintVectorizer().vectorize(contract)
    assert export.decoy_type_frequencies_available is False
    assert vector.values[vector.feature_order.index("decoy_type_frequencies_available")] == 0
    assert vector.values[vector.feature_order.index("decoy_frequency.credential")] == 0


def test_incomparable_timestamps_remain_unavailable():
    naive = datetime(2026, 1, 1)
    aware = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = EventStore()
    from app.events.models import HoneypotEvent
    store.add(HoneypotEvent(event_id="n", actor_id="mixed", decoy_id="decoy-finance-001", action="read", timestamp=naive))
    store.add(HoneypotEvent(event_id="a", actor_id="mixed", decoy_id="decoy-credential-001", action="attempt_login", timestamp=aware))
    fingerprint = BehavioralIntelligenceService(store).analyze_actor("mixed")
    assert fingerprint is not None and fingerprint.timing_reliable is False
    assert fingerprint.elapsed_seconds is None
    assert fingerprint.interactions_per_minute is None
    vector = BehavioralFingerprintVectorizer().vectorize(fingerprint)
    assert vector.values[vector.feature_order.index("elapsed_seconds.value")] == 0
    assert vector.values[vector.feature_order.index("elapsed_seconds.missing")] == 1


def test_serialization_digest_and_vector_are_deterministic_with_fixed_order():
    fingerprint = make_fingerprint()
    original = fingerprint.model_dump(mode="python")
    exported = to_shareable_export(fingerprint)
    canonical = canonical_serialize_export(exported)
    reordered = exported.model_copy(update={
        "action_frequencies": dict(reversed(list(exported.action_frequencies.items()))),
        "decoy_type_frequencies": dict(reversed(list(exported.decoy_type_frequencies.items()))),
    })
    assert canonical_serialize_export(reordered) == canonical
    assert export_digest(reordered) == export_digest(exported)

    vectorizer = BehavioralFingerprintVectorizer()
    first = vectorizer.vectorize(fingerprint)
    second = vectorizer.vectorize(fingerprint)
    assert fingerprint.model_dump(mode="python") == original
    assert first == second
    assert first.feature_order == VECTOR_FEATURE_ORDER
    assert len(first.values) == 26
    assert all(value == value and abs(value) != float("inf") for value in first.values)
    with pytest.raises(ValidationError):
        type(first).model_validate({**first.model_dump(), "values": first.values[:-1]})
    with pytest.raises(ValidationError):
        type(first).model_validate({
            **first.model_dump(),
            "values": (*first.values[:-1], float("nan")),
        })


def test_unknown_categories_use_fixed_other_dimensions_without_echoing_labels():
    payload = contract_from_operational(make_fingerprint()).model_dump(mode="python")
    payload.update({
        "event_count": 2,
        "unique_actions": 1,
        "action_sequence": ["Unlisted ACTION", "Unlisted ACTION"],
        "action_frequencies": {"Unlisted ACTION": 2},
        "decoy_types_accessed": ["private-decoy-category"],
        "decoy_type_frequencies": {"private-decoy-category": 1},
        "credential_probing": False,
        "database_probing": False,
        "file_probing": False,
    })
    contract = FingerprintContractV1.model_validate(payload)
    export = to_shareable_export(contract)
    vector = BehavioralFingerprintVectorizer().vectorize(contract)
    assert set(export.action_frequencies) == set(ACTION_CATEGORIES)
    assert set(export.decoy_type_frequencies) == set(DECOY_CATEGORIES)
    assert export.action_frequencies["other"] == 2
    assert export.decoy_type_frequencies["other"] == 1
    assert "private-decoy-category" not in canonical_serialize_export(export)
    assert len(vector.values) == 26


def test_privacy_export_excludes_identifiers_times_sequences_and_free_text():
    export = to_shareable_export(make_fingerprint(
        reasons=[
            "password=hunter2 secret token /private/workspace/sensitive.txt "
            "C:\\Users\\Sam\\private.txt decoy_id=decoy-credential-001"
        ],
    ))
    serialized = canonical_serialize_export(export)
    for forbidden in (
        "private-actor-example-001", "2026-01-01", "attempt_login\",\"read",
        "secret token", "password=hunter2", "/private/workspace",
        "C:\\Users\\Sam", "decoy-credential-001", "decision_id", "event_id",
    ):
        assert forbidden not in serialized
    assert export.schema_version == 1
    assert export_digest(export) not in serialized


def test_schema_metadata_describes_all_vector_features_and_privacy_policy():
    metadata = fingerprint_schema_metadata()
    assert metadata["vector_feature_order"] == list(VECTOR_FEATURE_ORDER)
    assert "actor_id" in metadata["excluded_from_export"]
    assert "vector_feature_definitions" in metadata


def test_fingerprint_api_validation_export_vector_and_reads_do_not_mutate_state():
    client = TestClient(app)
    actor_id = f"schema-api-{uuid4().hex}"
    interaction = client.post(
        "/api/v1/decoys/decoy-credential-001/interactions",
        json={"actor_id": actor_id, "action": "attempt_login"},
    )
    assert interaction.status_code == 201

    payload = client.get(f"/api/v1/intelligence/fingerprints/{actor_id}").json()
    before = (
        len(routes.event_ledger.list_entries()),
        routes.event_store.count_events(),
        routes.adaptive_honeypot_service.get_decision_history(actor_id),
        routes.adaptive_honeypot_service._history_storage.get_observed_strategy(actor_id),
        [bundle.bundle_id for bundle in routes.generated_decoy_registry.list_bundles(actor_id)],
    )
    assert client.get("/api/v1/intelligence/fingerprints/schema").status_code == 200
    validated = client.post("/api/v1/intelligence/fingerprints/validate", json=payload)
    assert validated.status_code == 200
    assert validated.json()["compatibility"] == "legacy_fingerprint_v1"
    invalid = dict(payload, fingerprint_version=7)
    rejected = client.post("/api/v1/intelligence/fingerprints/validate", json=invalid)
    assert rejected.status_code == 422
    shared = client.get(f"/api/v1/intelligence/fingerprints/{actor_id}/export")
    vector = client.get(f"/api/v1/intelligence/fingerprints/{actor_id}/vector")
    assert shared.status_code == vector.status_code == 200
    assert "actor_id" not in shared.json()["export"]
    assert vector.json()["feature_order"] == list(VECTOR_FEATURE_ORDER)
    after = (
        len(routes.event_ledger.list_entries()),
        routes.event_store.count_events(),
        routes.adaptive_honeypot_service.get_decision_history(actor_id),
        routes.adaptive_honeypot_service._history_storage.get_observed_strategy(actor_id),
        [bundle.bundle_id for bundle in routes.generated_decoy_registry.list_bundles(actor_id)],
    )
    assert after == before
