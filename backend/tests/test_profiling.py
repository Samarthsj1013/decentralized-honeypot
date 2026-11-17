from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.events.models import HoneypotEvent
from app.events.store import EventStore
from app.incidents.service import IncidentService
from app.incidents.storage import SQLiteIncidentStorage
from app.profiling.features import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION, extract_features, group_external_events
from app.profiling.models_ml import (
    ProfileModelError,
    generate_synthetic_dataset,
    load_model_bundle,
    save_model_bundle,
    train_profile_models,
    validate_model_bundle,
)
from app.profiling.service import AttackerProfileService
from app.profiling.storage import SQLiteProfileStorage


@pytest.fixture(scope="module")
def models():
    return train_profile_models(samples_per_category=12, random_seed=917)


@pytest.fixture(scope="module")
def isolated_evaluation_summary():
    return AttackerProfileService._run_isolated_evaluation()


def external_event(event_id, kind, when, *, source_ip="198.51.100.77", source_system="cowrie", protocol="ssh", attrs=None, severity="medium", port=22, sensor="sensor-a"):
    return HoneypotEvent(
        event_id=event_id,
        timestamp=when,
        decoy_id="external-telemetry",
        actor_id="external-sensor-not-an-actor",
        action=kind,
        event_type="external_telemetry",
        severity=severity,
        source="external",
        source_system=source_system,
        sensor_id=sensor,
        telemetry_event_type=kind,
        source_ip=source_ip,
        destination_ip="203.0.113.12",
        destination_port=port,
        protocol=protocol,
        attributes=attrs or {},
    )


def test_feature_extraction_uses_versioned_aggregates_and_omits_sensitive_values():
    now = datetime.now(timezone.utc)
    rows = [
        external_event("e1", "cowrie_login_failed", now, attrs={"authentication_outcome": "failed", "username": "private-user", "password": "SECRET_PASSWORD", "input": "rm -rf /"}),
        external_event("e2", "cowrie_command_attempt", now + timedelta(seconds=10), attrs={"command_attempt": True, "input": "cat /private/file"}),
        external_event("e3", "suricata_alert", now + timedelta(seconds=20), source_system="suricata", protocol="TCP", severity="high", attrs={"alert": {"signature": "PRIVATE_SIGNATURE"}}),
        external_event("e4", "zeek_connection", now + timedelta(seconds=30), source_system="zeek", protocol="udp", port=53, attrs={"duration": 2.5}),
    ]
    features = extract_features(rows, window_seconds=3600, as_of=now + timedelta(seconds=30))
    assert tuple(features) == FEATURE_COLUMNS
    assert FEATURE_SCHEMA_VERSION == 1
    assert features["failed_auth_count"] == 1
    assert features["unique_usernames_attempted"] == 1
    assert features["command_attempt_count"] == 1
    assert features["suricata_alert_count"] == 1
    assert features["alert_severity_high"] == 1
    assert features["connection_count"] == 1
    assert features["mean_session_duration_seconds"] == 2.5
    assert features["sensor_count"] == 1
    assert 0 <= features["behavioral_diversity"] <= 1
    assert not {"private-user", "SECRET_PASSWORD", "rm -rf /", "cat /private/file", "PRIVATE_SIGNATURE"} & set(map(str, features.values()))


def test_profiles_group_by_source_ip_and_window_without_persisting_raw_ip_or_usernames(tmp_path, models):
    now = datetime.now(timezone.utc)
    events = EventStore()
    for index in range(5):
        events.add_event(external_event(f"profile-{index}", "cowrie_login_failed", now + timedelta(seconds=index), attrs={"authentication_outcome": "failed", "username": f"user-{index}", "password": "DO_NOT_STORE_PASSWORD"}))
    events.add_event(external_event("other-ip", "cowrie_login_failed", now, source_ip="203.0.113.89", attrs={"authentication_outcome": "failed"}))
    events.add_event(HoneypotEvent(event_id="sim", timestamp=now, decoy_id="decoy-finance-001", actor_id="sim-1", action="read"))
    path = tmp_path / "profiles.sqlite3"
    service = AttackerProfileService(events, SQLiteProfileStorage(path), model_bundle=models)

    profiles, created = service.recompute(3600)
    assert len(profiles) == 2
    assert created == 2
    assert all(profile.source_ref not in {"198.51.100.77", "203.0.113.89"} for profile in profiles)
    assert all(len(profile.source_ref) == 64 for profile in profiles)
    assert profiles[0].feature_schema_version == 1
    assert profiles[0].model_version == "attacker-profile-synthetic-v1"
    assert profiles[0].classification in {"reconnaissance", "authentication_probing", "repeated_connection", "suspicious_session", "multi_protocol", "unknown"}
    assert 0 <= profiles[0].anomaly_index <= 1
    assert profiles[0].cluster >= 0
    assert service.recompute(3600)[1] == 0
    assert len(service.list_profiles()[0]) == 2
    raw = path.read_bytes()
    assert b"198.51.100.77" not in raw
    assert b"DO_NOT_STORE_PASSWORD" not in raw
    assert b"user-0" not in raw


def test_genuine_cowrie_log_projection_persists_and_enters_source_ip_profile(tmp_path, models):
    from pathlib import Path
    from app.telemetry.cowrie import parse_cowrie_record
    from app.telemetry.service import TelemetryIngestionService

    class IsolatedLedger:
        def __init__(self):
            self.entries = []

        def append(self, event):
            self.entries.append(event)

    path = Path(__file__).parent / "fixtures" / "cowrie_events.jsonl"
    store = EventStore()
    ledger = IsolatedLedger()
    ingestion = TelemetryIngestionService(store, ledger)
    for line in path.read_text(encoding="utf-8").splitlines():
        envelope = parse_cowrie_record(line, sensor_id="cowrie-live-fixture")
        ingestion.ingest(envelope)

    events = store.list_events()
    expected_records = len(path.read_text(encoding="utf-8").splitlines())
    assert len(events) == len(ledger.entries) == expected_records == 8
    assert all(event.source == "external" and event.source_system == "cowrie" for event in events)
    assert all(event.sensor_id == "cowrie-live-fixture" and event.source_event_id for event in events)
    profile_service = AttackerProfileService(
        store, SQLiteProfileStorage(tmp_path / "cowrie-profiles.sqlite3"), model_bundle=models
    )
    profiles, _created = profile_service.recompute(3600)
    assert len(profiles) == 1
    assert profiles[0].observation_count == expected_records
    assert profiles[0].features["failed_auth_count"] == 1
    assert profiles[0].source_ref != "192.0.2.10"


def test_feature_window_drops_old_events_and_handles_missing_optional_fields():
    now = datetime.now(timezone.utc)
    older = external_event("old", "zeek_connection", now - timedelta(hours=2), source_system="zeek", protocol=None, attrs={})
    recent = external_event("recent", "cowrie_other", now, protocol=None, attrs={})
    features = extract_features([older, recent], window_seconds=600, as_of=now)
    assert features["event_count"] == 1
    assert features["connection_count"] == 0
    assert features["protocol_other_count"] == 1
    assert features["mean_inter_attempt_seconds"] == 0
    assert features["inter_attempts_available"] == 0
    with pytest.raises(ValueError, match="window_seconds"):
        extract_features([recent], window_seconds=10, as_of=now)


def test_profile_features_include_bounded_incident_counts_without_evidence_text(tmp_path, models):
    now = datetime.now(timezone.utc)
    events = EventStore()
    incident_storage = SQLiteIncidentStorage(tmp_path / "incidents.sqlite3")
    incident_service = IncidentService(incident_storage, window_seconds=300)
    for index in range(3):
        event = external_event(f"zeek-profile-{index}", "zeek_connection", now + timedelta(seconds=index), source_system="zeek", protocol="tcp")
        events.add_event(event)
        incident_service.inspect(event)
    service = AttackerProfileService(events, SQLiteProfileStorage(tmp_path / "profile-with-incidents.sqlite3"), incident_storage=incident_storage, model_bundle=models)
    profiles, _ = service.recompute(3600)
    assert profiles[0].features["incident_count"] == 1
    assert profiles[0].features["incident_rule_count"] >= 1
    serialized = profiles[0].model_dump_json()
    assert "repeated_zeek_connections" not in serialized
    assert "zeek-profile-0" not in serialized


def test_synthetic_dataset_and_training_are_reproducible_and_labeled_only_synthetically(models, tmp_path):
    first_rows, first_labels = generate_synthetic_dataset(10, 123)
    second_rows, second_labels = generate_synthetic_dataset(10, 123)
    assert first_rows == second_rows
    assert first_labels == second_labels
    assert len(first_rows) == 60
    assert set(first_labels) == {"reconnaissance", "authentication_probing", "repeated_connection", "suspicious_session", "multi_protocol", "unknown"}
    assert models["metadata"]["training_source"] == "explicit_synthetic_labeled_dataset"
    artifact = save_model_bundle(models, tmp_path / "profile-model.joblib")
    loaded = load_model_bundle(artifact)
    assert loaded["metadata"]["feature_schema_version"] == 1
    assert len(loaded["classifier"].classes_) == 6
    broken = dict(models)
    broken["metadata"] = {**models["metadata"], "feature_schema_version": 99}
    with pytest.raises(ProfileModelError, match="metadata"):
        validate_model_bundle(broken)


def test_training_rejects_insufficient_data():
    with pytest.raises(ValueError, match="samples_per_category"):
        generate_synthetic_dataset(2)


def test_profile_history_is_bounded_and_recommendation_is_advisory(tmp_path, models):
    now = datetime.now(timezone.utc)
    events = EventStore()
    storage = SQLiteProfileStorage(tmp_path / "history.sqlite3")
    service = AttackerProfileService(events, storage, model_bundle=models)
    for index in range(25):
        events.add_event(external_event(f"event-{index}", "cowrie_login_failed", now + timedelta(seconds=index), attrs={"authentication_outcome": "failed", "username": f"u{index}"}))
        profiles, _ = service.recompute(3600)
    profile = storage.get_profile(profiles[0].profile_id)
    assert profile is not None
    assert len(profile.history) <= 20
    recommendation = service.list_recommendations()[0][0]
    assert recommendation.status == "pending"
    assert "does not deploy" in " ".join(recommendation.risk_constraints)
    with pytest.raises(HTTPException, match="passing evaluation"):
        service.approve_recommendation(recommendation.recommendation_id)


def test_failed_evaluation_is_audited_and_cannot_be_approved(tmp_path, models):
    now = datetime.now(timezone.utc)
    events = EventStore()
    for index in range(4):
        events.add_event(external_event(f"fail-{index}", "cowrie_login_failed", now + timedelta(seconds=index), attrs={"authentication_outcome": "failed"}))
    storage = SQLiteProfileStorage(tmp_path / "failed.sqlite3")
    service = AttackerProfileService(events, storage, model_bundle=models, evaluation_runner=lambda: (_ for _ in ()).throw(RuntimeError("private path or telemetry must not leak")))
    service.recompute(3600)
    recommendation = service.list_recommendations()[0][0]
    evaluated = service.evaluate_recommendation(recommendation.recommendation_id)
    assert evaluated.status == "evaluation_failed"
    assert evaluated.evaluation is not None and evaluated.evaluation.outcome == "failed"
    assert "private path" not in evaluated.model_dump_json()
    with pytest.raises(HTTPException, match="passing evaluation"):
        service.approve_recommendation(recommendation.recommendation_id)


def test_isolated_recommendation_evaluation_and_explicit_approval(tmp_path, models, isolated_evaluation_summary):
    now = datetime.now(timezone.utc)
    events = EventStore()
    for index in range(8):
        events.add_event(external_event(f"auth-{index}", "cowrie_login_failed", now + timedelta(seconds=index), attrs={"authentication_outcome": "failed", "username": f"name-{index}"}))
    storage = SQLiteProfileStorage(tmp_path / "approved.sqlite3")
    service = AttackerProfileService(events, storage, model_bundle=models, evaluation_runner=lambda: isolated_evaluation_summary)
    profiles, _ = service.recompute(3600)
    recommendation, = service.list_recommendations()[0]
    # Confirm the classifier yields a defensible scenario for the synthetic auth-heavy fixture.
    assert recommendation.expected_scenario is not None
    evaluated = service.evaluate_recommendation(recommendation.recommendation_id)
    assert evaluated.evaluation is not None
    assert evaluated.evaluation.evaluation_kind == "isolated_synthetic_workflow_validation"
    assert evaluated.evaluation.measured_scenarios
    assert "Unavailable" in evaluated.evaluation.telemetry_coverage
    assert "Unavailable" in evaluated.evaluation.false_positive_risk
    assert evaluated.evaluation.outcome == "passed"
    assert evaluated.status == "evaluated"
    approved = service.approve_recommendation(recommendation.recommendation_id)
    assert approved.status == "approved"
    assert approved.status_history[-1].action == "approved"


@pytest.mark.parametrize("failure_mode", ["partial", "invalid_bundle", "missing_measurement"])
def test_incomplete_or_invalid_synthetic_evaluation_blocks_approval(tmp_path, models, isolated_evaluation_summary, failure_mode):
    from app.evaluation.models import EvaluationMetrics

    summary = isolated_evaluation_summary
    if failure_mode == "partial":
        summary = summary.model_copy(update={"status": "partial"})
    elif failure_mode == "invalid_bundle":
        from app.honeypot.bundles import BundleValidationIssue
        run_index = next(index for index, run in enumerate(summary.runs) if run.simulation_summary and run.simulation_summary.bundle_ids)
        run = summary.runs[run_index]
        sim = run.simulation_summary
        validations = list(sim.bundle_validation_results)
        validations[0] = validations[0].model_copy(update={"valid": False, "issues": [BundleValidationIssue(code="test_failure", message="synthetic invalid bundle")]})
        changed_sim = sim.model_copy(update={"bundle_validation_results": validations})
        runs = list(summary.runs)
        runs[run_index] = run.model_copy(update={"simulation_summary": changed_sim})
        overall = summary.overall.model_copy(update={"bundle_validation_failures": 1})
        summary = summary.model_copy(update={"runs": runs, "overall": overall})
    else:
        values = summary.overall.model_dump()
        values.pop("bundle_validation_failures")
        summary = summary.model_copy(update={"overall": EvaluationMetrics.model_validate(values)})

    now = datetime.now(timezone.utc)
    events = EventStore()
    for index in range(4):
        events.add_event(external_event(f"reject-{failure_mode}-{index}", "cowrie_login_failed", now + timedelta(seconds=index), attrs={"authentication_outcome": "failed"}))
    service = AttackerProfileService(events, SQLiteProfileStorage(tmp_path / f"{failure_mode}.sqlite3"), model_bundle=models, evaluation_runner=lambda: summary)
    service.recompute(3600)
    recommendation = service.list_recommendations()[0][0]
    failed = service.evaluate_recommendation(recommendation.recommendation_id)
    assert failed.status == "evaluation_failed"
    assert failed.evaluation is not None and failed.evaluation.outcome == "failed"
    with pytest.raises(HTTPException, match="passing evaluation"):
        service.approve_recommendation(recommendation.recommendation_id)


def test_profile_api_routes_validate_bounds_and_return_persisted_data(tmp_path, models, monkeypatch):
    from app.api import routes
    from app.main import app

    now = datetime.now(timezone.utc)
    events = EventStore()
    for index in range(4):
        events.add_event(external_event(f"api-{index}", "cowrie_login_failed", now + timedelta(seconds=index), attrs={"authentication_outcome": "failed"}))
    service = AttackerProfileService(events, SQLiteProfileStorage(tmp_path / "api.sqlite3"), model_bundle=models)
    service.recompute(3600)
    monkeypatch.setattr(routes, "attacker_profile_service", service)
    client = TestClient(app)
    assert client.get("/api/v1/profiles?limit=0").status_code == 422
    listed = client.get("/api/v1/profiles")
    assert listed.status_code == 200
    profile_id = listed.json()["items"][0]["profile_id"]
    assert client.get(f"/api/v1/profiles/{profile_id}").json()["profile_id"] == profile_id
    assert client.get("/api/v1/profiles/stats").status_code == 200
    recs = client.get("/api/v1/deception/recommendations").json()["items"]
    assert len(recs) == 1
    assert client.post(f"/api/v1/deception/recommendations/{recs[0]['recommendation_id']}/approve").status_code == 409
    assert client.post("/api/v1/profiles/recompute", json={"window_seconds": 10}).status_code == 422
