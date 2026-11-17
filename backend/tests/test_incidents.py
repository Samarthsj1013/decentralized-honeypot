import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.events.models import HoneypotEvent
from app.incidents.service import IncidentService
from app.incidents.storage import SQLiteIncidentStorage


def event(event_id, source_system, event_type, *, offset=0, sensor="sensor-a", severity="medium", port=443, source_ip="192.0.2.44", source="external"):
    return HoneypotEvent(
        event_id=event_id,
        timestamp=datetime(2026, 11, 6, 10, 0, tzinfo=timezone.utc) + timedelta(seconds=offset),
        decoy_id="external-telemetry",
        actor_id="hashed-sensor-reference",
        action=event_type,
        event_type="external_telemetry" if source == "external" else "decoy_interaction",
        source=source,
        source_system=source_system,
        sensor_id=sensor,
        telemetry_event_type=event_type,
        source_ip=source_ip,
        destination_port=port,
        severity=severity,
        attributes={"private_payload": "must not be persisted"},
    )


def cowrie_event(event_id, event_type, *, offset=0, session_ref="session-a", auth=None, command=False, source_ip="192.0.2.44"):
    attributes = {"session_id": session_ref, "command_attempt": command}
    if auth:
        attributes["authentication_outcome"] = auth
    return HoneypotEvent(
        event_id=event_id,
        timestamp=datetime(2026, 11, 6, 10, 0, tzinfo=timezone.utc) + timedelta(seconds=offset),
        decoy_id="external-telemetry", actor_id="hashed-sensor-reference", action=event_type,
        event_type="external_telemetry", source="external", source_system="cowrie",
        sensor_id="cowrie-a", telemetry_event_type=event_type, source_ip=source_ip,
        severity="medium", attributes=attributes,
    )


@pytest.fixture
def service(tmp_path):
    return IncidentService(SQLiteIncidentStorage(tmp_path / "incidents.sqlite3"), window_seconds=300)


def test_alert_then_multiple_zeek_connections_create_persistent_incident(service):
    assert service.inspect(event("alert-1", "suricata", "suricata_alert", offset=0, severity="high")) is None
    first_incident = service.inspect(event("conn-1", "zeek", "zeek_connection", offset=10, sensor="sensor-b"))
    assert first_incident is not None
    assert "multi_sensor_activity" in first_incident.detection_rules
    incident = service.inspect(event("conn-2", "zeek", "zeek_connection", offset=20, sensor="sensor-b"))
    assert incident is not None
    assert incident.incident_id == first_incident.incident_id
    assert incident.status == "open"
    assert incident.severity == "high"
    assert "alert_then_zeek_connections" in incident.detection_rules
    assert set(incident.contributing_event_ids) == {"alert-1", "conn-1", "conn-2"}
    assert all("private_payload" not in summary for summary in incident.evidence_summary)
    reloaded = IncidentService(SQLiteIncidentStorage(service.storage.database_path), window_seconds=300)
    assert reloaded.get(incident.incident_id) == incident


@pytest.mark.parametrize(
    "events,expected_rule",
    [
        ([event(f"a{i}", "suricata", "suricata_alert", offset=i, severity="high") for i in range(2)], "multiple_suricata_alerts"),
        ([event(f"z{i}", "zeek", "zeek_connection", offset=i) for i in range(3)], "repeated_zeek_connections"),
        ([event(f"p{i}", "zeek", "zeek_connection", offset=i, port=1000+i) for i in range(3)], "multiple_destination_ports"),
        ([event("s1", "zeek", "zeek_connection", offset=0, sensor="sensor-a"), event("s2", "suricata", "suricata_flow", offset=1, sensor="sensor-b")], "multi_sensor_activity"),
        ([event("e1", "zeek", "zeek_connection", offset=0, severity="low"), event("e2", "zeek", "zeek_connection", offset=1, severity="medium"), event("e3", "zeek", "zeek_connection", offset=2, severity="high")], "suspicious_activity_escalation"),
    ],
)
def test_detection_rules(events, expected_rule, tmp_path):
    service = IncidentService(SQLiteIncidentStorage(tmp_path / f"{expected_rule}.sqlite3"), 300)
    result = None
    for item in events:
        result = service.inspect(item)
    assert result is not None
    assert expected_rule in result.detection_rules


def test_simulator_and_unrelated_source_events_are_ignored(service):
    assert service.inspect(event("sim", "zeek", "zeek_connection", source="simulator")) is None
    assert service.inspect(event("generic", "generic", "suspicious", offset=1)) is None
    assert service.stats()["total"] == 0


def test_same_sensor_reporting_two_sources_does_not_count_as_multi_sensor(service):
    assert service.inspect(event("zeek-one", "zeek", "zeek_connection", sensor="shared-sensor")) is None
    assert service.inspect(event("suri-one", "suricata", "suricata_flow", offset=1, sensor="shared-sensor")) is None


@pytest.mark.parametrize(
    "sequence,rule,expected_severity",
    [
        ([cowrie_event(f"fail-{i}", "cowrie_login_failed", offset=i, auth="failed") for i in range(3)], "cowrie_repeated_failed_authentication", "medium"),
        ([cowrie_event(f"auth-fail-{i}", "cowrie_login_failed", offset=i, auth="failed") for i in range(3)] + [cowrie_event("auth-success", "cowrie_login_success", offset=4, auth="success")], "cowrie_success_after_repeated_failures", "high"),
        ([cowrie_event(f"command-{i}", "cowrie_command_attempt", offset=i, command=True) for i in range(3)], "cowrie_multiple_commands_in_session", "medium"),
        ([cowrie_event(f"session-{i}", "cowrie_session_connected", offset=i) for i in range(3)], "cowrie_repeated_sessions_from_source", "medium"),
    ],
)
def test_cowrie_ssh_rules_are_explainable_and_do_not_claim_compromise(sequence, rule, expected_severity, tmp_path):
    service = IncidentService(SQLiteIncidentStorage(tmp_path / f"{rule}.sqlite3"), 300)
    result = None
    for item in sequence:
        result = service.inspect(item)
    assert result is not None
    assert rule in result.detection_rules
    assert result.severity == expected_severity
    assert result.confidence <= 0.95
    if rule == "cowrie_success_after_repeated_failures":
        assert any("not proof of compromise" in note for note in result.evidence_summary)


@pytest.mark.parametrize(
    "second,rule",
    [
        (event("zeek-cowrie", "zeek", "zeek_connection", offset=1, sensor="zeek-b"), "cowrie_correlated_zeek_connections"),
        (event("suri-cowrie", "suricata", "suricata_alert", offset=1, sensor="suri-b", severity="high"), "cowrie_correlated_suricata_alert"),
    ],
)
def test_cowrie_correlates_with_existing_network_sources(second, rule, tmp_path):
    service = IncidentService(SQLiteIncidentStorage(tmp_path / f"{rule}.sqlite3"), 300)
    first = cowrie_event("cowrie-connect", "cowrie_session_connected", offset=0)
    assert service.inspect(first) is None
    result = service.inspect(second)
    assert result is not None
    assert rule in result.detection_rules


def test_events_outside_window_do_not_correlate(service):
    service.inspect(event("old-1", "zeek", "zeek_connection", offset=0))
    service.inspect(event("old-2", "zeek", "zeek_connection", offset=1))
    assert service.inspect(event("new", "zeek", "zeek_connection", offset=400)) is None


def test_new_correlation_window_creates_a_separate_incident(service):
    for index in range(3):
        first = service.inspect(event(f"first-{index}", "zeek", "zeek_connection", offset=index))
    for index in range(3):
        second = service.inspect(event(f"later-{index}", "zeek", "zeek_connection", offset=400 + index))
    assert first is not None and second is not None
    assert second.incident_id != first.incident_id
    assert service.stats()["total"] == 2


def test_incident_lifecycle_is_explicit_and_ack_after_resolve_rejected(service):
    for index in range(3):
        incident = service.inspect(event(f"conn-{index}", "zeek", "zeek_connection", offset=index))
    assert incident is not None
    acknowledged = service.transition(incident.incident_id, "acknowledged")
    assert acknowledged.status == "acknowledged"
    resolved = service.transition(incident.incident_id, "resolved")
    assert resolved.status == "resolved"
    with pytest.raises(HTTPException) as error:
        service.transition(incident.incident_id, "acknowledged")
    assert error.value.status_code == 409
    assert service.stats()["resolved"] == 1


def test_new_matching_evidence_reopens_resolved_incident(service):
    for index in range(3):
        incident = service.inspect(event(f"a-{index}", "zeek", "zeek_connection", offset=index))
    service.transition(incident.incident_id, "resolved")
    reopened = service.inspect(event("a-new", "zeek", "zeek_connection", offset=4))
    assert reopened is not None
    assert reopened.incident_id == incident.incident_id
    assert reopened.status == "open"


def test_storage_is_lazy_and_evidence_is_bounded(tmp_path):
    path = tmp_path / "not-created-until-use" / "incidents.sqlite3"
    storage = SQLiteIncidentStorage(path)
    assert not path.exists()
    service = IncidentService(storage, 300)
    for index in range(3):
        incident = service.inspect(event(f"bound-{index}", "zeek", "zeek_connection", offset=index))
    assert incident is not None
    assert not hasattr(incident, "attributes")
    assert path.exists()


def test_incident_api_pagination_filters_and_actions_use_injected_temp_store(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.api import routes
    from app.events.store import event_store
    from app.main import app

    service = IncidentService(SQLiteIncidentStorage(tmp_path / "api.sqlite3"), 300)
    monkeypatch.setattr(routes, "incident_service", service)
    event_store.clear()
    for index in range(3):
        service.inspect(event(f"api-{index}", "zeek", "zeek_connection", offset=index))
    for index in range(3):
        event_store.add_event(event(f"api-list-{index}", "generic", "other", offset=index))
    client = TestClient(app)
    page = client.get("/api/v1/incidents?limit=1&offset=0")
    assert page.status_code == 200
    assert page.json()["total"] == 1
    incident_id = page.json()["items"][0]["incident_id"]
    assert client.get("/api/v1/incidents/stats").json()["open"] == 1
    assert client.get(f"/api/v1/incidents/{incident_id}").status_code == 200
    assert client.post(f"/api/v1/incidents/{incident_id}/acknowledge").json()["status"] == "acknowledged"
    assert client.post(f"/api/v1/incidents/{incident_id}/resolve").json()["status"] == "resolved"
    assert client.get("/api/v1/incidents?status=invalid").status_code == 422


def test_telemetry_ingestion_updates_incidents_after_ledger_acceptance(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from uuid import uuid4
    from app.api import routes
    from app.events.store import event_store
    from app.ledger.service import EventLedger
    from app.ledger.storage import SQLiteLedgerStorage
    from app.main import app
    from app.telemetry.service import TelemetryIngestionService

    service = IncidentService(SQLiteIncidentStorage(tmp_path / "ingested-incidents.sqlite3"), 300)
    monkeypatch.setattr(routes, "incident_service", service)
    isolated_ledger = EventLedger(SQLiteLedgerStorage(tmp_path / "ingested-ledger.sqlite3"))
    monkeypatch.setattr(routes, "telemetry_ingestion_service", TelemetryIngestionService(event_store, isolated_ledger))
    token = "incident-test-token-0123456789-extra"
    monkeypatch.setenv("HONEYPOT_TELEMETRY_INGEST_TOKEN", token)
    event_store.clear()
    client = TestClient(app)
    prefix = uuid4().hex

    def ingest(sensor_id, event_id, source_system, event_type, second):
        return client.post("/api/v1/telemetry/ingest", headers={"Authorization": f"Bearer {token}"}, json={
            "source_system": source_system, "sensor_id": sensor_id,
            "external_event_id": f"{prefix}-{event_id}",
            "occurred_at": f"2026-11-06T10:00:{second:02d}Z",
            "event_type": event_type, "severity": "high",
            "source_ip": "198.51.100.31", "destination_ip": "203.0.113.9",
            "destination_port": 443, "protocol": "tcp", "attributes": {},
        })

    first_response = ingest("suri-a", "alert", "suricata", "suricata_alert", 0)
    assert first_response.status_code == 201, first_response.text
    assert ingest("zeek-b", "conn-1", "zeek", "zeek_connection", 1).status_code == 201
    accepted = ingest("zeek-b", "conn-2", "zeek", "zeek_connection", 2)
    assert accepted.status_code == 201
    assert isolated_ledger.verify_chain().valid
    page = client.get("/api/v1/incidents?source_ip=198.51.100.31").json()
    assert page["total"] == 1
    assert "alert_then_zeek_connections" in page["items"][0]["detection_rules"]


def test_incident_database_is_not_initialized_on_module_import(tmp_path, monkeypatch):
    from app.api import routes

    isolated_storage = SQLiteIncidentStorage(tmp_path / "incidents.sqlite3")
    monkeypatch.setattr(routes.incident_service, "storage", isolated_storage)

    assert isolated_storage._initialized is False
    assert not isolated_storage.database_path.exists()

def test_live_incident_notification_contains_only_refresh_identifier():
    from app.telemetry.live import LiveUpdateHub

    async def run():
        hub = LiveUpdateHub()
        subscriber_id, queue = hub.subscribe()
        hub.publish_incident("incident-safe-id")
        await asyncio.sleep(0)
        message = await queue.get()
        hub.unsubscribe(subscriber_id)
        assert message["kind"] == "incident"
        assert message["data"] == {"incident_id": "incident-safe-id"}
        assert "198.51.100" not in hub.encode(message)

    asyncio.run(run())
