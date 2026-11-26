import json
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes
from app.events.store import EventStore
from app.incidents.service import IncidentService
from app.incidents.storage import SQLiteIncidentStorage
from app.ledger.service import EventLedger
from app.ledger.storage import SQLiteLedgerStorage
from app.profiling.models_ml import train_profile_models
from app.profiling.service import AttackerProfileService
from app.profiling.storage import SQLiteProfileStorage
from app.telemetry.alerts import TelemetryAlertService
from app.telemetry.live import LiveUpdateHub
from app.telemetry.service import TelemetryIngestionService


def test_telemetry_dashboard_api_flow_is_isolated_and_reviewable(tmp_path, monkeypatch):
    token = "isolated-dashboard-test-token-0123456789abcdef"
    source_ip = "198.51.100.42"
    event_store = EventStore()
    ledger = EventLedger(SQLiteLedgerStorage(tmp_path / "ledger.sqlite3"))
    incident_storage = SQLiteIncidentStorage(tmp_path / "incidents.sqlite3")
    alerts = TelemetryAlertService()

    monkeypatch.setenv("HONEYPOT_TELEMETRY_INGEST_TOKEN", token)
    monkeypatch.delenv("HONEYPOT_INTEL_COLLECTOR_URL", raising=False)
    monkeypatch.setattr(routes, "event_store", event_store)
    monkeypatch.setattr(routes, "event_ledger", ledger)
    monkeypatch.setattr(routes, "telemetry_ingestion_service", TelemetryIngestionService(event_store, ledger))
    monkeypatch.setattr(routes, "telemetry_alert_service", alerts)
    monkeypatch.setattr(routes, "live_update_hub", LiveUpdateHub())
    monkeypatch.setattr(routes, "incident_service", IncidentService(incident_storage))
    monkeypatch.setattr(
        routes,
        "attacker_profile_service",
        AttackerProfileService(
            event_store,
            SQLiteProfileStorage(tmp_path / "profiles.sqlite3"),
            incident_storage=incident_storage,
            model_bundle=train_profile_models(samples_per_category=12, random_seed=917),
        ),
    )
    event_store.subscribe(routes._on_event_recorded)

    app = FastAPI()
    app.include_router(routes.router)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    start = datetime.now(timezone.utc)

    # These realistic sensor records are intentionally synthetic fixtures.
    raw_records = []
    for index in range(3):
        raw_records.append(
            {
                "eventid": "cowrie.login.failed",
                "timestamp": (start + timedelta(seconds=index)).isoformat(),
                "session": f"fixture-session-{index}",
                "src_ip": source_ip,
                "src_port": 42000 + index,
                "dst_ip": "192.0.2.22",
                "dst_port": 2222,
                "username": f"fixture-user-{index}",
                "password": "FIXTURE_PASSWORD_MUST_NOT_LEAK",
            }
        )

    from app.telemetry.cowrie import parse_cowrie_record

    ingested = []
    for raw in raw_records:
        normalized = parse_cowrie_record(
            json.dumps(raw), sensor_id="dashboard-fixture-sensor"
        )
        response = client.post(
            "/api/v1/telemetry/ingest",
            json=normalized.model_dump(mode="json"),
            headers=headers,
        )
        assert response.status_code == 201
        ingested.append(response.json())
        assert "FIXTURE_PASSWORD_MUST_NOT_LEAK" not in response.text
        assert "fixture-user-" not in response.text

    replay = parse_cowrie_record(
        json.dumps(raw_records[0]), sensor_id="dashboard-fixture-sensor"
    )
    duplicate = client.post(
        "/api/v1/telemetry/ingest", json=replay.model_dump(mode="json"), headers=headers
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True
    assert len(ledger.list_entries()) == 3

    suricata_alert = {
        "source_system": "suricata",
        "sensor_id": "dashboard-synthetic-alert",
        "external_event_id": "fixture-alert-001",
        "occurred_at": start.isoformat(),
        "event_type": "suricata_alert",
        "severity": "high",
        "source_ip": source_ip,
        "protocol": "tcp",
        "attributes": {"signature": "Synthetic dashboard-only alert"},
    }
    alert_response = client.post(
        "/api/v1/telemetry/ingest", json=suricata_alert, headers=headers
    )
    assert alert_response.status_code == 201

    cowrie_rows = client.get("/api/v1/telemetry/cowrie/events").json()
    live_rows = client.get("/api/v1/events").json()
    alert_rows = client.get("/api/v1/telemetry/alerts").json()
    incident_page = client.get("/api/v1/incidents").json()
    assert len(cowrie_rows) == 3
    assert len(live_rows) == 4
    assert len(alert_rows) == 1
    assert alert_rows[0]["rule"] == "suricata_eve_alert"
    assert "cowrie_correlated_suricata_alert" in incident_page["items"][0]["detection_rules"]
    assert "cowrie_repeated_failed_authentication" in incident_page["items"][0]["detection_rules"]
    assert all("FIXTURE_PASSWORD_MUST_NOT_LEAK" not in json.dumps(row) for row in cowrie_rows)

    recomputed = client.post(
        "/api/v1/profiles/recompute", json={"window_seconds": 3600}
    )
    assert recomputed.status_code == 200
    assert recomputed.json()["profiles_updated"] == 1
    assert recomputed.json()["model_version"] == "attacker-profile-synthetic-v1"
    profile_id = recomputed.json()["profiles"][0]["profile_id"]
    profile = client.get(f"/api/v1/profiles/{profile_id}").json()
    assert profile["observation_count"] == 4
    assert profile["features"]["failed_auth_count"] == 3
    assert profile["source_ref"] != source_ip
    recommendation_rows = client.get("/api/v1/deception/recommendations").json()["items"]
    assert len(recommendation_rows) == 1
    assert recommendation_rows[0]["status"] == "pending"

    verification = client.get("/api/v1/ledger/verify").json()
    assert verification["valid"] is True
    assert verification["entries_checked"] == 4

    monkeypatch.delenv("HONEYPOT_NODE_DASHBOARD_URL", raising=False)
    node_status = client.get("/api/v1/network-node/dashboard")
    assert node_status.status_code == 503
    assert "not configured" in node_status.json()["detail"].lower()
