import asyncio
import pytest
from fastapi.testclient import TestClient

from app.api import routes
from app.events.models import HoneypotEvent
from app.events.store import EventStore, event_store
from app.ledger.service import EventLedger, event_ledger
from app.ledger.storage import SQLiteLedgerStorage
from app.main import app
from app.telemetry.live import LiveUpdateHub
from app.telemetry.service import TelemetryIngestionService


client = TestClient(app)
TOKEN = "test-telemetry-ingest-token-0123456789"


@pytest.fixture(autouse=True)
def isolate_live_telemetry(monkeypatch):
    event_store.clear()
    event_ledger.clear()
    routes.telemetry_alert_service.clear()
    monkeypatch.setenv("HONEYPOT_TELEMETRY_INGEST_TOKEN", TOKEN)
    yield
    event_store.clear()
    event_ledger.clear()
    routes.telemetry_alert_service.clear()


def payload(**updates):
    data = {
        "source_system": "generic",
        "sensor_id": "sensor-test-01",
        "external_event_id": "evt-0001",
        "occurred_at": "2026-11-02T12:00:00Z",
        "event_type": "port_scan_detected",
        "severity": "high",
        "source_ip": "192.0.2.15",
        "destination_ip": "198.51.100.9",
        "destination_port": 443,
        "protocol": "tcp",
        "attributes": {"count": 12, "tags": ["synthetic", "network"]},
    }
    data.update(updates)
    return data


def ingest(body=None, **kwargs):
    return client.post(
        "/api/v1/telemetry/ingest",
        json=payload(**kwargs) if body is None else body,
        headers={"Authorization": f"Bearer {TOKEN}"},
    )


def test_ingestion_requires_configured_bearer_token(monkeypatch):
    monkeypatch.delenv("HONEYPOT_TELEMETRY_INGEST_TOKEN")
    assert client.post("/api/v1/telemetry/ingest", json=payload()).status_code == 503
    monkeypatch.setenv("HONEYPOT_TELEMETRY_INGEST_TOKEN", "too-short")
    assert client.post("/api/v1/telemetry/ingest", json=payload()).status_code == 503
    monkeypatch.setenv("HONEYPOT_TELEMETRY_INGEST_TOKEN", TOKEN)
    assert client.post("/api/v1/telemetry/ingest", json=payload()).status_code == 401
    assert client.post(
        "/api/v1/telemetry/ingest",
        json=payload(),
        headers={"Authorization": "Bearer wrong-token"},
    ).status_code == 401
    assert event_store.count_events() == 0
    assert event_ledger.list_entries() == []


def test_openapi_documents_normalized_ingestion_request():
    schema = client.get("/openapi.json").json()
    request_schema = schema["paths"]["/api/v1/telemetry/ingest"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert request_schema["properties"]["sensor_id"]["type"] == "string"
    assert request_schema["properties"]["attributes"]["type"] == "object"


def test_ingestion_normalizes_stores_ledgers_and_alerts_external_event():
    response = ingest()
    assert response.status_code == 201
    result = response.json()
    event = result["event"]
    assert result["accepted"] is True
    assert result["duplicate"] is False
    assert event["source"] == "external"
    assert event["event_type"] == "external_telemetry"
    assert event["telemetry_event_type"] == "port_scan_detected"
    assert event["source_ip"] == "192.0.2.15"
    assert event["attributes"]["count"] == 12
    assert event_store.get_event(event["event_id"]) is not None
    assert event_ledger.list_entries()[0].event_data["event_id"] == event["event_id"]
    assert result["alert"]["rule"] == "external_high_severity"
    assert client.get("/api/v1/telemetry/alerts").json()[0]["event_id"] == event["event_id"]


def test_duplicate_ingestion_is_idempotent_and_conflicting_replay_is_rejected():
    first = ingest()
    duplicate = ingest()
    assert first.status_code == 201
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True
    assert duplicate.json()["event"]["event_id"] == first.json()["event"]["event_id"]
    assert event_store.count_events() == 1
    assert len(event_ledger.list_entries()) == 1
    assert len(routes.telemetry_alert_service.list_alerts()) == 1

    conflict = ingest(attributes={"count": 13})
    assert conflict.status_code == 409
    assert event_store.count_events() == 1
    assert len(event_ledger.list_entries()) == 1


def test_external_event_deduplication_survives_event_store_recreation(tmp_path):
    database = tmp_path / "isolated-ledger.sqlite3"
    first_store = EventStore()
    first_ledger = EventLedger(SQLiteLedgerStorage(database))
    first_service = TelemetryIngestionService(first_store, first_ledger)
    from app.events.models import TelemetryIngestRequest

    request = TelemetryIngestRequest.model_validate(payload())
    first_event, created = first_service.ingest(request)
    assert created is True

    second_store = EventStore()
    second_ledger = EventLedger(SQLiteLedgerStorage(database))
    for entry in second_ledger.list_entries():
        second_store.add_event(HoneypotEvent.model_validate(entry.event_data))
    second_service = TelemetryIngestionService(second_store, second_ledger)
    replayed_event, created = second_service.ingest(request)
    assert created is False
    assert replayed_event.event_id == first_event.event_id
    assert len(second_ledger.list_entries()) == 1


@pytest.mark.parametrize(
    "body,expected_status",
    [
        ({"sensor_id": "bad id"}, 422),
        ({"occurred_at": "2026-11-02T12:00:00"}, 422),
        ({"unknown_field": "not accepted"}, 422),
        ({"attributes": {"deep": {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}}}, 422),
    ],
)
def test_malformed_or_unsupported_fields_are_rejected(body, expected_status):
    response = ingest(body=payload(**body))
    assert response.status_code == expected_status
    assert event_store.count_events() == 0
    assert event_ledger.list_entries() == []


def test_malformed_json_and_oversized_body_are_rejected():
    malformed = client.post(
        "/api/v1/telemetry/ingest",
        content=b"{not-json",
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
    )
    oversized = client.post(
        "/api/v1/telemetry/ingest",
        content=b" " * (32 * 1024 + 1),
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
    )
    assert malformed.status_code == 400
    assert oversized.status_code == 413
    assert event_store.count_events() == 0


def test_alert_rules_ignore_simulator_events_and_flag_suspicious_external_types():
    simulator = HoneypotEvent(
        event_id="sim-event",
        decoy_id="decoy-finance-001",
        actor_id="sim-actor",
        action="read",
        source="simulator",
        event_type="decoy_interaction",
    )
    assert routes.telemetry_alert_service.inspect(simulator) is None
    response = ingest(severity="low", event_type="credential_stuffing")
    assert response.status_code == 201
    assert response.json()["alert"]["rule"] == "external_suspicious_event_type"


def test_sse_hub_fans_out_bounded_sanitized_event_summaries():
    async def run():
        hub = LiveUpdateHub(queue_size=1)
        subscriber_id, queue = hub.subscribe()
        event = HoneypotEvent(
            event_id="external-test-id",
            decoy_id="external-telemetry",
            actor_id="sensor-hash",
            action="port_scan",
            event_type="external_telemetry",
            source="external",
            attributes={"private_payload": "must not be in the stream"},
        )
        hub.publish_event(event)
        await asyncio.sleep(0)
        message = await queue.get()
        hub.unsubscribe(subscriber_id)
        assert message["kind"] == "event"
        assert message["data"]["event_id"] == event.event_id
        assert "private_payload" not in hub.encode(message)

    asyncio.run(run())


def test_sse_endpoint_replays_recent_event_summaries_without_attributes():
    event = HoneypotEvent(
        event_id="sse-event-001",
        decoy_id="external-telemetry",
        actor_id="external-sensor-hash",
        action="port_scan",
        event_type="external_telemetry",
        source="external",
        source_system="generic",
        telemetry_event_type="port_scan",
        attributes={"raw": "must stay out of browser stream"},
    )
    event_store.add_event(event)

    async def run():
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        from starlette.requests import Request

        request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/api/v1/telemetry/stream",
                "raw_path": b"/api/v1/telemetry/stream",
                "query_string": b"",
                "headers": [],
                "client": ("127.0.0.1", 12345),
                "server": ("127.0.0.1", 8000),
                "scheme": "http",
                "http_version": "1.1",
                "asgi": {"version": "3.0", "spec_version": "2.3"},
            },
            receive,
        )
        response = await routes.stream_live_updates(request, after_event_id=None)
        iterator = response.body_iterator
        retry_frame = await anext(iterator)
        assert retry_frame == "retry: 3000\n\n"
        event_frame = await anext(iterator)
        assert "event: event\n" in event_frame
        assert "sse-event-001" in event_frame
        assert "must stay out of browser stream" not in event_frame
        await iterator.aclose()

    asyncio.run(run())


def test_simulator_interaction_source_remains_distinct_from_external():
    simulator = client.post(
        "/api/v1/decoys/decoy-finance-001/interactions",
        json={"actor_id": "telemetry-compat-test", "action": "read"},
    )
    external = ingest()
    assert simulator.status_code == 201
    assert simulator.json()["source"] == "simulator"
    assert external.status_code == 201
    assert external.json()["event"]["source"] == "external"

