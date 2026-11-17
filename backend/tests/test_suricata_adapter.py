import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.events.store import EventStore
from app.ledger.service import EventLedger
from app.ledger.storage import SQLiteLedgerStorage
from app.telemetry.alerts import TelemetryAlertService
from app.telemetry.service import TelemetryIngestionService
from app.telemetry.suricata import MAX_EVE_LINE_BYTES, SuricataRecordError, parse_eve_record
from app.telemetry import suricata_cli


FIXTURE = Path(__file__).parent / "fixtures" / "suricata_eve.jsonl"


def records():
    return [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]


def test_eve_fixture_parses_all_supported_types_and_maps_fields():
    source = records()
    parsed = [parse_eve_record(json.dumps(item), sensor_id="suricata-lab-01") for item in source]
    assert [event.attributes["event_type"] for event in parsed] == [
        "alert", "flow", "dns", "http", "tls", "ssh", "fileinfo"
    ]
    alert = parsed[0]
    assert alert.source_system == "suricata"
    assert alert.event_type == "suricata_alert"
    assert alert.severity == "high"
    assert alert.external_event_id.startswith("eve-")
    assert alert.occurred_at.isoformat() == "2026-11-05T10:15:30.125000+00:00"
    assert str(alert.source_ip) == "192.0.2.10"
    assert alert.source_port == 51514
    assert str(alert.destination_ip) == "198.51.100.20"
    assert alert.destination_port == 443
    assert alert.protocol == "TCP"
    assert alert.attributes["alert"]["signature"] == "ET SCAN Suspicious inbound connection"
    assert alert.attributes["alert"]["category"] == "Attempted Information Leak"
    assert alert.attributes["flow"]["bytes_toserver"] == 512
    assert "payload" not in alert.attributes
    assert parsed[1].attributes["flow"]["state"] == "closed"
    assert parsed[2].attributes["dns"]["answers"] == ["198.51.100.9"]
    assert parsed[3].attributes["http"]["http_method"] == "GET"
    assert parsed[4].attributes["tls"]["sni"] == "example.test"
    assert parsed[5].attributes["ssh"]["client_hassh"] == "deadbeef"
    assert parsed[6].attributes["fileinfo"]["sha256"].startswith("012345")


@pytest.mark.parametrize("suricata_severity,expected", [(1, "high"), (2, "medium"), (3, "low"), ("low", "low")])
def test_only_high_severity_alert_records_map_to_high(suricata_severity, expected):
    record = {"timestamp": "2026-11-05T10:15:30Z", "event_type": "alert", "alert": {"severity": suricata_severity}}
    event = parse_eve_record(json.dumps(record), sensor_id="sensor-1")
    assert event.severity == expected


def test_non_alert_suricata_events_are_not_labeled_suspicious():
    event = parse_eve_record(json.dumps({
        "timestamp": "2026-11-05T10:15:30Z", "event_type": "dns",
        "dns": {"rrname": "ordinary.example"},
    }), sensor_id="sensor-1")
    assert event.severity == "low"
    assert event.event_type == "suricata_dns"


def test_only_suricata_alert_event_types_create_suricata_dashboard_alerts(tmp_path):
    ledger = EventLedger(SQLiteLedgerStorage(tmp_path / "ledger.sqlite3"))
    service = TelemetryIngestionService(EventStore(), ledger)
    alerts = TelemetryAlertService()
    routine = parse_eve_record(json.dumps({
        "timestamp": "2026-11-05T10:15:30Z", "event_type": "dns",
        "dns": {"rrname": "ordinary.example"},
    }), sensor_id="sensor-1")
    detected = parse_eve_record(json.dumps({
        "timestamp": "2026-11-05T10:15:31Z", "event_type": "alert",
        "alert": {"signature": "Example signature", "severity": 3},
    }), sensor_id="sensor-1")
    routine_event, _ = service.ingest(routine)
    detected_event, _ = service.ingest(detected)
    assert routine_event.severity == "low"
    assert alerts.inspect(routine_event) is None
    generated = alerts.inspect(detected_event)
    assert generated is not None
    assert generated.severity == "low"
    assert generated.rule == "suricata_eve_alert"


def test_alert_ingestion_uses_existing_alert_and_dashboard_event_model(tmp_path):
    event = parse_eve_record(json.dumps(records()[0]), sensor_id="sensor-1")
    ledger = EventLedger(SQLiteLedgerStorage(tmp_path / "ledger.sqlite3"))
    service = TelemetryIngestionService(EventStore(), ledger)
    stored, created = service.ingest(event)
    alert = TelemetryAlertService().inspect(stored)
    assert created is True
    assert stored.source_system == "suricata"
    assert stored.telemetry_event_type == "suricata_alert"
    assert alert is not None
    assert alert.rule == "suricata_eve_alert"
    assert alert.event_type == "suricata_alert"


@pytest.mark.parametrize("record", [
    b"{not-json}", b"[]", b"null",
    b'{"timestamp":"2026-11-05T10:15:30","event_type":"flow"}',
    b'{"timestamp":"bad","event_type":"flow"}',
    b'{"timestamp":"2026-11-05T10:15:30Z","event_type":"flow","src_ip":"not-an-ip"}',
])
def test_malformed_or_missing_required_values_are_rejected(record):
    with pytest.raises(SuricataRecordError):
        parse_eve_record(record, sensor_id="sensor-1")


def test_unknown_event_type_is_preserved_as_benign_unknown_event():
    event = parse_eve_record(json.dumps({
        "timestamp": "2026-11-05T10:15:30Z", "event_type": "stats",
        "stats": {"capture": {"kernel_drops": 1}},
    }), sensor_id="sensor-1")
    assert event.event_type == "suricata_unknown"
    assert event.attributes == {"event_type": "stats"}
    assert event.severity == "low"


def test_projected_fields_and_record_size_are_bounded_and_private_fields_omitted():
    record = records()[0]
    record["payload"] = "x" * 200_000
    event = parse_eve_record(json.dumps(record), sensor_id="sensor-1")
    assert "payload" not in event.attributes
    record["alert"]["signature"] = "x" * 1025
    with pytest.raises(SuricataRecordError, match="string exceeds"):
        parse_eve_record(json.dumps(record), sensor_id="sensor-1")
    with pytest.raises(SuricataRecordError, match="maximum line size"):
        parse_eve_record(b" " * (MAX_EVE_LINE_BYTES + 1), sensor_id="sensor-1")


def test_http_query_and_fragment_values_are_filtered_from_shared_attributes():
    event = parse_eve_record(json.dumps({
        "timestamp": "2026-11-05T10:15:30Z", "event_type": "http",
        "http": {
            "url": "/search?access_token=private#fragment",
            "http_refer": "https://example.test/from?session=private#top",
            "http_method": "GET",
        },
    }), sensor_id="sensor-1")
    assert event.attributes["http"]["url"] == "/search"
    assert event.attributes["http"]["http_refer"] == "/from"
    assert "private" not in event.model_dump_json()


def test_identical_record_has_stable_external_event_id():
    record = records()[0]
    one = parse_eve_record(json.dumps(record), sensor_id="sensor-1")
    two = parse_eve_record(json.dumps(record, sort_keys=True), sensor_id="sensor-1")
    assert one.external_event_id == two.external_event_id


def test_incremental_cli_resumes_counts_duplicate_and_does_not_repost(tmp_path, monkeypatch):
    log = tmp_path / "eve.json"
    log.write_bytes(FIXTURE.read_bytes())
    cursor = tmp_path / "eve.cursor.json"
    responses = iter([True, False, True, True, True, True, True])
    sent = []

    def post(_api, _token, event):
        sent.append(event.external_event_id)
        return next(responses)

    monkeypatch.setattr(suricata_cli, "_post_event", post)
    summary = suricata_cli.process_file(
        log, api_url="http://127.0.0.1:8000", token="test-token",
        sensor_id="suricata-lab-01", cursor_path=cursor,
    )
    assert (summary.records_read, summary.accepted, summary.duplicates, summary.alert_events) == (7, 6, 1, 1)
    assert len(sent) == 7
    replay = suricata_cli.process_file(
        log, api_url="http://127.0.0.1:8000", token="test-token",
        sensor_id="suricata-lab-01", cursor_path=cursor,
    )
    assert replay.records_read == 0
    assert len(sent) == 7


def test_api_failure_leaves_cursor_before_failed_record_for_retry(tmp_path, monkeypatch):
    log = tmp_path / "eve.json"
    log.write_bytes(FIXTURE.read_bytes())
    cursor = tmp_path / "eve.cursor.json"
    attempts = []

    def fail_second(_api, _token, event):
        attempts.append(event.external_event_id)
        if len(attempts) == 2:
            raise RuntimeError("temporary API outage")
        return True

    monkeypatch.setattr(suricata_cli, "_post_event", fail_second)
    partial = suricata_cli.process_file(
        log, api_url="http://127.0.0.1:8000", token="test-token",
        sensor_id="suricata-lab-01", cursor_path=cursor,
    )
    assert partial.error and "transmission failed" in partial.error
    assert partial.accepted == 1
    failed_offset = partial.failed_offset
    assert json.loads(cursor.read_text())["offset"] == failed_offset
    monkeypatch.setattr(suricata_cli, "_post_event", lambda *_args: True)
    retried = suricata_cli.process_file(
        log, api_url="http://127.0.0.1:8000", token="test-token",
        sensor_id="suricata-lab-01", cursor_path=cursor,
    )
    assert retried.accepted == 6


def test_malformed_line_is_reported_and_cursor_does_not_pass_it(tmp_path, monkeypatch):
    log = tmp_path / "eve.json"
    log.write_bytes(FIXTURE.read_bytes().splitlines(keepends=True)[0] + b"{broken secret payload}\n")
    cursor = tmp_path / "cursor.json"
    monkeypatch.setattr(suricata_cli, "_post_event", lambda *_args: True)
    summary = suricata_cli.process_file(
        log, api_url="http://127.0.0.1:8000", token="test-token",
        sensor_id="suricata-lab-01", cursor_path=cursor,
    )
    assert summary.accepted == 1
    assert summary.failed_offset is not None
    assert "malformed EVE record" in summary.error
    assert "secret payload" not in summary.error
    assert json.loads(cursor.read_text())["offset"] == summary.failed_offset


def test_dry_run_parses_without_network_or_cursor_mutation(tmp_path, monkeypatch):
    log = tmp_path / "eve.json"
    log.write_bytes(FIXTURE.read_bytes())
    cursor = tmp_path / "cursor.json"
    monkeypatch.setattr(suricata_cli, "_post_event", lambda *_args: pytest.fail("dry-run transmitted"))
    summary = suricata_cli.process_file(
        log, api_url="https://collector.example", token=None,
        sensor_id="suricata-lab-01", cursor_path=cursor, dry_run=True,
    )
    assert summary.records_read == 7
    assert summary.accepted == 0
    assert summary.alert_events == 1
    assert not cursor.exists()


def test_partial_tail_waits_and_truncation_is_rejected(tmp_path, monkeypatch):
    log = tmp_path / "eve.json"
    full_line = FIXTURE.read_bytes().splitlines(keepends=True)[0]
    log.write_bytes(full_line[:-1])
    cursor = tmp_path / "cursor.json"
    monkeypatch.setattr(suricata_cli, "_post_event", lambda *_args: True)
    partial = suricata_cli.process_file(
        log, api_url="http://127.0.0.1:8000", token="test-token",
        sensor_id="sensor-1", cursor_path=cursor,
    )
    assert partial.records_read == 0
    log.write_bytes(full_line)
    complete = suricata_cli.process_file(
        log, api_url="http://127.0.0.1:8000", token="test-token",
        sensor_id="sensor-1", cursor_path=cursor,
    )
    assert complete.accepted == 1
    log.write_bytes(b"{}\n")
    with pytest.raises(ValueError, match="shorter than the saved cursor"):
        suricata_cli.process_file(
            log, api_url="http://127.0.0.1:8000", token="test-token",
            sensor_id="sensor-1", cursor_path=cursor,
        )


def test_http_sender_uses_only_configured_url_and_rejects_redirects(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *_args): return False

    class FakeOpener:
        def open(self, request, timeout):
            captured["url"] = request.full_url
            captured["authorization"] = request.get_header("Authorization")
            captured["timeout"] = timeout
            return FakeResponse()

    monkeypatch.setattr(suricata_cli.urllib.request, "build_opener", lambda handler: FakeOpener())
    event = parse_eve_record(json.dumps(records()[0]), sensor_id="sensor-1")
    assert suricata_cli._post_event("https://collector.example", "test-secret", event) is False
    assert captured["url"] == "https://collector.example/api/v1/telemetry/ingest"
    assert captured["authorization"] == "Bearer test-secret"
    assert captured["timeout"] == 15
    assert not suricata_cli._validate_api_url("https://user:pass@example.com")
    assert not suricata_cli._validate_api_url("https://collector.example/?target=other")
