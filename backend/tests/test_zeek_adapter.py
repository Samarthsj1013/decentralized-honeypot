import json
from pathlib import Path

import pytest

from app.events.models import TelemetryIngestRequest
from app.telemetry import zeek_cli
from app.telemetry.zeek_conn import iter_zeek_log, iter_zeek_tsv, parse_json_record


FIXTURE = Path(__file__).parent / "fixtures" / "zeek_conn.log"


def test_realistic_conn_tsv_headers_types_fields_and_missing_values():
    with FIXTURE.open(encoding="utf-8") as handle:
        events = list(iter_zeek_log(handle, sensor_id="zeek-lab-01"))

    assert len(events) == 3
    first, second, third = events
    assert first.source_system == "zeek"
    assert first.external_event_id == "Cxyz123abc"
    assert first.occurred_at.isoformat() == "2026-11-02T12:00:00.125000+00:00"
    assert str(first.source_ip) == "192.0.2.44"
    assert first.source_port == 51514
    assert str(first.destination_ip) == "198.51.100.20"
    assert first.destination_port == 443
    assert first.protocol == "tcp"
    assert first.attributes == {
        "service": "ssl", "conn_state": "SF", "duration": 0.25,
        "orig_bytes": 512, "resp_bytes": 2048,
    }
    assert second.external_event_id == "Cxyz456def"
    assert second.source_port is None
    assert second.attributes == {"conn_state": "S0", "orig_bytes": 0}
    assert third.external_event_id == "Cxyz789ghi"
    assert third.attributes == {"service": "", "conn_state": "S0"}


def test_json_lines_record_is_normalized_and_timestamp_preserved():
    event = parse_json_record(json.dumps({
        "ts": 1793620800.5, "uid": "CJ0abc", "id.orig_h": "203.0.113.5",
        "id.orig_p": 12345, "id.resp_h": "198.51.100.2", "id.resp_p": 80,
        "proto": "tcp", "service": "http", "conn_state": "SF",
        "duration": 1.75, "orig_bytes": 40, "resp_bytes": 200,
    }), sensor_id="zeek-json")
    assert event.source_system == "zeek"
    assert event.external_event_id == "CJ0abc"
    assert event.occurred_at.timestamp() == 1793620800.5
    assert event.attributes["duration"] == 1.75
    assert event.attributes["resp_bytes"] == 200


def test_missing_uid_gets_stable_deduplication_identifier():
    raw = {"ts": 1793620800, "id.orig_h": "192.0.2.3", "id.orig_p": 53,
           "id.resp_h": "198.51.100.3", "id.resp_p": 53, "proto": "udp",
           "service": "-"}
    a = parse_json_record(json.dumps(raw), sensor_id="zeek-lab")
    b = parse_json_record(json.dumps(raw, sort_keys=True), sensor_id="zeek-lab")
    assert a.external_event_id.startswith("zeek-")
    assert a.external_event_id == b.external_event_id
    assert "service" not in a.attributes


@pytest.mark.parametrize("lines", [
    ["1.0\tuid\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\n"],
    ["#fields\tts\tuid\n", "#types\ttime\n", "1.0\tu\n"],
    ["#fields\tts\tuid\n", "#types\ttime\tstring\n", "-\tu\n"],
])
def test_malformed_tsv_is_rejected(lines):
    with pytest.raises(ValueError):
        list(iter_zeek_tsv(lines, sensor_id="zeek-lab"))


def test_incremental_cli_posts_only_new_lines_and_persists_cursor(tmp_path, monkeypatch):
    source = tmp_path / "conn.log"
    source.write_bytes(FIXTURE.read_bytes())
    cursor = tmp_path / "conn.cursor.json"
    submitted = []

    def post(_url, _token, event: TelemetryIngestRequest):
        submitted.append(event.external_event_id)
        return True

    monkeypatch.setattr(zeek_cli, "_post_event", post)
    assert zeek_cli.process_file(
        source, api_url="http://127.0.0.1:8000", token="test-token",
        sensor_id="zeek-lab-01", cursor_path=cursor,
    ) == (3, 0)
    assert submitted == ["Cxyz123abc", "Cxyz456def", "Cxyz789ghi"]
    assert zeek_cli.process_file(
        source, api_url="http://127.0.0.1:8000", token="test-token",
        sensor_id="zeek-lab-01", cursor_path=cursor,
    ) == (0, 0)
    assert submitted == ["Cxyz123abc", "Cxyz456def", "Cxyz789ghi"]


def test_incremental_cursor_advances_only_after_api_acceptance(tmp_path, monkeypatch):
    source = tmp_path / "conn.log"
    source.write_bytes(FIXTURE.read_bytes())
    cursor = tmp_path / "cursor.json"
    attempts = []

    def fail_second(_url, _token, event):
        attempts.append(event.external_event_id)
        if len(attempts) == 2:
            raise RuntimeError("simulated API unavailable")
        return True

    monkeypatch.setattr(zeek_cli, "_post_event", fail_second)
    with pytest.raises(RuntimeError, match="unavailable"):
        zeek_cli.process_file(
            source, api_url="http://127.0.0.1:8000", token="test-token",
            sensor_id="zeek-lab-01", cursor_path=cursor,
        )
    assert json.loads(cursor.read_text())["offset"] < source.stat().st_size
    monkeypatch.setattr(zeek_cli, "_post_event", lambda *_args: True)
    assert zeek_cli.process_file(
        source, api_url="http://127.0.0.1:8000", token="test-token",
        sensor_id="zeek-lab-01", cursor_path=cursor,
    ) == (2, 0)


def test_cursor_cannot_be_reused_for_another_sensor(tmp_path, monkeypatch):
    source = tmp_path / "conn.log"
    source.write_bytes(FIXTURE.read_bytes())
    cursor = tmp_path / "cursor.json"
    monkeypatch.setattr(zeek_cli, "_post_event", lambda *_args: True)
    zeek_cli.process_file(
        source, api_url="http://127.0.0.1:8000", token="test-token",
        sensor_id="zeek-lab-01", cursor_path=cursor,
    )
    with pytest.raises(ValueError, match="different log file, API, or sensor"):
        zeek_cli.process_file(
            source, api_url="http://127.0.0.1:8000", token="test-token",
            sensor_id="zeek-lab-02", cursor_path=cursor,
        )


def test_http_sender_targets_only_configured_ingestion_endpoint(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 201
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    class FakeOpener:
        def open(self, request, timeout):
            captured["url"] = request.full_url
            captured["authorization"] = request.get_header("Authorization")
            captured["body"] = json.loads(request.data)
            captured["timeout"] = timeout
            return FakeResponse()

    def fake_build_opener(handler):
        captured["redirect_handler"] = handler
        return FakeOpener()

    from datetime import datetime, timezone
    event = TelemetryIngestRequest(
        source_system="zeek", sensor_id="sensor-1", external_event_id="C123",
        occurred_at=datetime(2026, 11, 2, tzinfo=timezone.utc),
        event_type="zeek_connection",
    )
    monkeypatch.setattr(zeek_cli.urllib.request, "build_opener", fake_build_opener)
    assert zeek_cli._post_event("https://telemetry.example", "secret-test", event) is True
    assert captured["url"] == "https://telemetry.example/api/v1/telemetry/ingest"
    assert captured["authorization"] == "Bearer secret-test"
    assert captured["body"]["source_system"] == "zeek"
    assert captured["timeout"] == 15
    assert isinstance(captured["redirect_handler"], zeek_cli._NoRedirectHandler)
    redirect_request = zeek_cli.urllib.request.Request("https://collector.example")
    assert captured["redirect_handler"].redirect_request(
        redirect_request, None, 307, "Temporary Redirect", {}, "https://other.example"
    ) is None


@pytest.mark.parametrize(
    "value",
    ["file:///tmp/telemetry", "https://user:secret@example.test", "https://collector.test/?x=1"],
)
def test_sender_rejects_unsafe_api_urls(value):
    event = TelemetryIngestRequest(
        source_system="zeek", sensor_id="sensor-1", external_event_id="C123",
        occurred_at="2026-11-02T00:00:00Z", event_type="zeek_connection",
    )
    with pytest.raises(ValueError, match="API URL"):
        zeek_cli._post_event(value, "secret-test", event)

