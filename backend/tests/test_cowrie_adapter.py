import json
import urllib.request
from pathlib import Path

import pytest

from app.telemetry import cowrie_cli
from app.telemetry.cowrie import CowrieRecordError, parse_cowrie_record


FIXTURE = Path(__file__).parent / "fixtures" / "cowrie_events.jsonl"
SENSOR = "cowrie-lab-01"
API = "http://127.0.0.1:8000"
TOKEN = "cowrie-test-token-with-at-least-32-bytes"


def records():
    return [line for line in FIXTURE.read_bytes().splitlines() if line]


def test_parser_maps_supported_cowrie_event_types_and_network_fields():
    parsed = [parse_cowrie_record(line, sensor_id=SENSOR) for line in records()]
    assert [event.event_type for event in parsed] == [
        "cowrie_session_connected", "cowrie_login_failed", "cowrie_login_success",
        "cowrie_command_attempt", "cowrie_file_upload", "cowrie_file_download",
        "cowrie_session_closed", "cowrie_session_metadata",
    ]
    assert parsed[0].source_system == "cowrie"
    assert str(parsed[0].source_ip) == "192.0.2.10"
    assert parsed[0].source_port == 51422
    assert str(parsed[0].destination_ip) == "198.51.100.20"
    assert parsed[0].destination_port == 2222
    assert parsed[0].protocol == "ssh"
    assert parsed[1].attributes["authentication_outcome"] == "failed"
    assert parsed[2].attributes["authentication_outcome"] == "success"
    assert parsed[3].attributes["command_attempt"] is True
    assert parsed[4].attributes["file_transfer_direction"] == "upload"


def test_sensitive_password_command_path_and_url_content_never_enter_normalized_payload():
    serialized = "\n".join(parse_cowrie_record(line, sensor_id=SENSOR).model_dump_json() for line in records())
    for secret in ("DO_NOT_LEAK_PASSWORD", "ANOTHER_SECRET", "cat /tmp/private-output.txt", "private-output", "downloads/sample.bin", "secret=yes"):
        assert secret not in serialized
    parsed_login = parse_cowrie_record(records()[1], sensor_id=SENSOR)
    assert parsed_login.attributes["username_ref"] != "root"
    assert len(parsed_login.attributes["username_ref"]) == 64
    assert "root" not in parsed_login.model_dump_json()
    assert parsed_login.attributes["session_id"] != "S-001"


def test_missing_optional_fields_and_unknown_event_are_safe():
    data = {"eventid": "cowrie.unknown.event", "timestamp": "2026-11-06T10:00:00+00:00"}
    parsed = parse_cowrie_record(json.dumps(data), sensor_id=SENSOR)
    assert parsed.event_type == "cowrie_other"
    assert parsed.source_ip is None
    assert parsed.source_port is None
    assert parsed.attributes["cowrie_event_id"] == "cowrie.unknown.event"


def test_event_name_control_characters_are_rejected():
    data = {"eventid": "cowrie.login.failed\nforged", "timestamp": "2026-11-06T10:00:00Z"}
    with pytest.raises(CowrieRecordError, match="eventid"):
        parse_cowrie_record(json.dumps(data), sensor_id=SENSOR)


@pytest.mark.parametrize(
    "line",
    [b"{bad json", b"[]", b'{"eventid":"cowrie.login.failed"}', b'{"eventid":"bad","timestamp":"2026-11-06T10:00:00Z"}', b'{"eventid":"cowrie.login.failed","timestamp":"2026-11-06T10:00:00"}'],
)
def test_malformed_or_missing_required_fields_raise_safe_errors(line):
    with pytest.raises(CowrieRecordError):
        parse_cowrie_record(line, sensor_id=SENSOR)


def test_invalid_address_and_oversized_line_are_rejected():
    bad_address = b'{"eventid":"cowrie.session.connect","timestamp":"2026-11-06T10:00:00Z","src_ip":"not-an-ip"}'
    with pytest.raises(CowrieRecordError, match="normalized telemetry"):
        parse_cowrie_record(bad_address, sensor_id=SENSOR)
    with pytest.raises(CowrieRecordError, match="maximum line size"):
        parse_cowrie_record(b" " * (64 * 1024 + 1), sensor_id=SENSOR)


def test_malformed_unicode_and_unbounded_numeric_fields_fail_safely():
    with pytest.raises(CowrieRecordError, match="UTF-8"):
        parse_cowrie_record("\ud800", sensor_id=SENSOR)

    data = {
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-11-06T10:00:00Z",
        "src_port": "9" * 5000,
    }
    event = parse_cowrie_record(json.dumps(data), sensor_id=SENSOR)
    assert event.source_port is None


def test_external_id_is_stable_for_same_record_and_changes_with_record():
    line = records()[0]
    assert parse_cowrie_record(line, sensor_id=SENSOR).external_event_id == parse_cowrie_record(line, sensor_id=SENSOR).external_event_id
    assert parse_cowrie_record(records()[1], sensor_id=SENSOR).external_event_id != parse_cowrie_record(records()[2], sensor_id=SENSOR).external_event_id


def test_cursor_persists_and_resume_skips_confirmed_records(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes(records()[0] + b"\n")
    cursor = tmp_path / "cursor.json"
    received = []

    def accept(_url, _token, event):
        received.append(event.external_event_id)
        return False

    first = cowrie_cli.process_file(log, api_url=API, sensor_id=SENSOR, token=TOKEN, cursor_path=cursor, post_event=accept)
    with log.open("ab") as handle:
        handle.write(records()[1] + b"\n")
    second = cowrie_cli.process_file(log, api_url=API, sensor_id=SENSOR, token=TOKEN, cursor_path=cursor, post_event=accept)
    third = cowrie_cli.process_file(log, api_url=API, sensor_id=SENSOR, token=TOKEN, cursor_path=cursor, post_event=accept)
    assert first.accepted == 1
    assert second.accepted == 1
    assert third.records_read == 0
    assert len(received) == 2
    assert json.loads(cursor.read_text())["offset"] == log.stat().st_size


def test_api_failure_does_not_advance_cursor_and_retry_can_confirm_duplicate(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes(records()[0] + b"\n" + records()[1] + b"\n")
    cursor = tmp_path / "cursor.json"
    calls = 0

    def fail_second(_url, _token, _event):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("temporary API failure")
        return False

    failed = cowrie_cli.process_file(log, api_url=API, sensor_id=SENSOR, token=TOKEN, cursor_path=cursor, post_event=fail_second)
    assert failed.accepted == 1
    assert failed.failed_offset is not None
    saved_offset = json.loads(cursor.read_text())["offset"]
    assert saved_offset < log.stat().st_size

    retried = cowrie_cli.process_file(log, api_url=API, sensor_id=SENSOR, token=TOKEN, cursor_path=cursor, post_event=lambda *_: True)
    assert retried.duplicates == 1
    assert json.loads(cursor.read_text())["offset"] == log.stat().st_size


def test_malformed_record_stops_before_advancing_and_dry_run_does_not_write_cursor(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes(records()[0] + b"\n{bad-json}\n" + records()[1] + b"\n")
    cursor = tmp_path / "cursor.json"
    failed = cowrie_cli.process_file(log, api_url=API, sensor_id=SENSOR, token=TOKEN, cursor_path=cursor, post_event=lambda *_: False)
    assert failed.records_read == 1
    assert failed.error == "record is not valid bounded JSON"
    assert json.loads(cursor.read_text())["offset"] == len(records()[0]) + 1

    dry_cursor = tmp_path / "dry-cursor.json"
    dry = cowrie_cli.process_file(log, api_url=API, sensor_id=SENSOR, token=None, cursor_path=dry_cursor, dry_run=True)
    assert dry.records_read == 1
    assert not dry_cursor.exists()


def test_cursor_rejects_truncation_rotation_and_api_configuration_changes(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes(records()[0] + b"\n")
    cursor = tmp_path / "cursor.json"
    cowrie_cli.process_file(log, api_url=API, sensor_id=SENSOR, token=TOKEN, cursor_path=cursor, post_event=lambda *_: False)
    log.write_bytes(records()[1] + b"\n")
    with pytest.raises(ValueError, match="log identity changed or log was truncated"):
        cowrie_cli.process_file(log, api_url=API, sensor_id=SENSOR, token=TOKEN, cursor_path=cursor, post_event=lambda *_: False)
    with pytest.raises(ValueError, match="base origin"):
        cowrie_cli.process_file(log, api_url=API + "/v1", sensor_id=SENSOR, token=TOKEN, cursor_path=tmp_path / "other.json")


def test_incomplete_tail_is_left_for_next_run_and_redirect_handler_blocks_redirects(tmp_path):
    log = tmp_path / "cowrie.json"
    first = records()[0] + b"\n"
    log.write_bytes(first + records()[1])
    cursor = tmp_path / "cursor.json"
    summary = cowrie_cli.process_file(log, api_url=API, sensor_id=SENSOR, token=TOKEN, cursor_path=cursor, post_event=lambda *_: False)
    assert summary.accepted == 1
    assert json.loads(cursor.read_text())["offset"] == len(first)
    handler = cowrie_cli._NoRedirect()
    request = urllib.request.Request("http://example.invalid")
    assert handler.redirect_request(request, None, 302, "Found", {}, "https://example.invalid") is None
