from __future__ import annotations

import csv
import gzip
import json

import pytest

from app.experiments.real_cowrie import DatasetValidationError, process_cyberlab_archive
from app.profiling.features import FEATURE_COLUMNS


def _write_archive(path, sessions):
    with gzip.open(path, "wb") as handle:
        handle.write(json.dumps(sessions).encode("utf-8"))


def test_public_cowrie_session_preprocessing_returns_numeric_features_without_secrets(tmp_path):
    source = tmp_path / "sample.json.gz"
    output = tmp_path / "features.csv"
    sessions = [{
        "raw-session-id-DO-NOT-EXPORT": [
            {"eventid": "cowrie.session.connect", "timestamp": "2020-01-01T00:00:00Z", "protocol": "ssh", "sensor": "sensor-a"},
            {"eventid": "cowrie.login.failed", "timestamp": "2020-01-01T00:00:01Z", "username": "secret-user", "password": "secret-password", "protocol": "ssh"},
            {"eventid": "cowrie.command.input", "timestamp": "2020-01-01T00:00:02Z", "input": "never execute me", "data": "private payload"},
        ]
    }]
    _write_archive(source, sessions)

    rows, summary = process_cyberlab_archive(source)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FEATURE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    exported = output.read_text(encoding="utf-8")

    assert len(rows) == 1
    assert tuple(rows[0]) == FEATURE_COLUMNS
    assert rows[0]["failed_auth_count"] == 1
    assert rows[0]["command_attempt_count"] == 1
    assert rows[0]["session_count"] == 1
    assert summary["processed_sessions"] == 1
    assert summary["labels_available"] is False
    assert all(secret not in exported for secret in ("raw-session-id", "secret-user", "secret-password", "never execute me", "private payload"))


def test_public_cowrie_session_preprocessing_deduplicates_session_keys_without_exporting_them(tmp_path):
    source = tmp_path / "duplicate.json.gz"
    events = [{"eventid": "cowrie.login.failed", "protocol": "ssh", "username": "example"}]
    _write_archive(source, [{"repeat-me": events}, {"repeat-me": events}])

    rows, summary = process_cyberlab_archive(source)

    assert len(rows) == 1
    assert summary["input_sessions"] == 2
    assert summary["processed_sessions"] == 1
    assert summary["duplicate_sessions_ignored"] == 1
    assert summary["raw_event_count"] == 2
    assert summary["processed_event_count"] == 1


def test_public_cowrie_session_preprocessing_handles_mixed_missing_timestamps(tmp_path):
    source = tmp_path / "mixed-timestamps.json.gz"
    _write_archive(source, [{"session": [
        {"eventid": "cowrie.login.failed", "timestamp": "2020-01-01T00:00:00Z"},
        {"eventid": "cowrie.login.success"},
        {"eventid": "cowrie.command.input", "timestamp": "not-a-time"},
    ]}])

    rows, summary = process_cyberlab_archive(source)

    assert rows[0]["event_count"] == 3
    assert rows[0]["failed_auth_count"] == 1
    assert summary["processed_event_count"] == 3


@pytest.mark.parametrize("document", [[], {}, [{"a": []}], [{"a": ["not-an-event"]}], [{"a": [], "b": []}]])
def test_public_cowrie_session_preprocessing_rejects_malformed_archive_shapes(tmp_path, document):
    source = tmp_path / "bad.json.gz"
    _write_archive(source, document)
    with pytest.raises(DatasetValidationError):
        process_cyberlab_archive(source)
