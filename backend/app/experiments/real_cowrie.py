"""Privacy-filtered preprocessing for public CyberLab Cowrie session exports.

Raw records may include passwords, usernames, commands, URLs, host identifiers,
and transfer metadata. This module projects only bounded numeric behavior
aggregates and never copies raw identifiers or payload fields to its outputs.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_bytes
from statistics import mean
from typing import Any

from app.profiling.features import FEATURE_COLUMNS


MAX_COMPRESSED_BYTES = 32 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_SESSIONS = 100_000
MAX_EVENTS_PER_SESSION = 10_000
MAX_TOTAL_EVENTS = 2_000_000

EVENT_TYPE_MAP = {
    "cowrie.login.failed": "cowrie_login_failed",
    "cowrie.login.success": "cowrie_login_success",
    "cowrie.session.connect": "cowrie_session_connected",
    "cowrie.session.closed": "cowrie_session_closed",
    "cowrie.command.input": "cowrie_command_attempt",
    "cowrie.command.failed": "cowrie_command_attempt",
    "cowrie.session.file_upload": "cowrie_file_upload",
    "cowrie.session.file_download": "cowrie_file_download",
    "cowrie.session.file_download.failed": "cowrie_file_download",
    "cowrie.session.params": "cowrie_session_metadata",
    "cowrie.client.version": "cowrie_session_metadata",
    "cowrie.client.fingerprint": "cowrie_session_metadata",
}


class DatasetValidationError(ValueError):
    """The source archive does not match the expected bounded Cowrie schema."""


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _number(value: Any, *, maximum: float) -> float | None:
    if type(value) not in (int, float):
        return None
    result = float(value)
    if not math.isfinite(result) or result < 0:
        return None
    return min(maximum, result)


def _session_features(events: list[dict[str, Any]]) -> tuple[dict[str, int | float], Counter[str]]:
    counts: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    username_salt = token_bytes(32)
    username_references: set[bytes] = set()
    sensors: set[str] = set()
    ports: set[int] = set()
    durations: list[float] = []
    attempt_times: list[datetime] = []

    for event in events:
        source_type = event.get("eventid")
        event_type = EVENT_TYPE_MAP.get(source_type, "cowrie_other") if isinstance(source_type, str) else "cowrie_other"
        counts[event_type] += 1
        protocol = event.get("protocol")
        if isinstance(protocol, str) and len(protocol) <= 32:
            protocols[protocol.casefold()] += 1
        username = event.get("username")
        if event_type in {"cowrie_login_failed", "cowrie_login_success"} and isinstance(username, str):
            normalized = username.casefold()[:256].encode("utf-8", errors="ignore")
            username_references.add(hashlib.sha256(username_salt + normalized).digest())
        sensor = event.get("sensor")
        if isinstance(sensor, str) and sensor:
            sensors.add(sensor[:128])
        port = event.get("dst_port")
        if type(port) is int and 1 <= port <= 65535:
            ports.add(port)
        duration = _number(event.get("duration"), maximum=86400.0)
        if duration is not None:
            durations.append(duration)
        if event_type in {"cowrie_login_failed", "cowrie_login_success", "cowrie_command_attempt"}:
            timestamp = _timestamp(event.get("timestamp"))
            if timestamp is not None:
                attempt_times.append(timestamp)

    event_total = len(events)
    failure_count = counts["cowrie_login_failed"]
    success_count = counts["cowrie_login_success"]
    command_count = counts["cowrie_command_attempt"]
    protocols_total = sum(protocols.values())
    connection_events = counts["cowrie_session_connected"]
    times = sorted(attempt_times)
    intervals = [(right - left).total_seconds() for left, right in zip(times, times[1:])]
    frequencies = list(counts.values())
    if len(frequencies) > 1:
        entropy = -sum((count / event_total) * math.log(count / event_total) for count in frequencies)
        diversity = entropy / math.log(len(frequencies))
    else:
        diversity = 0.0
    event_times = [
        timestamp for event in events
        if (timestamp := _timestamp(event.get("timestamp"))) is not None
    ]
    first_time = min(event_times, default=None)
    last_time = max(event_times, default=None)
    span_seconds = max(60.0, (last_time - first_time).total_seconds()) if first_time and last_time else 60.0

    features: dict[str, int | float] = {name: 0 for name in FEATURE_COLUMNS}
    features.update({
        "event_count": event_total,
        "failed_auth_count": failure_count,
        "successful_auth_count": success_count,
        "unique_usernames_attempted": len(username_references),
        "session_count": int(connection_events > 0),
        "command_attempt_count": command_count,
        "unique_destination_ports": len(ports),
        # The profile schema defines this as Zeek connection/Suricata flow
        # count; Cowrie session events remain represented in session_count.
        "connection_count": 0,
        "connections_per_minute": 0.0,
        "suricata_alert_count": 0,
        "mean_session_duration_seconds": round(mean(durations), 6) if durations else 0.0,
        "session_duration_available": int(bool(durations)),
        "protocol_ssh_count": protocols["ssh"],
        "protocol_tcp_count": protocols["tcp"],
        "protocol_udp_count": protocols["udp"],
        "protocol_icmp_count": protocols["icmp"],
        "protocol_other_count": sum(value for key, value in protocols.items() if key not in {"ssh", "tcp", "udp", "icmp"}),
        "unique_protocol_count": len(protocols),
        "sensor_count": len(sensors),
        "mean_inter_attempt_seconds": round(mean(intervals), 6) if intervals else 0.0,
        "inter_attempts_available": int(bool(intervals)),
        "behavioral_diversity": round(diversity, 6),
    })
    return features, counts


def process_cyberlab_archive(path: str | Path) -> tuple[list[dict[str, int | float]], dict[str, Any]]:
    """Read a bounded gzip JSON archive and return anonymous per-session features.

    Session IDs are hashed only for in-memory duplicate detection. They and all
    credential, command, IP, URL, file, and payload values are omitted from
    returned rows and summary metadata.
    """
    source = Path(path)
    try:
        compressed_size = source.stat().st_size
        if compressed_size <= 0 or compressed_size > MAX_COMPRESSED_BYTES:
            raise DatasetValidationError("compressed dataset size is outside the supported limit")
        with gzip.open(source, "rb") as handle:
            payload = handle.read(MAX_DECOMPRESSED_BYTES + 1)
    except DatasetValidationError:
        raise
    except (OSError, EOFError):
        raise DatasetValidationError("dataset archive could not be read") from None
    if len(payload) > MAX_DECOMPRESSED_BYTES:
        raise DatasetValidationError("decompressed dataset exceeds the supported limit")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise DatasetValidationError("dataset is not valid bounded UTF-8 JSON") from None
    if not isinstance(document, list) or not document or len(document) > MAX_SESSIONS:
        raise DatasetValidationError("dataset root must be a non-empty bounded session list")

    seen_session_refs: set[bytes] = set()
    rows: list[dict[str, int | float]] = []
    event_counts: Counter[str] = Counter()
    duplicate_sessions = 0
    raw_event_count = 0
    processed_event_count = 0
    for item in document:
        if not isinstance(item, dict) or len(item) != 1:
            raise DatasetValidationError("session record must contain one session key")
        session_id, events = next(iter(item.items()))
        if not isinstance(session_id, str) or not session_id or len(session_id) > 256:
            raise DatasetValidationError("session identifier is missing or malformed")
        if not isinstance(events, list) or not events or len(events) > MAX_EVENTS_PER_SESSION:
            raise DatasetValidationError("session event list is empty or exceeds the supported limit")
        if any(not isinstance(event, dict) for event in events):
            raise DatasetValidationError("session contains a malformed event")
        raw_event_count += len(events)
        if raw_event_count > MAX_TOTAL_EVENTS:
            raise DatasetValidationError("dataset event count exceeds the supported limit")
        session_ref = hashlib.sha256(session_id.encode("utf-8")).digest()
        if session_ref in seen_session_refs:
            duplicate_sessions += 1
            continue
        seen_session_refs.add(session_ref)
        processed_event_count += len(events)
        features, types = _session_features(events)
        rows.append(features)
        event_counts.update(types)

    summary: dict[str, Any] = {
        "input_sessions": len(document),
        "processed_sessions": len(rows),
        "duplicate_sessions_ignored": duplicate_sessions,
        "raw_event_count": raw_event_count,
        "processed_event_count": processed_event_count,
        "event_type_counts": dict(sorted(event_counts.items())),
        "feature_schema_columns": list(FEATURE_COLUMNS),
        "labels_available": False,
    }
    return rows, summary
