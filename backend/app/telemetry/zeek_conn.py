"""Safe parser for Zeek conn.log TSV and JSON-lines exports.

This module only converts log records into normalized telemetry envelopes. It
does not execute record contents or perform network operations.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from itertools import chain
from typing import Any, Iterable, Iterator, TextIO

from app.events.models import TelemetryIngestRequest

_MISSING = "-"
_ATTRIBUTES = ("service", "conn_state", "duration", "orig_bytes", "resp_bytes")


def _optional(value: Any) -> Any:
    return None if value in (None, "", _MISSING) else value


def _timestamp(value: Any) -> datetime:
    if value is None or value == _MISSING:
        raise ValueError("Zeek connection record is missing ts")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except ValueError:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
    raise ValueError("Zeek ts must be an epoch timestamp or ISO datetime")


def _typed(value: str, zeek_type: str) -> Any:
    if value == _MISSING:
        return None
    if zeek_type in {"count", "int", "port", "counter"}:
        return int(value)
    if zeek_type in {"double", "time", "interval"}:
        return float(value)
    if zeek_type == "bool":
        lowered = value.casefold()
        if lowered not in {"t", "f", "true", "false"}:
            raise ValueError("invalid Zeek boolean")
        return lowered in {"t", "true"}
    return value


def _normalize(record: dict[str, Any], *, sensor_id: str) -> TelemetryIngestRequest:
    uid = record.get("uid")
    if uid in (None, "", _MISSING):
        stable = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
        uid = "zeek-" + hashlib.sha256(stable.encode("utf-8")).hexdigest()[:48]
    attributes = {
        key: record[key]
        for key in _ATTRIBUTES
        if record.get(key) is not None and record.get(key) != _MISSING
    }
    return TelemetryIngestRequest.model_validate(
        {
            "source_system": "zeek",
            "sensor_id": sensor_id,
            "external_event_id": str(uid),
            "occurred_at": _timestamp(record.get("ts")),
            "event_type": "zeek_connection",
            "severity": "low",
            "source_ip": _optional(record.get("id.orig_h")),
            "source_port": _optional(record.get("id.orig_p")),
            "destination_ip": _optional(record.get("id.resp_h")),
            "destination_port": _optional(record.get("id.resp_p")),
            "protocol": _optional(record.get("proto")),
            "attributes": attributes,
        }
    )


def parse_json_record(line: str, *, sensor_id: str) -> TelemetryIngestRequest:
    """Parse one Zeek JSON log line (the usual newline-delimited form)."""
    record = json.loads(line)
    if not isinstance(record, dict):
        raise ValueError("Zeek JSON log line must contain an object")
    return _normalize(record, sensor_id=sensor_id)


def iter_zeek_tsv(
    lines: Iterable[str], *, sensor_id: str, fields: list[str] | None = None,
    types: list[str] | None = None, separator: str = "\t",
    unset_field: str = "-", empty_field: str = "(empty)",
) -> Iterator[TelemetryIngestRequest]:
    """Yield normalized TSV records, honoring Zeek #fields/#types headers."""
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line:
            continue
        if line.startswith("#separator "):
            token = line[len("#separator "):]
            # Zeek writes escaped delimiters, commonly ``\\x09``.
            separator = bytes(token, "ascii").decode("unicode_escape")
            if len(separator) != 1:
                raise ValueError("Zeek separator must decode to exactly one character")
            continue
        if line.startswith("#fields"):
            values = line.split(separator)
            fields = values[1:]
            continue
        if line.startswith("#types"):
            values = line.split(separator)
            types = values[1:]
            continue
        if line.startswith("#unset_field"):
            values = line.split(separator, 1)
            if len(values) == 2:
                unset_field = values[1]
            continue
        if line.startswith("#empty_field"):
            values = line.split(separator, 1)
            if len(values) == 2:
                empty_field = values[1]
            continue
        if line.startswith("#"):
            continue
        if not fields:
            raise ValueError("Zeek TSV data requires a preceding #fields header")
        values = line.split(separator)
        if len(values) != len(fields):
            raise ValueError("Zeek TSV record field count does not match #fields")
        if types is not None and len(types) != len(fields):
            raise ValueError("Zeek #types count does not match #fields")
        row: dict[str, Any] = {}
        for index, (name, value) in enumerate(zip(fields, values)):
            if value == unset_field:
                row[name] = None
            elif value == empty_field:
                row[name] = ""
            else:
                row[name] = _typed(value, types[index]) if types else value
        yield _normalize(row, sensor_id=sensor_id)


def iter_zeek_log(handle: TextIO, *, sensor_id: str) -> Iterator[TelemetryIngestRequest]:
    """Detect TSV or newline-delimited JSON based on the first non-empty line."""
    lines = iter(handle)
    buffered: list[str] = []
    for line in lines:
        buffered.append(line)
        if line.strip():
            break
    if not buffered:
        return
    first = next((line.strip() for line in buffered if line.strip()), "")
    if first.startswith("{"):
        for line in chain(buffered, lines):
            if line.strip():
                yield parse_json_record(line, sensor_id=sensor_id)
        return
    yield from iter_zeek_tsv(chain(buffered, lines), sensor_id=sensor_id)
