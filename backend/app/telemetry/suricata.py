"""Bounded parser for newline-delimited Suricata EVE JSON records."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from app.events.models import TelemetryIngestRequest

MAX_EVE_LINE_BYTES = 256 * 1024
MAX_ATTRIBUTE_DEPTH = 4
MAX_ATTRIBUTE_NODES = 256
MAX_ATTRIBUTE_STRING = 1024

_EVENT_FIELDS: dict[str, tuple[str, ...]] = {
    "flow": ("pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient", "start", "end", "age", "state", "reason", "alerted"),
    "dns": ("type", "id", "rrname", "rrtype", "rcode", "answers", "tx_id", "query", "opcode", "version", "flags", "authorities", "additionals"),
    "http": ("hostname", "url", "http_user_agent", "http_content_type", "http_method", "protocol", "status", "length", "http_refer", "redirect", "xff"),
    "tls": ("sni", "version", "subject", "issuerdn", "serial", "fingerprint", "ja3", "ja3s", "not_before", "not_after"),
    "ssh": ("client_proto_version", "server_proto_version", "client_software_version", "server_software_version", "client_hassh", "server_hassh"),
    "fileinfo": ("filename", "magic", "state", "md5", "sha1", "sha256", "size", "stored", "file_id"),
}


class SuricataRecordError(ValueError):
    """A malformed or unsupported-size EVE record, safe to report without its contents."""


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise SuricataRecordError("record is missing a string timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise SuricataRecordError("timestamp is not valid ISO-8601") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SuricataRecordError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _bounded_json(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > MAX_ATTRIBUTE_NODES or depth > MAX_ATTRIBUTE_DEPTH:
        raise SuricataRecordError("projected attributes exceed structural limits")
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise SuricataRecordError("attributes contain a non-finite number")
        return value
    if isinstance(value, str):
        if len(value) > MAX_ATTRIBUTE_STRING or "\x00" in value:
            raise SuricataRecordError("a projected string exceeds its size limit")
        return value
    if isinstance(value, list):
        if len(value) > 32:
            raise SuricataRecordError("a projected array exceeds its item limit")
        return [_bounded_json(item, depth=depth + 1, budget=budget) for item in value]
    if isinstance(value, dict):
        if len(value) > 32:
            raise SuricataRecordError("a projected object exceeds its field limit")
        projected: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 64 or "\x00" in key:
                raise SuricataRecordError("a projected field name is invalid")
            projected[key] = _bounded_json(item, depth=depth + 1, budget=budget)
        return projected
    raise SuricataRecordError("projected attributes contain a non-JSON value")


def _project_fields(record: dict[str, Any], event_type: str) -> dict[str, Any]:
    attributes: dict[str, Any] = {"event_type": event_type}
    if event_type == "alert":
        alert = record.get("alert")
        if alert is not None:
            if not isinstance(alert, dict):
                raise SuricataRecordError("alert must be a JSON object")
            selected = ("signature", "category", "severity", "signature_id", "rev", "gid", "action")
            values = {key: alert[key] for key in selected if key in alert and alert[key] is not None}
            if values:
                attributes["alert"] = values
    else:
        fields = _EVENT_FIELDS.get(event_type, ())
        source = record.get(event_type)
        if source is not None:
            if not isinstance(source, dict):
                raise SuricataRecordError(f"{event_type} must be a JSON object")
            values = {key: source[key] for key in fields if key in source and source[key] is not None}
            if event_type == "http":
                # Query strings and fragments often carry credentials or
                # tracking tokens. Keep only the request path in shared data.
                for url_field in ("url", "http_refer"):
                    value = values.get(url_field)
                    if isinstance(value, str):
                        values[url_field] = urlsplit(value).path
            if values:
                attributes[event_type] = values

    if event_type == "alert":
        # Flow context can accompany an alert; retain only selected counters/state.
        source = record.get("flow")
        if source is not None:
            if not isinstance(source, dict):
                raise SuricataRecordError("flow must be a JSON object")
            values = {key: source[key] for key in _EVENT_FIELDS["flow"] if key in source and source[key] is not None}
            if values:
                attributes["flow"] = values
    return _bounded_json(attributes)


def _mapped_severity(record: dict[str, Any], event_type: str) -> str:
    if event_type != "alert":
        return "low"
    alert = record.get("alert")
    raw = alert.get("severity") if isinstance(alert, dict) else None
    if isinstance(raw, bool):
        return "medium"
    if isinstance(raw, int):
        if raw == 1:
            return "high"
        if raw == 2:
            return "medium"
        if raw >= 3:
            return "low"
        return "medium"
    if isinstance(raw, str):
        return {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(raw.casefold(), "medium")
    return "medium"


def _port(record: dict[str, Any], field: str) -> int | None:
    value = record.get(field)
    if value is None or value == "":
        return None
    if type(value) is not int:
        raise SuricataRecordError(f"{field} must be an integer port")
    return value


def parse_eve_record(line: str | bytes, *, sensor_id: str) -> TelemetryIngestRequest:
    """Parse one EVE JSON record into the existing normalized request schema.

    Only fields explicitly selected for the event type are retained. The full
    record is hashed for a stable idempotency key but is never stored/exported.
    """
    raw = line.encode("utf-8") if isinstance(line, str) else line
    if len(raw) > MAX_EVE_LINE_BYTES:
        raise SuricataRecordError("EVE record exceeds the maximum line size")
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise SuricataRecordError("record is not valid UTF-8 JSON") from None
    if not isinstance(record, dict):
        raise SuricataRecordError("EVE record must be a JSON object")
    try:
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise SuricataRecordError("record contains unsupported JSON values") from None

    event_type = record.get("event_type")
    if not isinstance(event_type, str) or not event_type or len(event_type) > 64:
        raise SuricataRecordError("event_type must be a non-empty bounded string")
    attributes = _project_fields(record, event_type)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    payload = {
        "source_system": "suricata",
        "sensor_id": sensor_id,
        "external_event_id": f"eve-{digest[:48]}",
        "occurred_at": _timestamp(record.get("timestamp")),
        "event_type": f"suricata_{event_type}" if event_type in {"alert", "flow", "dns", "http", "tls", "ssh", "fileinfo"} else "suricata_unknown",
        "severity": _mapped_severity(record, event_type),
        "source_ip": record.get("src_ip") or None,
        "source_port": _port(record, "src_port"),
        "destination_ip": record.get("dest_ip") or None,
        "destination_port": _port(record, "dest_port"),
        "protocol": record.get("proto") or None,
        "attributes": attributes,
    }
    try:
        normalized = TelemetryIngestRequest.model_validate(payload)
    except ValidationError as exc:
        errors = ", ".join(".".join(str(part) for part in item["loc"]) for item in exc.errors())
        raise SuricataRecordError(f"record fields failed normalized validation: {errors}") from None
    if len(normalized.model_dump_json().encode("utf-8")) > 30 * 1024:
        raise SuricataRecordError("normalized record exceeds the ingestion request size limit")
    return normalized
