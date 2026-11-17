"""Safe Cowrie JSON log projection to the normalized telemetry contract."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any

from app.events.models import TelemetryIngestRequest

MAX_COWRIE_LINE_BYTES = 64 * 1024
_EVENT_MAP = {
    "cowrie.login.failed": ("cowrie_login_failed", "failed"),
    "cowrie.login.success": ("cowrie_login_success", "success"),
    "cowrie.session.connect": ("cowrie_session_connected", None),
    "cowrie.session.closed": ("cowrie_session_closed", None),
    "cowrie.command.input": ("cowrie_command_attempt", None),
    "cowrie.command.failed": ("cowrie_command_attempt", None),
    "cowrie.session.file_upload": ("cowrie_file_upload", None),
    "cowrie.session.file_download": ("cowrie_file_download", None),
    "cowrie.session.file_download.failed": ("cowrie_file_download", None),
    "cowrie.session.params": ("cowrie_session_metadata", None),
    "cowrie.client.version": ("cowrie_session_metadata", None),
    "cowrie.client.fingerprint": ("cowrie_session_metadata", None),
}
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class CowrieRecordError(ValueError):
    """A malformed or unsafe Cowrie JSON record."""


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant {value}")


def _bounded_text(value: Any, maximum: int = 128) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = "".join(char for char in value.strip() if char.isprintable())
    return normalized[:maximum] or None


def _integer(value: Any) -> int | None:
    if type(value) is int and 1 <= value <= 65535:
        return value
    # Bound before conversion: an attacker-controlled log field with tens of
    # thousands of digits must not escape as Python's integer conversion error.
    if isinstance(value, str) and len(value) <= 5 and value.isdecimal():
        parsed = int(value)
        return parsed if 1 <= parsed <= 65535 else None
    return None


def _event_time(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise CowrieRecordError("record is missing a bounded timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise CowrieRecordError("timestamp is not valid ISO-8601") from None
    if result.tzinfo is None or result.utcoffset() is None:
        raise CowrieRecordError("timestamp must include a timezone")
    return result


def _session_reference(value: Any) -> str | None:
    text = _bounded_text(value, 256)
    if text is None:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


def parse_cowrie_record(line: str | bytes, *, sensor_id: str) -> TelemetryIngestRequest:
    """Parse one Cowrie JSON line without retaining secrets or raw commands."""
    try:
        raw = line.encode("utf-8") if isinstance(line, str) else line
    except UnicodeEncodeError:
        raise CowrieRecordError("record is not valid UTF-8") from None
    if len(raw) > MAX_COWRIE_LINE_BYTES:
        raise CowrieRecordError("Cowrie record exceeds the maximum line size")
    try:
        document = json.loads(raw, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise CowrieRecordError("record is not valid bounded JSON") from None
    if not isinstance(document, dict):
        raise CowrieRecordError("Cowrie record must be a JSON object")

    original_type = document.get("eventid")
    if (
        not isinstance(original_type, str)
        or not original_type.startswith("cowrie.")
        or len(original_type) > 96
        or not _SAFE_LABEL.fullmatch(original_type)
    ):
        raise CowrieRecordError("eventid must be a bounded Cowrie event name")
    event_type, auth_outcome = _EVENT_MAP.get(original_type, ("cowrie_other", None))
    timestamp = _event_time(document.get("timestamp"))

    attributes: dict[str, Any] = {"cowrie_event_id": original_type}
    session_ref = _session_reference(document.get("session"))
    if session_ref is not None:
        attributes["session_id"] = session_ref
    username = _bounded_text(document.get("username"), 64)
    if username is not None:
        # Login names are credential data. Persist only a stable reference so
        # event and ledger APIs never return the original username.
        attributes["username_ref"] = hashlib.sha256(
            f"{sensor_id}\0{username.casefold()}".encode("utf-8")
        ).hexdigest()
    if auth_outcome is not None:
        attributes["authentication_outcome"] = auth_outcome
    if event_type == "cowrie_command_attempt":
        command = document.get("input")
        attributes["command_attempt"] = True
        if isinstance(command, str):
            attributes["command_length"] = min(len(command), 4096)
    if event_type in {"cowrie_file_upload", "cowrie_file_download"}:
        attributes["file_transfer_direction"] = "upload" if event_type.endswith("upload") else "download"
        digest = _bounded_text(document.get("shasum") or document.get("sha256"), 128)
        if digest and re.fullmatch(r"(?i)(?:[a-f0-9]{40}|[a-f0-9]{64})", digest):
            attributes["file_digest"] = digest.lower()
        size = document.get("size")
        if type(size) is int and 0 <= size <= 2**53:
            attributes["file_size"] = size
    for source_key, target_key in (("arch", "client_architecture"), ("version", "client_version"), ("protocol", "client_protocol")):
        value = _bounded_text(document.get(source_key), 96)
        if value is not None:
            attributes[target_key] = value

    # Hash the bounded original line for a stable deduplication key. The line,
    # including any password field, is never placed in the normalized payload.
    external_id = hashlib.sha256(raw.rstrip(b"\r\n")).hexdigest()
    try:
        return TelemetryIngestRequest.model_validate({
            "source_system": "cowrie",
            "sensor_id": sensor_id,
            "external_event_id": external_id,
            "occurred_at": timestamp,
            "event_type": event_type,
            "severity": "medium" if auth_outcome == "failed" else "low",
            "source_ip": document.get("src_ip"),
            "source_port": _integer(document.get("src_port")),
            "destination_ip": document.get("dst_ip") or document.get("dest_ip"),
            "destination_port": _integer(document.get("dst_port") or document.get("dest_port")),
            "protocol": "ssh",
            "attributes": attributes,
        })
    except Exception:
        raise CowrieRecordError("record fields failed normalized telemetry validation") from None
