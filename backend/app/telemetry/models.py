from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.events.models import HoneypotEvent


class TelemetryAlert(BaseModel):
    model_config = ConfigDict(frozen=True)

    alert_id: str
    event_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: Literal["low", "medium", "high", "critical"]
    source_system: str
    event_type: str
    rule: str
    message: str


class TelemetryIngestResponse(BaseModel):
    accepted: bool = True
    duplicate: bool = False
    event: HoneypotEvent
    alert: TelemetryAlert | None = None
    intelligence_collection: dict | None = None


class LiveEventSummary(BaseModel):
    event_id: str
    timestamp: datetime
    source: Literal["simulator", "external"]
    event_type: str
    severity: Literal["low", "medium", "high", "critical"]
    action: str
    source_system: str | None = None
    telemetry_event_type: str | None = None


class CowrieEventSummary(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: str
    source_ip: str | None = None
    severity: Literal["low", "medium", "high", "critical"]
    session_ref: str | None = None
    authentication_outcome: Literal["success", "failed"] | None = None
    command_attempt: bool = False
    summary: str


def live_summary(event: HoneypotEvent) -> LiveEventSummary:
    """Project an event for browser updates without raw attributes or addresses."""
    return LiveEventSummary(
        event_id=event.event_id,
        timestamp=event.timestamp,
        source=event.source,
        event_type=event.event_type,
        severity=event.severity,
        action=event.action,
        source_system=event.source_system,
        telemetry_event_type=event.telemetry_event_type,
    )


def cowrie_summary(event: HoneypotEvent) -> CowrieEventSummary | None:
    """Expose only safe Cowrie session metadata, never credentials or commands."""
    if event.source_system != "cowrie" or event.source != "external":
        return None
    attributes = event.attributes if isinstance(event.attributes, dict) else {}
    messages = {
        "cowrie_login_failed": "SSH authentication failed",
        "cowrie_login_success": "SSH authentication succeeded (not proof of compromise)",
        "cowrie_session_connected": "SSH session connected",
        "cowrie_session_closed": "SSH session closed",
        "cowrie_command_attempt": "Command attempt observed; command text and output withheld",
        "cowrie_file_upload": "File upload observed; file contents withheld",
        "cowrie_file_download": "File download activity observed; content withheld",
        "cowrie_session_metadata": "SSH client/session metadata observed",
        "cowrie_other": "Other Cowrie session event observed",
    }
    auth = attributes.get("authentication_outcome")
    if auth not in {"success", "failed"}:
        auth = None
    session = attributes.get("session_id")
    if not isinstance(session, str) or len(session) > 64:
        session = None
    return CowrieEventSummary(
        event_id=event.event_id,
        timestamp=event.timestamp,
        event_type=event.telemetry_event_type or event.action,
        source_ip=event.source_ip,
        severity=event.severity,
        session_ref=session,
        authentication_outcome=auth,
        command_attempt=attributes.get("command_attempt") is True,
        summary=messages.get(event.telemetry_event_type, "Cowrie event observed"),
    )
