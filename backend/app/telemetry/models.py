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


class LiveEventSummary(BaseModel):
    event_id: str
    timestamp: datetime
    source: Literal["simulator", "external"]
    event_type: str
    severity: Literal["low", "medium", "high", "critical"]
    action: str
    source_system: str | None = None
    telemetry_event_type: str | None = None


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
