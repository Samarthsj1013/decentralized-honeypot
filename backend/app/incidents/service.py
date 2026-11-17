import os
from datetime import datetime, timezone
from ipaddress import ip_address

from fastapi import HTTPException

from app.events.models import HoneypotEvent
from app.incidents.models import Incident, IncidentStatus
from app.incidents.storage import SQLiteIncidentStorage


class IncidentService:
    """Rule-based, passive correlator for external Zeek and Suricata telemetry."""

    def __init__(self, storage: SQLiteIncidentStorage | None = None, window_seconds: int | None = None) -> None:
        self.storage = storage or SQLiteIncidentStorage()
        raw_window = window_seconds if window_seconds is not None else int(os.getenv("HONEYPOT_CORRELATION_WINDOW_SECONDS", "300"))
        if not 1 <= raw_window <= 3600:
            raise ValueError("correlation window must be between 1 and 3600 seconds")
        self.window_seconds = raw_window

    def inspect(self, event: HoneypotEvent) -> Incident | None:
        if event.source != "external" or event.source_system not in {"zeek", "suricata", "cowrie"} or not event.source_ip:
            return None
        try:
            source_ip = str(ip_address(event.source_ip))
            occurred_at = event.timestamp
            if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
                return None
        except (ValueError, TypeError):
            return None
        relevant = event.model_copy(update={"source_ip": source_ip, "timestamp": occurred_at.astimezone(timezone.utc)})
        return self.storage.ingest_and_correlate(relevant, self.window_seconds, datetime.now(timezone.utc).isoformat())

    def list(self, limit: int, offset: int, status: str | None, severity: str | None, source_ip: str | None):
        return self.storage.list(limit=limit, offset=offset, status=status, severity=severity, source_ip=source_ip)

    def get(self, incident_id: str) -> Incident:
        incident = self.storage.get(incident_id)
        if incident is None:
            raise HTTPException(404, "Incident not found")
        return incident

    def transition(self, incident_id: str, status: IncidentStatus) -> Incident:
        try:
            changed = self.storage.set_status(incident_id, status)
        except ValueError:
            raise HTTPException(409, "A resolved incident cannot be acknowledged") from None
        if changed is None:
            raise HTTPException(404, "Incident not found")
        return changed

    def stats(self):
        return self.storage.stats()
