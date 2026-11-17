from threading import Lock

from app.events.models import HoneypotEvent
from app.telemetry.models import TelemetryAlert


class TelemetryAlertService:
    """Small deterministic rule set; alerts never execute or enforce actions."""

    _SUSPICIOUS_MARKERS = {
        "authentication_failure",
        "brute_force",
        "command_injection",
        "credential_stuffing",
        "exploit",
        "intrusion",
        "malware",
        "port_scan",
        "scan",
        "sql_injection",
        "unauthorized_access",
    }

    def __init__(self, limit: int = 500) -> None:
        self._limit = limit
        self._alerts: list[TelemetryAlert] = []
        self._by_event: dict[str, TelemetryAlert] = {}
        self._lock = Lock()

    @classmethod
    def _rule_for(cls, event: HoneypotEvent) -> str | None:
        if event.source != "external":
            return None
        if (
            event.source_system == "suricata"
            and event.telemetry_event_type == "suricata_alert"
        ):
            return "suricata_eve_alert"
        if event.severity in {"high", "critical"}:
            return "external_high_severity"
        normalized_type = (event.telemetry_event_type or "").casefold()
        tokens = set(normalized_type.replace("-", "_").replace(".", "_").split("_"))
        if any(marker in normalized_type or marker in tokens for marker in cls._SUSPICIOUS_MARKERS):
            return "external_suspicious_event_type"
        return None

    def inspect(self, event: HoneypotEvent) -> TelemetryAlert | None:
        rule = self._rule_for(event)
        if rule is None:
            return None
        with self._lock:
            existing = self._by_event.get(event.event_id)
            if existing is not None:
                return existing
            alert = TelemetryAlert(
                alert_id=f"alert-{event.event_id.removeprefix('external-')}",
                event_id=event.event_id,
                severity=event.severity,
                source_system=event.source_system or "generic",
                event_type=event.telemetry_event_type or "unknown",
                rule=rule,
                message="External telemetry matched a configured suspicious-event rule.",
            )
            self._alerts.append(alert)
            self._by_event[event.event_id] = alert
            while len(self._alerts) > self._limit:
                removed = self._alerts.pop(0)
                self._by_event.pop(removed.event_id, None)
            return alert

    def get_for_event(self, event_id: str) -> TelemetryAlert | None:
        with self._lock:
            return self._by_event.get(event_id)

    def list_alerts(self, limit: int = 100) -> list[TelemetryAlert]:
        with self._lock:
            return list(reversed(self._alerts[-limit:]))

    def clear(self) -> None:
        with self._lock:
            self._alerts.clear()
            self._by_event.clear()
