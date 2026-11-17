"""Versioned, privacy-filtered aggregates for external sensor behavior."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from math import isfinite, log
from typing import Any

from app.events.models import HoneypotEvent


FEATURE_SCHEMA_VERSION = 1
FEATURE_SCHEMA_NAME = "decentralized_honeypot.attacker_behavior_features"
FEATURE_COLUMNS = (
    "event_count", "failed_auth_count", "successful_auth_count",
    "unique_usernames_attempted", "session_count", "command_attempt_count",
    "unique_destination_ports", "connection_count", "connections_per_minute",
    "suricata_alert_count", "alert_severity_low", "alert_severity_medium",
    "alert_severity_high", "alert_severity_critical", "mean_session_duration_seconds",
    "session_duration_available", "protocol_ssh_count", "protocol_tcp_count",
    "protocol_udp_count", "protocol_icmp_count", "protocol_other_count",
    "unique_protocol_count", "sensor_count", "mean_inter_attempt_seconds",
    "inter_attempts_available", "behavioral_diversity", "incident_count",
    "incident_severity_high_count", "incident_severity_critical_count",
    "incident_rule_count",
)

FEATURE_DEFINITIONS = {
    "event_count": "External events in the source-IP observation window.",
    "failed_auth_count": "Cowrie failed authentication events; passwords are ignored.",
    "successful_auth_count": "Cowrie successful authentication events; not proof of compromise.",
    "unique_usernames_attempted": "Distinct count of sensor-scoped username references; raw Cowrie names are not stored.",
    "session_count": "Distinct Cowrie session references observed as connected.",
    "command_attempt_count": "Cowrie command attempt count; command text is ignored.",
    "unique_destination_ports": "Distinct destination ports across external events.",
    "connection_count": "Zeek connection and Suricata flow event count.",
    "connections_per_minute": "Connection count divided by the bounded observed span in minutes.",
    "suricata_alert_count": "Suricata alert events in the observation window.",
    "alert_severity_low": "Count of low severity Suricata alerts.",
    "alert_severity_medium": "Count of medium severity Suricata alerts.",
    "alert_severity_high": "Count of high severity Suricata alerts.",
    "alert_severity_critical": "Count of critical severity Suricata alerts.",
    "mean_session_duration_seconds": "Mean available bounded duration from sensor metadata.",
    "session_duration_available": "One if at least one usable duration was observed.",
    "protocol_ssh_count": "Events labeled SSH.",
    "protocol_tcp_count": "Events labeled TCP.",
    "protocol_udp_count": "Events labeled UDP.",
    "protocol_icmp_count": "Events labeled ICMP.",
    "protocol_other_count": "Events with another or unavailable protocol.",
    "unique_protocol_count": "Distinct normalized protocol labels.",
    "sensor_count": "Distinct non-empty sensor identifiers.",
    "mean_inter_attempt_seconds": "Mean interval between authentication or command attempts.",
    "inter_attempts_available": "One when at least two attempts have timestamps.",
    "behavioral_diversity": "Normalized Shannon entropy across observed event types (0 to 1).",
    "incident_count": "Persisted incidents for this source IP in the same observation window.",
    "incident_severity_high_count": "High severity incidents for this source IP in the window.",
    "incident_severity_critical_count": "Critical severity incidents for this source IP in the window.",
    "incident_rule_count": "Sum of matched rule counts from incidents in the window; rule text is not retained.",
}


def _duration(event: HoneypotEvent) -> float | None:
    attributes = event.attributes if isinstance(event.attributes, dict) else {}
    raw = attributes.get("duration")
    if raw is None and isinstance(attributes.get("flow"), dict):
        flow = attributes["flow"]
        start, end = flow.get("start"), flow.get("end")
        if type(start) in (float, int) and type(end) in (float, int):
            raw = float(end) - float(start)
    if isinstance(raw, str):
        try:
            raw = float(raw)
        except ValueError:
            return None
    if type(raw) not in (float, int) or not isfinite(float(raw)):
        return None
    value = float(raw)
    return min(86400.0, max(0.0, value))


def extract_features(events: list[HoneypotEvent], *, window_seconds: int, as_of: datetime | None = None, incident_records: list[dict[str, Any]] | None = None) -> dict[str, int | float]:
    """Aggregate only selected external telemetry fields; never return raw identifiers or payloads."""
    if not 60 <= window_seconds <= 86400:
        raise ValueError("window_seconds must be between 60 and 86400")
    eligible = [event for event in events if event.source == "external" and event.source_ip and event.source_system in {"zeek", "suricata", "cowrie"}]
    if as_of is None:
        as_of = max((event.timestamp for event in eligible), default=datetime.now(timezone.utc))
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise ValueError("as_of must include a timezone")
    cutoff = as_of.astimezone(timezone.utc) - timedelta(seconds=window_seconds)
    selected = []
    for event in eligible:
        timestamp = event.timestamp
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            continue
        if cutoff <= timestamp.astimezone(timezone.utc) <= as_of.astimezone(timezone.utc):
            selected.append(event)
    selected.sort(key=lambda item: item.timestamp.astimezone(timezone.utc))
    features: dict[str, int | float] = {name: 0 for name in FEATURE_COLUMNS}
    if not selected:
        return features

    event_types = Counter((event.telemetry_event_type or event.action or "unknown").casefold()[:64] for event in selected)
    protocols = Counter((event.protocol or "other").casefold() for event in selected)
    usernames: set[str] = set()
    ports: set[int] = set()
    sensors: set[str] = set()
    sessions: set[str] = set()
    durations: list[float] = []
    attempt_times: list[datetime] = []
    failed = successful = commands = connections = suricata_alerts = 0
    severity_counts = Counter()
    for event in selected:
        kind = (event.telemetry_event_type or event.action or "").casefold()
        attributes = event.attributes if isinstance(event.attributes, dict) else {}
        auth = attributes.get("authentication_outcome")
        if auth == "failed" or kind in {"cowrie_login_failed", "cowrie.login.failed"}:
            failed += 1
            attempt_times.append(event.timestamp.astimezone(timezone.utc))
        if auth == "success" or kind in {"cowrie_login_success", "cowrie.login.success"}:
            successful += 1
            attempt_times.append(event.timestamp.astimezone(timezone.utc))
        username_ref = attributes.get("username_ref")
        username = attributes.get("username")
        if auth in {"failed", "success"} or kind in {"cowrie_login_failed", "cowrie_login_success", "cowrie.login.failed", "cowrie.login.success"}:
            if isinstance(username_ref, str) and username_ref:
                usernames.add(username_ref)
            elif isinstance(username, str) and username:
                # Compatibility for previously recorded/direct test events;
                # normal Cowrie ingestion stores only username_ref.
                usernames.add(sha256(username.casefold().encode("utf-8", errors="ignore")).hexdigest())
        session_ref = attributes.get("session_id")
        if kind in {"cowrie_session_connected", "cowrie.session.connect"} and isinstance(session_ref, str) and session_ref:
            sessions.add(session_ref[:64])
        if attributes.get("command_attempt") is True or kind in {"cowrie_command_attempt", "cowrie.command.input", "cowrie.command.failed"}:
            commands += 1
            attempt_times.append(event.timestamp.astimezone(timezone.utc))
        if event.source_system == "zeek" and kind in {"zeek_connection", "conn"} or event.source_system == "suricata" and kind in {"suricata_flow", "flow"}:
            connections += 1
        if event.source_system == "suricata" and kind in {"suricata_alert", "alert"}:
            suricata_alerts += 1
            severity_counts[event.severity] += 1
        if event.destination_port is not None:
            ports.add(event.destination_port)
        if event.sensor_id:
            sensors.add(event.sensor_id[:64])
        duration = _duration(event)
        if duration is not None:
            durations.append(duration)
        # No raw command, password, filename, URL, or arbitrary payload is read here.

    span_seconds = max(60.0, (selected[-1].timestamp - selected[0].timestamp).total_seconds())
    features.update({
        "event_count": len(selected),
        "failed_auth_count": failed,
        "successful_auth_count": successful,
        "unique_usernames_attempted": len(usernames),
        "session_count": len(sessions),
        "command_attempt_count": commands,
        "unique_destination_ports": len(ports),
        "connection_count": connections,
        "connections_per_minute": round(connections / (span_seconds / 60.0), 6),
        "suricata_alert_count": suricata_alerts,
        "alert_severity_low": severity_counts["low"],
        "alert_severity_medium": severity_counts["medium"],
        "alert_severity_high": severity_counts["high"],
        "alert_severity_critical": severity_counts["critical"],
        "mean_session_duration_seconds": round(sum(durations) / len(durations), 6) if durations else 0.0,
        "session_duration_available": int(bool(durations)),
        "protocol_ssh_count": protocols["ssh"],
        "protocol_tcp_count": protocols["tcp"],
        "protocol_udp_count": protocols["udp"],
        "protocol_icmp_count": protocols["icmp"],
        "protocol_other_count": sum(value for key, value in protocols.items() if key not in {"ssh", "tcp", "udp", "icmp"}),
        "unique_protocol_count": len(protocols),
        "sensor_count": len(sensors),
    })
    selected_ip = str(selected[0].source_ip)
    for incident in incident_records or []:
        if incident.get("source_ip") != selected_ip or not isinstance(incident.get("last_seen"), str):
            continue
        try:
            incident_time = datetime.fromisoformat(incident["last_seen"].replace("Z", "+00:00"))
            if incident_time.tzinfo is None or incident_time.astimezone(timezone.utc) < cutoff or incident_time.astimezone(timezone.utc) > as_of.astimezone(timezone.utc):
                continue
        except ValueError:
            continue
        features["incident_count"] += 1
        severity = incident.get("severity")
        if severity == "high":
            features["incident_severity_high_count"] += 1
        elif severity == "critical":
            features["incident_severity_critical_count"] += 1
        rule_count = incident.get("rule_count", 0)
        if type(rule_count) is int and rule_count > 0:
            features["incident_rule_count"] += min(rule_count, 12)
    intervals = [(right - left).total_seconds() for left, right in zip(attempt_times, attempt_times[1:])]
    if intervals:
        features["mean_inter_attempt_seconds"] = round(sum(intervals) / len(intervals), 6)
        features["inter_attempts_available"] = 1
    if len(event_types) > 1:
        entropy = -sum((count / len(selected)) * log(count / len(selected)) for count in event_types.values())
        features["behavioral_diversity"] = round(entropy / log(len(event_types)), 6)
    return features


def group_external_events(events: list[HoneypotEvent], *, window_seconds: int, as_of: datetime | None = None, incident_records: list[dict[str, Any]] | None = None) -> dict[str, tuple[str, list[HoneypotEvent], dict[str, int | float]]]:
    """Return source-reference keyed groups; raw IP is used only as an ephemeral grouping key."""
    if as_of is None:
        as_of = max((event.timestamp for event in events if event.source_ip and event.source == "external"), default=datetime.now(timezone.utc))
    cutoff = as_of.astimezone(timezone.utc) - timedelta(seconds=window_seconds)
    all_by_ip: dict[str, list[HoneypotEvent]] = defaultdict(list)
    recent_by_ip: dict[str, list[HoneypotEvent]] = defaultdict(list)
    incident_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    incident_cutoff = as_of.astimezone(timezone.utc) - timedelta(seconds=window_seconds)
    for incident in incident_records or []:
        address = incident.get("source_ip")
        last_seen = incident.get("last_seen")
        if not isinstance(address, str) or not isinstance(last_seen, str):
            continue
        try:
            timestamp = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            if timestamp.tzinfo is not None and incident_cutoff <= timestamp.astimezone(timezone.utc) <= as_of.astimezone(timezone.utc):
                incident_by_ip[address].append(incident)
        except ValueError:
            continue
    for event in events:
        if event.source != "external" or event.source_system not in {"zeek", "suricata", "cowrie"} or not event.source_ip:
            continue
        address = str(event.source_ip)
        all_by_ip[address].append(event)
        if event.timestamp.tzinfo is not None and event.timestamp.astimezone(timezone.utc) >= cutoff:
            recent_by_ip[address].append(event)
    result = {}
    for address, recent in recent_by_ip.items():
        reference = sha256(address.encode("utf-8")).hexdigest()
        historical = all_by_ip[address]
        result[reference] = (address, historical, extract_features(recent, window_seconds=window_seconds, as_of=as_of, incident_records=incident_by_ip[address]))
    return result
