"""Deterministic offline adversary event generator. It never opens sockets."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


Scenario = Literal[
    "reconnaissance", "ssh_authentication_probing", "repeated_failed_authentication",
    "successful_auth_suspicious_activity", "multi_port_probing", "multi_protocol_activity",
    "repeated_session_behavior", "multi_sensor_correlated_activity", "low_and_slow_activity",
    "mixed_benign_suspicious_traffic",
]

SCENARIOS: tuple[Scenario, ...] = (
    "reconnaissance", "ssh_authentication_probing", "repeated_failed_authentication",
    "successful_auth_suspicious_activity", "multi_port_probing", "multi_protocol_activity",
    "repeated_session_behavior", "multi_sensor_correlated_activity", "low_and_slow_activity",
    "mixed_benign_suspicious_traffic",
)


class SyntheticEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    occurred_at: datetime
    event_type: str
    source_system: Literal["zeek", "suricata", "cowrie"]
    sensor_id: str
    source_ip: str = "198.51.100.10"
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = None
    severity: Literal["low", "medium", "high", "critical"] = "low"
    suspicious: bool
    attributes: dict[str, str | int | float | bool]


def generate_scenario(scenario: Scenario, seed: int, *, start: datetime | None = None) -> list[SyntheticEvent]:
    """Create normalized, bounded synthetic records from a stable scenario seed."""
    if scenario not in SCENARIOS:
        raise ValueError("unsupported synthetic scenario")
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError("seed must be between 0 and 4294967295")
    rng = random.Random(seed)
    start = start or datetime(2026, 1, 1, tzinfo=timezone.utc)
    specs: list[tuple[str, str, str, int | None, str, str, bool, dict]] = []

    def add(kind, source="zeek", sensor="sensor-a", port=None, proto="tcp", severity="low", suspicious=True, attrs=None):
        specs.append((kind, source, sensor, port, proto, severity, suspicious, attrs or {}))

    if scenario == "reconnaissance":
        for port in (22, 80, 443, 8080): add("zeek_connection", port=port)
    elif scenario in {"ssh_authentication_probing", "repeated_failed_authentication"}:
        count = 3 if scenario == "ssh_authentication_probing" else 6
        for _ in range(count): add("cowrie_login_failed", "cowrie", port=22, proto="ssh", attrs={"authentication_outcome": "failed"})
    elif scenario == "successful_auth_suspicious_activity":
        add("cowrie_login_failed", "cowrie", port=22, proto="ssh", attrs={"authentication_outcome": "failed"})
        add("cowrie_login_success", "cowrie", port=22, proto="ssh", attrs={"authentication_outcome": "success"})
        add("cowrie_command_attempt", "cowrie", port=22, proto="ssh", attrs={"command_attempt": True})
        add("suricata_alert", "suricata", port=445, severity="high", attrs={"alert_signature": "synthetic test signature"})
    elif scenario == "multi_port_probing":
        for port in (21, 22, 23, 80, 443, 3389): add("zeek_connection", port=port)
    elif scenario == "multi_protocol_activity":
        for proto, port in (("tcp", 22), ("udp", 53), ("icmp", None), ("tcp", 443)):
            add("zeek_connection", port=port, proto=proto)
    elif scenario == "repeated_session_behavior":
        for _ in range(5): add("cowrie_session_connected", "cowrie", port=22, proto="ssh", attrs={"session_id": "synthetic-session"})
        for _ in range(3): add("cowrie_command_attempt", "cowrie", port=22, proto="ssh", attrs={"command_attempt": True})
    elif scenario == "multi_sensor_correlated_activity":
        add("suricata_alert", "suricata", "sensor-a", 443, severity="high", attrs={"alert_signature": "synthetic test signature"})
        add("zeek_connection", "zeek", "sensor-b", 443)
        add("zeek_connection", "zeek", "sensor-c", 8443)
    elif scenario == "low_and_slow_activity":
        for i in range(4):
            add("zeek_connection", port=(22, 80, 443, 8080)[i], attrs={"synthetic_delay_seconds": 30 + i * 30})
    else:  # mixed benign and suspicious traffic
        for _ in range(4): add("zeek_connection", port=rng.choice((80, 443)), suspicious=False)
        for _ in range(3): add("cowrie_login_failed", "cowrie", port=22, proto="ssh", attrs={"authentication_outcome": "failed"})

    events = []
    for index, (kind, source, sensor, port, proto, severity, suspicious, attrs) in enumerate(specs):
        spacing = 45 if scenario == "low_and_slow_activity" else 1
        occurred = start + timedelta(seconds=index * spacing)
        events.append(SyntheticEvent(
            event_id=f"syn-{seed:010d}-{index:04d}", occurred_at=occurred, event_type=kind,
            source_system=source, sensor_id=sensor, destination_port=port, protocol=proto,
            severity=severity, suspicious=suspicious, attributes=attrs,
        ))
    return events
