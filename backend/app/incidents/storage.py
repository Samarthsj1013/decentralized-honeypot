from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from threading import RLock
from contextlib import contextmanager

from app.events.models import HoneypotEvent
from app.incidents.models import Incident, IncidentStatus


DEFAULT_DATABASE_PATH = Path(__file__).resolve().parents[3] / "data" / "incidents.sqlite3"
MAX_CANDIDATES = 10000


class SQLiteIncidentStorage:
    """Separate additive incident store; tables are initialized on first use."""

    def __init__(self, database_path: str | Path | None = None) -> None:
        configured = database_path or os.getenv("HONEYPOT_INCIDENT_DB_PATH") or DEFAULT_DATABASE_PATH
        self.database_path = Path(configured)
        self._lock = RLock()
        self._initialized = False

    @contextmanager
    def _connect(self):
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.database_path), timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self, connection: sqlite3.Connection) -> None:
        if self._initialized:
            return
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                source_ip TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                status TEXT NOT NULL,
                contributing_event_ids TEXT NOT NULL,
                contributing_sensors TEXT NOT NULL,
                detection_rules TEXT NOT NULL,
                evidence_summary TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents(last_seen DESC);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
            CREATE TABLE IF NOT EXISTS correlation_events (
                event_id TEXT PRIMARY KEY,
                source_ip TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                source_system TEXT NOT NULL,
                sensor_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                destination_port INTEGER,
                session_ref TEXT,
                auth_outcome TEXT,
                command_attempt INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_correlation_source_time ON correlation_events(source_ip, occurred_at);
            """
        )
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(correlation_events)")}
        for name, declaration in (
            ("session_ref", "TEXT"),
            ("auth_outcome", "TEXT"),
            ("command_attempt", "INTEGER NOT NULL DEFAULT 0"),
        ):
            if name not in columns:
                connection.execute(f"ALTER TABLE correlation_events ADD COLUMN {name} {declaration}")
        connection.commit()
        self._initialized = True

    @staticmethod
    def _decode(row: sqlite3.Row) -> Incident:
        return Incident(
            incident_id=row["incident_id"], source_ip=row["source_ip"],
            first_seen=row["first_seen"], last_seen=row["last_seen"],
            severity=row["severity"], confidence=row["confidence"], status=row["status"],
            contributing_event_ids=json.loads(row["contributing_event_ids"]),
            contributing_sensors=json.loads(row["contributing_sensors"]),
            detection_rules=json.loads(row["detection_rules"]),
            evidence_summary=json.loads(row["evidence_summary"]),
        )

    def ingest_and_correlate(self, event: HoneypotEvent, window_seconds: int, now: str) -> Incident | None:
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            connection.execute("BEGIN IMMEDIATE")
            attributes = event.attributes if isinstance(event.attributes, dict) else {}
            session_ref = attributes.get("session_id") if isinstance(attributes.get("session_id"), str) else None
            auth_outcome = attributes.get("authentication_outcome") if attributes.get("authentication_outcome") in {"success", "failed"} else None
            command_attempt = int(attributes.get("command_attempt") is True)
            connection.execute(
                "INSERT OR IGNORE INTO correlation_events "
                "(event_id, source_ip, occurred_at, observed_at, source_system, sensor_id, event_type, severity, destination_port, session_ref, auth_outcome, command_attempt) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (event.event_id, event.source_ip, event.timestamp.isoformat(), now,
                 event.source_system, event.sensor_id or "unknown", event.telemetry_event_type or "unknown",
                 event.severity, event.destination_port, session_ref, auth_outcome, command_attempt),
            )
            from datetime import datetime, timedelta
            cutoff_observed = (datetime.fromisoformat(now) - timedelta(seconds=window_seconds)).isoformat()
            connection.execute("DELETE FROM correlation_events WHERE observed_at < ?", (cutoff_observed,))
            excess = connection.execute(
                "SELECT COUNT(*) - ? FROM correlation_events", (MAX_CANDIDATES,)
            ).fetchone()[0]
            if excess > 0:
                connection.execute(
                    "DELETE FROM correlation_events WHERE event_id IN "
                    "(SELECT event_id FROM correlation_events ORDER BY observed_at ASC LIMIT ?)",
                    (excess,),
                )
            from datetime import datetime, timedelta, timezone
            cutoff = (event.timestamp.astimezone(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
            rows = connection.execute(
                "SELECT * FROM correlation_events WHERE source_ip = ? AND occurred_at >= ? ORDER BY occurred_at ASC",
                (event.source_ip, cutoff),
            ).fetchall()
            incident = self._upsert_incident(connection, event, rows, window_seconds)
            return incident

    def _upsert_incident(self, connection: sqlite3.Connection, event: HoneypotEvent, rows: list[sqlite3.Row], window_seconds: int) -> Incident | None:
        from datetime import datetime, timedelta, timezone
        from uuid import uuid4

        zeek = [row for row in rows if row["source_system"] == "zeek" and row["event_type"] in {"zeek_connection", "conn"}]
        alerts = [row for row in rows if row["source_system"] == "suricata" and row["event_type"] == "suricata_alert"]
        rules: list[str] = []
        evidence: list[str] = []
        if len(alerts) >= 2:
            rules.append("multiple_suricata_alerts"); evidence.append("Multiple Suricata alert events from this source IP occurred within the correlation window.")
        if alerts and len(zeek) >= 2:
            earliest_alert = min(datetime.fromisoformat(row["occurred_at"]) for row in alerts)
            if sum(datetime.fromisoformat(row["occurred_at"]) > earliest_alert for row in zeek) >= 2:
                rules.append("alert_then_zeek_connections"); evidence.append("A Suricata alert was followed by multiple Zeek connection events within the correlation window.")
        if len(zeek) >= 3:
            rules.append("repeated_zeek_connections"); evidence.append("Three or more Zeek connection events occurred within the correlation window.")
        cowrie_rows = [row for row in rows if row["source_system"] == "cowrie"]
        failed_logins = [row for row in cowrie_rows if row["event_type"] == "cowrie_login_failed"]
        successful_logins = [row for row in cowrie_rows if row["event_type"] == "cowrie_login_success"]
        if len(failed_logins) >= 3:
            rules.append("cowrie_repeated_failed_authentication"); evidence.append("At least three Cowrie SSH authentication failures came from this source IP in the correlation window.")
        if any(
            sum(datetime.fromisoformat(failure["occurred_at"]) < datetime.fromisoformat(success["occurred_at"]) for failure in failed_logins) >= 3
            for success in successful_logins
        ):
            rules.append("cowrie_success_after_repeated_failures"); evidence.append("Cowrie recorded a successful authentication after at least three failures from this source IP; this is suspicious activity, not proof of compromise.")
        session_commands: dict[str, int] = {}
        for row in cowrie_rows:
            if row["command_attempt"] and row["session_ref"]:
                session_commands[row["session_ref"]] = session_commands.get(row["session_ref"], 0) + 1
        if any(count >= 3 for count in session_commands.values()):
            rules.append("cowrie_multiple_commands_in_session"); evidence.append("At least three command attempts were observed in one Cowrie session; command text and output are not retained here.")
        if sum(row["event_type"] == "cowrie_session_connected" for row in cowrie_rows) >= 3:
            rules.append("cowrie_repeated_sessions_from_source"); evidence.append("At least three Cowrie SSH sessions were observed from this source IP in the correlation window.")
        if any(row["event_type"] == "cowrie_session_connected" for row in cowrie_rows) and zeek:
            rules.append("cowrie_correlated_zeek_connections"); evidence.append("Cowrie session activity and Zeek connection events share a source IP and correlation window.")
        if cowrie_rows and alerts:
            rules.append("cowrie_correlated_suricata_alert"); evidence.append("Cowrie activity and a Suricata alert share a source IP and correlation window.")
        ports = {row["destination_port"] for row in rows if row["destination_port"] is not None}
        if len(ports) >= 3:
            rules.append("multiple_destination_ports"); evidence.append("Connections targeted at least three distinct destination ports within the correlation window.")
        suspicious_sensor_ids = {
            row["sensor_id"]
            for row in rows
            if row["sensor_id"] != "unknown"
            and (
                row["severity"] in {"high", "critical"}
                or (row["source_system"] == "suricata" and row["event_type"] == "suricata_alert")
                or (
                    row["source_system"] == "cowrie"
                    and (
                        row["auth_outcome"] == "failed"
                        or row["command_attempt"]
                        or row["event_type"] in {"cowrie_file_upload", "cowrie_file_download"}
                    )
                )
            )
        }
        sensors = sorted({f"{row['source_system']}:{row['sensor_id']}" for row in rows})
        if len(suspicious_sensor_ids) >= 2:
            rules.append("multi_sensor_activity"); evidence.append("Suspicious evidence was independently observed by multiple sensors.")
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        ordered = sorted(rows, key=lambda row: row["occurred_at"])
        if len(ordered) >= 3 and severity_order[ordered[-1]["severity"]] > max(severity_order[row["severity"]] for row in ordered[:-1]):
            rules.append("suspicious_activity_escalation"); evidence.append("The latest event severity exceeded all earlier events in the correlation window.")
        if not rules:
            return None

        timestamp_values = [datetime.fromisoformat(row["occurred_at"]) for row in rows]
        event_ids = list(dict.fromkeys(row["event_id"] for row in rows))[-200:]
        max_severity = max((row["severity"] for row in rows), key=lambda value: severity_order[value])
        high_rules = ("multiple_suricata_alerts", "alert_then_zeek_connections", "suspicious_activity_escalation", "cowrie_success_after_repeated_failures", "cowrie_correlated_suricata_alert")
        rule_severity = "high" if any(rule in rules for rule in high_rules) else "medium"
        severity = max((max_severity, rule_severity), key=lambda value: severity_order[value])
        confidence_by_rule = {"multi_sensor_activity": .45, "repeated_zeek_connections": .55, "multiple_destination_ports": .60, "multiple_suricata_alerts": .70, "alert_then_zeek_connections": .75, "suspicious_activity_escalation": .85, "cowrie_repeated_failed_authentication": .60, "cowrie_success_after_repeated_failures": .80, "cowrie_multiple_commands_in_session": .65, "cowrie_repeated_sessions_from_source": .60, "cowrie_correlated_zeek_connections": .70, "cowrie_correlated_suricata_alert": .75}
        confidence = min(.95, max(confidence_by_rule[rule] for rule in rules) + .05 * (len(rules) - 1))
        correlation_start = (event.timestamp.astimezone(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
        existing_row = connection.execute(
            "SELECT * FROM incidents WHERE source_ip = ? AND status != 'resolved' AND last_seen >= ? ORDER BY last_seen DESC LIMIT 1",
            (event.source_ip, correlation_start),
        ).fetchone()
        if existing_row is None:
            existing_row = connection.execute(
                "SELECT * FROM incidents WHERE source_ip = ? AND status = 'resolved' AND last_seen >= ? ORDER BY last_seen DESC LIMIT 1",
                (event.source_ip, correlation_start),
            ).fetchone()
        if existing_row:
            current = self._decode(existing_row)
            merged_ids = list(dict.fromkeys(current.contributing_event_ids + event_ids))[-200:]
            merged_sensors = sorted(set(current.contributing_sensors + sensors))[-32:]
            merged_rules = list(dict.fromkeys(current.detection_rules + rules))[-12:]
            merged_evidence = list(dict.fromkeys(current.evidence_summary + evidence))[-12:]
            status: IncidentStatus = "open" if current.status == "resolved" else current.status
            incident = current.model_copy(update={
                "last_seen": max(current.last_seen, max(timestamp_values)),
                "severity": max((current.severity, severity), key=lambda value: severity_order[value]),
                "confidence": max(current.confidence, confidence), "status": status,
                "contributing_event_ids": merged_ids, "contributing_sensors": merged_sensors,
                "detection_rules": merged_rules, "evidence_summary": merged_evidence,
            })
        else:
            incident = Incident(
                incident_id=str(uuid4()), source_ip=event.source_ip,
                first_seen=min(timestamp_values), last_seen=max(timestamp_values), severity=severity,
                confidence=confidence, status="open", contributing_event_ids=event_ids,
                contributing_sensors=sensors[:32], detection_rules=rules[:12], evidence_summary=evidence[:12],
            )
        connection.execute(
            "INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(incident_id) DO UPDATE SET last_seen=excluded.last_seen, severity=excluded.severity, confidence=excluded.confidence, status=excluded.status, contributing_event_ids=excluded.contributing_event_ids, contributing_sensors=excluded.contributing_sensors, detection_rules=excluded.detection_rules, evidence_summary=excluded.evidence_summary",
            (incident.incident_id, incident.source_ip, incident.first_seen.isoformat(), incident.last_seen.isoformat(), incident.severity, incident.confidence, incident.status, json.dumps(incident.contributing_event_ids), json.dumps(incident.contributing_sensors), json.dumps(incident.detection_rules), json.dumps(incident.evidence_summary)),
        )
        return incident

    def list(self, *, limit: int, offset: int, status: str | None = None, severity: str | None = None, source_ip: str | None = None) -> tuple[list[Incident], int]:
        clauses, values = [], []
        if status: clauses.append("status = ?"); values.append(status)
        if severity: clauses.append("severity = ?"); values.append(severity)
        if source_ip: clauses.append("source_ip = ?"); values.append(source_ip)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            total = connection.execute("SELECT COUNT(*) FROM incidents" + where, values).fetchone()[0]
            rows = connection.execute("SELECT * FROM incidents" + where + " ORDER BY last_seen DESC LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
        return [self._decode(row) for row in rows], total

    def get(self, incident_id: str) -> Incident | None:
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            row = connection.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        return self._decode(row) if row else None

    def stats(self) -> dict:
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            rows = connection.execute("SELECT status, severity, COUNT(*) AS count FROM incidents GROUP BY status, severity").fetchall()
        result = {"total": 0, "open": 0, "acknowledged": 0, "resolved": 0, "severity_counts": {key: 0 for key in ("low", "medium", "high", "critical")}}
        for row in rows:
            result["total"] += row["count"]; result[row["status"]] += row["count"]; result["severity_counts"][row["severity"]] += row["count"]
        return result

    def profile_signals(self, *, since: str, limit: int = 10000) -> list[dict]:
        """Return bounded incident aggregates for profiling, excluding evidence and event IDs."""
        bounded_limit = min(max(int(limit), 1), 10000)
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            rows = connection.execute(
                "SELECT source_ip, last_seen, severity, detection_rules FROM incidents "
                "WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT ?",
                (since, bounded_limit),
            ).fetchall()
        result = []
        for row in rows:
            try:
                rules = json.loads(row["detection_rules"])
            except (TypeError, json.JSONDecodeError):
                rules = []
            result.append({
                "source_ip": row["source_ip"],
                "last_seen": row["last_seen"],
                "severity": row["severity"],
                "rule_count": len(rules) if isinstance(rules, list) else 0,
            })
        return result

    def set_status(self, incident_id: str, status: IncidentStatus) -> Incident | None:
        with self._lock, self._connect() as connection:
            self._initialize(connection)
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if row is None: return None
            if status == "acknowledged" and row["status"] == "resolved":
                raise ValueError("resolved incident cannot be acknowledged")
            incident = self._decode(row).model_copy(update={"status": status})
            connection.execute("UPDATE incidents SET status = ? WHERE incident_id = ?", (status, incident_id))
            return incident
