"""Small HTTP threat-intelligence exchange prototype.

Each node has an independent SQLite store and Ed25519 key. Peer bearer tokens
authenticate the HTTP channel; signatures authenticate record possession and
integrity. This module implements no consensus or automatic enforcement.
"""

from __future__ import annotations

import base64
import hmac
import json
import math
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
from threading import RLock
from typing import Literal
from uuid import uuid4

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, StrictInt, StrictStr, ValidationError, field_validator, model_validator


SIGNING_DOMAIN = b"decentralized-honeypot:node-threat-intel:v1\0"
MAX_BODY_BYTES = 16 * 1024
MAX_RECORD_AGE = timedelta(days=30)


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


class ThreatIntelRecord(BaseModel):
    """Bounded indicator observation; deliberately excludes raw events/actors."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, populate_by_name=True)
    schema_name: Literal["honeypot.threat-intel.v1"] = Field(
        default="honeypot.threat-intel.v1", alias="schema"
    )
    record_id: StrictStr = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    publisher_id: StrictStr = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    key_id: StrictStr = Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9_.:-]+$")
    created_at: datetime
    indicator_type: Literal["ipv4", "ipv6", "domain"]
    indicator: StrictStr = Field(min_length=1, max_length=253)
    classification: Literal["scanning", "brute_force", "exploit", "malware", "suspicious_activity"]
    severity: Literal["low", "medium", "high", "critical"]
    source_system: Literal["generic", "zeek", "suricata", "cowrie"]
    first_seen: datetime
    last_seen: datetime
    observation_count: StrictInt = Field(ge=1, le=1_000_000)

    @field_validator("created_at", "first_seen", "last_seen")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a timezone")
        return value

    @field_validator("indicator")
    @classmethod
    def validate_indicator(cls, value: str, info):
        kind = info.data.get("indicator_type")
        if kind in {"ipv4", "ipv6"}:
            try:
                parsed = ip_address(value)
            except ValueError as exc:
                raise ValueError("indicator must be a valid IP address") from exc
            if parsed.version != (4 if kind == "ipv4" else 6):
                raise ValueError("indicator address family does not match indicator_type")
        elif kind == "domain" and (
            len(value) > 253
            or not re.fullmatch(r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*", value)
        ):
            raise ValueError("indicator must be a bounded domain name")
        return value

    @model_validator(mode="after")
    def validate_time_order(self):
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen must not be later than last_seen")
        return self

    @classmethod
    def from_observation(
        cls, *, publisher_id: str, key_id: str, indicator: str,
        classification: str, severity: str, source_system: str,
        first_seen: datetime, last_seen: datetime, observation_count: int,
        indicator_type: str | None = None,
    ) -> "ThreatIntelRecord":
        if indicator_type is None:
            try:
                address = ip_address(indicator)
                indicator_type = "ipv4" if address.version == 4 else "ipv6"
            except ValueError:
                indicator_type = "domain"
        return cls(
            record_id=uuid4().hex, publisher_id=publisher_id, key_id=key_id,
            created_at=datetime.now(timezone.utc), indicator_type=indicator_type,
            indicator=indicator, classification=classification, severity=severity,
            source_system=source_system, first_seen=first_seen, last_seen=last_seen,
            observation_count=observation_count,
        )


class SignedThreatIntel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    record: ThreatIntelRecord
    digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    signature: StrictStr = Field(min_length=1, max_length=256)


class SecurityEventObservation(BaseModel):
    """Minimal event projection accepted by the optional local collector."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    source_system: Literal["generic", "zeek", "suricata", "cowrie"]
    sensor_id: StrictStr = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    external_event_id: StrictStr = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    occurred_at: datetime
    event_type: StrictStr = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    severity: Literal["low", "medium", "high", "critical"]
    source_ip: IPvAnyAddress | None = None

    @field_validator("occurred_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        return value


class ThreatPublicationPolicy(BaseModel):
    """Explicit collection gates; disabled and unmapped by default."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    enabled: bool = False
    minimum_severity: Literal["low", "medium", "high", "critical"] = "high"
    minimum_observations: int = Field(default=3, ge=2, le=1000)
    allowed_sources: list[Literal["generic", "zeek", "suricata", "cowrie"]] = Field(default_factory=list, max_length=4)
    event_type_classifications: dict[StrictStr, Literal["scanning", "brute_force", "exploit", "malware", "suspicious_activity"]] = Field(default_factory=dict, max_length=64)
    require_global_ip: bool = True

    @field_validator("allowed_sources")
    @classmethod
    def unique_sources(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("allowed_sources must be unique")
        return value


class PublisherKeyStageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    key_id: StrictStr = Field(min_length=1, max_length=96)
    public_key_pem: StrictStr = Field(min_length=80, max_length=2048)
    expected_fingerprint: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


class FingerprintConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_fingerprint: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    reason: StrictStr = Field(min_length=3, max_length=280)


@dataclass(frozen=True)
class TrustedPeer:
    key_id: str
    public_key: Ed25519PublicKey
    bearer_token: str
    allowed_sources: frozenset[str] | None = None
    allowed_classifications: frozenset[str] | None = None
    minimum_observations: int = 1


@dataclass(frozen=True)
class PeerEndpoint:
    base_url: str
    bearer_token: str


def _public_key_pem(key: Ed25519PublicKey) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _key_fingerprint(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sha256(raw).hexdigest()


def _normalized_indicator(record: ThreatIntelRecord) -> str:
    if record.indicator_type in {"ipv4", "ipv6"}:
        return ip_address(record.indicator).compressed
    return record.indicator.rstrip(".").casefold()


@dataclass(frozen=True)
class NodeConfig:
    node_id: str
    key_id: str
    private_key: Ed25519PrivateKey
    database_path: str | Path
    admin_token: str
    trusted_publishers: dict[str, TrustedPeer]
    peers: dict[str, PeerEndpoint]
    publication_policy: ThreatPublicationPolicy = field(default_factory=ThreatPublicationPolicy)
    dashboard_token: str | None = None
    dashboard_origins: tuple[str, ...] = ()

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.node_id):
            raise ValueError("Invalid node ID")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", self.key_id):
            raise ValueError("Invalid key ID")
        if not isinstance(self.private_key, Ed25519PrivateKey):
            raise ValueError("Node private key must be Ed25519")
        if len(self.admin_token) < 32:
            raise ValueError("Node admin token must contain at least 32 characters")
        if self.dashboard_token is not None and len(self.dashboard_token) < 32:
            raise ValueError("Node dashboard token must contain at least 32 characters")
        if any(not origin.startswith(("http://", "https://")) or origin == "*" for origin in self.dashboard_origins):
            raise ValueError("Dashboard CORS origins must be explicit HTTP(S) origins")
        if not isinstance(self.publication_policy, ThreatPublicationPolicy):
            raise ValueError("publication_policy must be validated ThreatPublicationPolicy")
        for peer_id, trusted in self.trusted_publishers.items():
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", peer_id) or len(trusted.bearer_token) < 32:
                raise ValueError("Trusted peer identity and bearer token are required")
            if not isinstance(trusted.public_key, Ed25519PublicKey):
                raise ValueError("Trusted peer public key must be Ed25519")
            if not 1 <= trusted.minimum_observations <= 1_000_000:
                raise ValueError("Publisher minimum_observations is out of range")
            if trusted.allowed_sources is not None and not trusted.allowed_sources <= {"generic", "zeek", "suricata", "cowrie"}:
                raise ValueError("Publisher policy contains an unsupported source")
            if trusted.allowed_classifications is not None and not trusted.allowed_classifications <= {"scanning", "brute_force", "exploit", "malware", "suspicious_activity"}:
                raise ValueError("Publisher policy contains an unsupported classification")
        for peer_id, endpoint in self.peers.items():
            if peer_id not in self.trusted_publishers:
                raise ValueError("Outbound peers must also have an explicit trusted publisher key")
            if not endpoint.base_url.startswith(("http://", "https://")) or len(endpoint.bearer_token) < 32:
                raise ValueError("Peer URL and bearer token are required")


class NodeStorage:
    """Per-node additive store with durable idempotency/replay protection."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS network_intelligence (record_id TEXT PRIMARY KEY, publisher_id TEXT NOT NULL, digest TEXT NOT NULL, record_json TEXT NOT NULL, state TEXT NOT NULL, received_at TEXT NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_network_intelligence_publisher ON network_intelligence(publisher_id)")
            db.execute("CREATE TABLE IF NOT EXISTS network_observation_fingerprints (fingerprint TEXT PRIMARY KEY, candidate_key TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS network_intel_candidates (candidate_key TEXT PRIMARY KEY, indicator TEXT NOT NULL, indicator_type TEXT NOT NULL, classification TEXT NOT NULL, source_system TEXT NOT NULL, severity TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, observation_count INTEGER NOT NULL, published_record_id TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS network_publisher_keys (publisher_id TEXT NOT NULL, key_id TEXT NOT NULL, public_key_pem TEXT NOT NULL, fingerprint TEXT NOT NULL, status TEXT NOT NULL, added_at TEXT NOT NULL, revoked_at TEXT, PRIMARY KEY(publisher_id,key_id))")
            db.execute("CREATE TABLE IF NOT EXISTS network_peer_registry (peer_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL, status TEXT NOT NULL, last_seen TEXT, last_success TEXT, failure_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, updated_at TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS network_sync_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, peer_id TEXT NOT NULL, record_id TEXT NOT NULL, succeeded INTEGER NOT NULL, error_code TEXT, attempted_at TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS network_intelligence_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id TEXT NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT, details_json TEXT NOT NULL, created_at TEXT NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_network_intelligence_audit_record ON network_intelligence_audit(record_id,id)")
            db.execute("CREATE TABLE IF NOT EXISTS network_indicator_relations (record_id TEXT NOT NULL, related_record_id TEXT NOT NULL, relation TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(record_id,related_record_id,relation))")
            db.execute("CREATE TABLE IF NOT EXISTS network_node_identity (slot INTEGER PRIMARY KEY CHECK(slot=1), node_id TEXT NOT NULL)")

    def bind_node_identity(self, node_id: str) -> None:
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT node_id FROM network_node_identity WHERE slot=1").fetchone()
            if row is not None and row[0] != node_id:
                raise ValueError("Configured node ID does not match the identity bound to this node database")
            db.execute("INSERT OR IGNORE INTO network_node_identity(slot,node_id) VALUES(1,?)", (node_id,))

    def put(self, envelope: SignedThreatIntel, state: str) -> Literal["stored", "duplicate"]:
        record = envelope.record
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT digest FROM network_intelligence WHERE record_id=?", (record.record_id,)).fetchone()
            if row:
                if row[0] != envelope.digest:
                    raise HTTPException(409, "Record ID was already used with different contents")
                return "duplicate"
            db.execute(
                "INSERT INTO network_intelligence VALUES (?, ?, ?, ?, ?, ?)",
                (record.record_id, record.publisher_id, envelope.digest,
                 envelope.model_dump_json(by_alias=True), state, datetime.now(timezone.utc).isoformat()),
            )
        return "stored"

    def put_import(self, envelope: SignedThreatIntel) -> tuple[Literal["stored", "duplicate"], str | None]:
        """Insert a pending record and classify same-indicator collisions atomically."""
        record = envelope.record
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            key_status = db.execute(
                "SELECT status FROM network_publisher_keys WHERE publisher_id=? AND key_id=?",
                (record.publisher_id, record.key_id),
            ).fetchone()
            if key_status is None or key_status[0] != "active":
                raise HTTPException(403, "Publisher key was revoked or is no longer active")
            existing = db.execute("SELECT digest FROM network_intelligence WHERE record_id=?", (record.record_id,)).fetchone()
            if existing:
                if existing[0] != envelope.digest:
                    raise HTTPException(409, "Record ID was already used with different contents")
                return "duplicate", None
            rows = db.execute(
                "SELECT record_id,record_json FROM network_intelligence WHERE state IN ('pending','approved')"
            ).fetchall()
            relations: list[tuple[str, str]] = []
            for other_id, other_json in rows:
                other = SignedThreatIntel.model_validate_json(other_json).record
                if other.indicator_type == record.indicator_type and _normalized_indicator(other) == _normalized_indicator(record):
                    relation = "duplicate_indicator" if other.classification == record.classification else "classification_conflict"
                    relations.append((other_id, relation))
            db.execute(
                "INSERT INTO network_intelligence VALUES (?, ?, ?, ?, 'pending', ?)",
                (record.record_id, record.publisher_id, envelope.digest, envelope.model_dump_json(by_alias=True), now),
            )
            db.execute(
                "INSERT INTO network_intelligence_audit(record_id,action,actor,reason,details_json,created_at) VALUES(?,?,?,?,?,?)",
                (record.record_id, "imported", record.publisher_id, None, "{}", now),
            )
            for related_id, relation in relations:
                db.execute("INSERT OR IGNORE INTO network_indicator_relations VALUES (?,?,?,?)", (record.record_id, related_id, relation, now))
                db.execute("INSERT OR IGNORE INTO network_indicator_relations VALUES (?,?,?,?)", (related_id, record.record_id, relation, now))
        relation_summary = relations[0][1] if relations else None
        return "stored", relation_summary

    def seed_key(self, publisher_id: str, key_id: str, public_key: Ed25519PublicKey) -> None:
        pem = _public_key_pem(public_key)
        fingerprint = _key_fingerprint(public_key)
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT fingerprint FROM network_publisher_keys WHERE publisher_id=? AND key_id=?", (publisher_id, key_id)).fetchone()
            if row and not hmac.compare_digest(row[0], fingerprint):
                raise ValueError("Configured key ID already belongs to a different public key")
            db.execute(
                "INSERT OR IGNORE INTO network_publisher_keys VALUES(?,?,?,?,'active',?,NULL)",
                (publisher_id, key_id, pem, fingerprint, datetime.now(timezone.utc).isoformat()),
            )

    def stage_key(self, publisher_id: str, key_id: str, public_key: Ed25519PublicKey) -> dict:
        pem, fingerprint = _public_key_pem(public_key), _key_fingerprint(public_key)
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT fingerprint,status FROM network_publisher_keys WHERE publisher_id=? AND key_id=?", (publisher_id, key_id)).fetchone()
            if row:
                if not hmac.compare_digest(row[0], fingerprint):
                    raise HTTPException(409, "Key ID is already associated with another fingerprint")
                return {"publisher_id": publisher_id, "key_id": key_id, "fingerprint": row[0], "status": row[1]}
            db.execute("INSERT INTO network_publisher_keys VALUES(?,?,?,?, 'pending', ?,NULL)", (publisher_id, key_id, pem, fingerprint, now))
            db.execute("INSERT INTO network_intelligence_audit(record_id,action,actor,reason,details_json,created_at) VALUES(?,?,?,?,?,?)", (f"key:{publisher_id}:{key_id}", "key_staged", "local_admin", None, json.dumps({"fingerprint": fingerprint}), now))
        return {"publisher_id": publisher_id, "key_id": key_id, "fingerprint": fingerprint, "status": "pending"}

    def publisher_key(self, publisher_id: str, key_id: str) -> tuple[Ed25519PublicKey, str, str] | None:
        with self._lock, sqlite3.connect(self.path) as db:
            row = db.execute("SELECT public_key_pem,fingerprint,status FROM network_publisher_keys WHERE publisher_id=? AND key_id=?", (publisher_id, key_id)).fetchone()
        if row is None:
            return None
        public_key = serialization.load_pem_public_key(row[0].encode("ascii"))
        if not isinstance(public_key, Ed25519PublicKey):
            return None
        return public_key, row[1], row[2]

    def list_keys(self) -> list[dict]:
        with self._lock, sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT publisher_id,key_id,fingerprint,status,added_at,revoked_at FROM network_publisher_keys ORDER BY publisher_id,key_id").fetchall()
        names = ("publisher_id", "key_id", "fingerprint", "status", "added_at", "revoked_at")
        return [dict(zip(names, row)) for row in rows]

    def key_audit(self) -> list[dict]:
        with self._lock, sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT record_id,action,actor,reason,details_json,created_at FROM network_intelligence_audit WHERE record_id LIKE 'key:%' ORDER BY id DESC LIMIT 200").fetchall()
        return [{"key_ref": row[0], "action": row[1], "actor": row[2], "reason": row[3], "details": json.loads(row[4]), "created_at": row[5]} for row in rows]

    def activate_key(self, publisher_id: str, key_id: str, expected_fingerprint: str) -> dict:
        with self._lock, sqlite3.connect(self.path) as db:
            row = db.execute("SELECT fingerprint,status FROM network_publisher_keys WHERE publisher_id=? AND key_id=?", (publisher_id,key_id)).fetchone()
            if row is None:
                raise HTTPException(404, "Publisher key not found")
            if not hmac.compare_digest(row[0], expected_fingerprint):
                raise HTTPException(409, "Public-key fingerprint confirmation does not match")
            if row[1] == "revoked":
                raise HTTPException(409, "A revoked publisher key cannot be reactivated")
            db.execute("UPDATE network_publisher_keys SET status='active' WHERE publisher_id=? AND key_id=?", (publisher_id,key_id))
            now = datetime.now(timezone.utc).isoformat()
            db.execute("INSERT INTO network_intelligence_audit(record_id,action,actor,reason,details_json,created_at) VALUES(?,?,?,?,?,?)", (f"key:{publisher_id}:{key_id}", "key_activated", "local_admin", None, json.dumps({"fingerprint": row[0]}), now))
        return {"publisher_id": publisher_id, "key_id": key_id, "fingerprint": row[0], "status": "active"}

    def revoke_key(self, publisher_id: str, key_id: str, expected_fingerprint: str) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT fingerprint,status FROM network_publisher_keys WHERE publisher_id=? AND key_id=?", (publisher_id,key_id)).fetchone()
            if row is None:
                raise HTTPException(404, "Publisher key not found")
            if not hmac.compare_digest(row[0], expected_fingerprint):
                raise HTTPException(409, "Public-key fingerprint confirmation does not match")
            if row[1] == "revoked":
                return {"publisher_id": publisher_id, "key_id": key_id, "fingerprint": row[0], "status": "revoked"}
            db.execute("UPDATE network_publisher_keys SET status='revoked',revoked_at=? WHERE publisher_id=? AND key_id=?", (now,publisher_id,key_id))
            records = db.execute("SELECT record_id,state FROM network_intelligence WHERE publisher_id=?", (publisher_id,)).fetchall()
            for record_id, prior_state in records:
                envelope_row = db.execute("SELECT record_json FROM network_intelligence WHERE record_id=?", (record_id,)).fetchone()
                if envelope_row and SignedThreatIntel.model_validate_json(envelope_row[0]).record.key_id == key_id:
                    db.execute("UPDATE network_intelligence SET state='revoked' WHERE record_id=?", (record_id,))
                    db.execute("INSERT INTO network_intelligence_audit(record_id,action,actor,reason,details_json,created_at) VALUES(?,?,?,?,?,?)", (record_id, "publisher_key_revoked", "local_admin", None, json.dumps({"prior_state": prior_state, "key_id": key_id}), now))
            db.execute("INSERT INTO network_intelligence_audit(record_id,action,actor,reason,details_json,created_at) VALUES(?,?,?,?,?,?)", (f"key:{publisher_id}:{key_id}", "key_revoked", "local_admin", None, json.dumps({"fingerprint": row[0]}), now))
        return {"publisher_id": publisher_id, "key_id": key_id, "fingerprint": row[0], "status": "revoked"}

    def seed_peer(self, peer_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("INSERT OR IGNORE INTO network_peer_registry(peer_id,enabled,status,updated_at) VALUES(?,1,'unknown',?)", (peer_id,now))

    def peer_state(self, peer_id: str) -> dict:
        with self._lock, sqlite3.connect(self.path) as db:
            row = db.execute("SELECT peer_id,enabled,status,last_seen,last_success,failure_count,last_error FROM network_peer_registry WHERE peer_id=?", (peer_id,)).fetchone()
        if row is None:
            return {"peer_id": peer_id, "enabled": True, "status": "unknown", "last_seen": None, "last_success": None, "failure_count": 0, "last_error": None}
        names = ("peer_id", "enabled", "status", "last_seen", "last_success", "failure_count", "last_error")
        state = dict(zip(names, row))
        state["enabled"] = bool(state["enabled"])
        return state

    def list_peers(self, peer_ids: list[str]) -> list[dict]:
        return [self.peer_state(peer_id) for peer_id in sorted(peer_ids)]

    def set_peer_enabled(self, peer_id: str, enabled: bool) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        status = "unknown" if enabled else "disabled"
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("INSERT OR IGNORE INTO network_peer_registry(peer_id,enabled,status,updated_at) VALUES(?,?,?,?)", (peer_id,int(enabled),status,now))
            db.execute("UPDATE network_peer_registry SET enabled=?,status=?,last_error=NULL,updated_at=? WHERE peer_id=?", (int(enabled),status,now,peer_id))
        return self.peer_state(peer_id)

    def record_peer_result(self, peer_id: str, *, success: bool, error_code: str | None = None) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        status = "healthy" if success else "unavailable"
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("INSERT OR IGNORE INTO network_peer_registry(peer_id,enabled,status,updated_at) VALUES(?,1,'unknown',?)", (peer_id,now))
            if success:
                db.execute("UPDATE network_peer_registry SET status='healthy',last_seen=?,last_success=?,last_error=NULL,updated_at=? WHERE peer_id=?", (now,now,now,peer_id))
            else:
                db.execute("UPDATE network_peer_registry SET status=?,failure_count=failure_count+1,last_error=?,updated_at=? WHERE peer_id=?", (status,error_code or "request_failed",now,peer_id))
        return self.peer_state(peer_id)

    def record_sync_attempt(self, peer_id: str, record_id: str, succeeded: bool, error_code: str | None = None) -> None:
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO network_sync_attempts(peer_id,record_id,succeeded,error_code,attempted_at) VALUES(?,?,?,?,?)", (peer_id,record_id,int(succeeded),error_code,datetime.now(timezone.utc).isoformat()))

    def sync_failure_count(self) -> int:
        with self._lock, sqlite3.connect(self.path) as db:
            return int(db.execute("SELECT COUNT(*) FROM network_sync_attempts WHERE succeeded=0").fetchone()[0])

    def transition_record(self, record_id: str, target: str, reason: str) -> dict:
        self.expire_records()
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state FROM network_intelligence WHERE record_id=?", (record_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Threat-intelligence record not found")
            if row[0] == target:
                return {"record_id": record_id, "state": target}
            if row[0] != "pending":
                raise HTTPException(409, "Only pending intelligence can be approved or rejected")
            db.execute("UPDATE network_intelligence SET state=? WHERE record_id=?", (target,record_id))
            db.execute("INSERT INTO network_intelligence_audit(record_id,action,actor,reason,details_json,created_at) VALUES(?,?,?,?,?,?)", (record_id,target,"local_admin",reason,"{}",now))
        return {"record_id": record_id, "state": target}

    def expire_records(self) -> None:
        cutoff = (datetime.now(timezone.utc) - MAX_RECORD_AGE).isoformat()
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT record_id,record_json,state FROM network_intelligence WHERE state IN ('pending','approved')").fetchall()
            for record_id, record_json, state in rows:
                created = SignedThreatIntel.model_validate_json(record_json).record.created_at.astimezone(timezone.utc).isoformat()
                if created <= cutoff:
                    db.execute("UPDATE network_intelligence SET state='expired' WHERE record_id=?", (record_id,))
                    db.execute("INSERT INTO network_intelligence_audit(record_id,action,actor,reason,details_json,created_at) VALUES(?,?,?,?,?,?)", (record_id,"expired","system","record age exceeded 30 days",json.dumps({"prior_state": state}),now))

    def audit_for_record(self, record_id: str) -> list[dict]:
        with self._lock, sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT action,actor,reason,details_json,created_at FROM network_intelligence_audit WHERE record_id=? ORDER BY id", (record_id,)).fetchall()
        names = ("action", "actor", "reason", "details_json", "created_at")
        output = []
        for row in rows:
            item = dict(zip(names,row))
            item["details"] = json.loads(item.pop("details_json"))
            output.append(item)
        return output

    def relations_for_record(self, record_id: str) -> list[dict]:
        with self._lock, sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT related_record_id,relation,created_at FROM network_indicator_relations WHERE record_id=? ORDER BY created_at", (record_id,)).fetchall()
        return [{"record_id": row[0], "relation": row[1], "created_at": row[2]} for row in rows]

    def get(self, record_id: str) -> SignedThreatIntel | None:
        with self._lock, sqlite3.connect(self.path) as db:
            row = db.execute("SELECT record_json FROM network_intelligence WHERE record_id=?", (record_id,)).fetchone()
        return SignedThreatIntel.model_validate_json(row[0]) if row else None

    def get_entry(self, record_id: str) -> tuple[SignedThreatIntel, str] | None:
        self.expire_records()
        with self._lock, sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT record_json,state FROM network_intelligence WHERE record_id=?",
                (record_id,),
            ).fetchone()
        if row is None:
            return None
        return SignedThreatIntel.model_validate_json(row[0]), row[1]

    def list(self, limit: int = 100) -> list[dict]:
        self.expire_records()
        with self._lock, sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            rows = db.execute("SELECT record_id,publisher_id,digest,record_json,state,received_at FROM network_intelligence ORDER BY received_at DESC LIMIT ?", (limit,)).fetchall()
        output = []
        for row in rows:
            envelope = SignedThreatIntel.model_validate_json(row["record_json"])
            record = envelope.record
            output.append({
                "record_id": row["record_id"], "publisher_id": row["publisher_id"],
                "key_id": record.key_id, "digest": row["digest"], "state": row["state"],
                "received_at": row["received_at"], "indicator_type": record.indicator_type,
                "indicator": record.indicator, "classification": record.classification,
                "severity": record.severity, "source_system": record.source_system,
                "observation_count": record.observation_count,
                "created_at": record.created_at.isoformat(),
                "expires_at": (record.created_at + MAX_RECORD_AGE).isoformat(),
                "confidence_score": round(min(0.95, 0.35 + 0.1 * math.log2(record.observation_count)), 4),
                "confidence_basis": "Heuristic from signed aggregate observation_count only; not a probability or truth claim.",
                "relations": self.relations_for_record(row["record_id"]),
            })
        return output

    def state_counts(self) -> dict[str, int]:
        self.expire_records()
        with self._lock, sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT state,COUNT(*) FROM network_intelligence GROUP BY state").fetchall()
        return {state: count for state, count in rows}

    def record_observation(
        self, *, fingerprint: str, candidate_key: str, indicator: str,
        indicator_type: str, classification: str, source_system: str,
        severity: str, occurred_at: datetime,
    ) -> tuple[bool, dict]:
        """Persist only a hashed local event key and a sanitized indicator aggregate."""
        timestamp = occurred_at.astimezone(timezone.utc).isoformat()
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            seen = db.execute(
                "SELECT candidate_key FROM network_observation_fingerprints WHERE fingerprint=?",
                (fingerprint,),
            ).fetchone()
            if seen is None:
                db.execute(
                    "INSERT INTO network_observation_fingerprints VALUES (?, ?)",
                    (fingerprint, candidate_key),
                )
                existing = db.execute(
                    "SELECT first_seen,last_seen,observation_count,severity FROM network_intel_candidates WHERE candidate_key=?",
                    (candidate_key,),
                ).fetchone()
                if existing is None:
                    db.execute(
                        "INSERT INTO network_intel_candidates VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, NULL)",
                        (candidate_key, indicator, indicator_type, classification,
                         source_system, severity, timestamp, timestamp),
                    )
                else:
                    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                    selected_severity = max((existing[3], severity), key=severity_rank.get)
                    db.execute(
                        "UPDATE network_intel_candidates SET first_seen=?, last_seen=?, observation_count=observation_count+1, severity=? WHERE candidate_key=?",
                        (min(existing[0], timestamp), max(existing[1], timestamp), selected_severity, candidate_key),
                    )
            else:
                candidate_key = seen[0]
            row = db.execute(
                "SELECT candidate_key,indicator,indicator_type,classification,source_system,severity,first_seen,last_seen,observation_count,published_record_id FROM network_intel_candidates WHERE candidate_key=?",
                (candidate_key,),
            ).fetchone()
        names = ("candidate_key", "indicator", "indicator_type", "classification", "source_system", "severity", "first_seen", "last_seen", "observation_count", "published_record_id")
        return seen is not None, dict(zip(names, row))

    def mark_candidate_published(self, candidate_key: str, record_id: str) -> None:
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE network_intel_candidates SET published_record_id=? WHERE candidate_key=? AND published_record_id IS NULL",
                (record_id, candidate_key),
            )


class ReplicationNode:
    def __init__(self, config: NodeConfig):
        self.config = config
        self.storage = NodeStorage(config.database_path)
        self._lock = RLock()
        self.storage.bind_node_identity(config.node_id)
        self.storage.seed_key(config.node_id, config.key_id, config.private_key.public_key())
        for publisher_id, trusted in config.trusted_publishers.items():
            self.storage.seed_key(publisher_id, trusted.key_id, trusted.public_key)
        for peer_id in config.peers:
            self.storage.seed_peer(peer_id)

    def peers(self) -> list[dict]:
        return self.storage.list_peers(list(self.config.peers))

    def set_peer_enabled(self, peer_id: str, enabled: bool) -> dict:
        if peer_id not in self.config.peers:
            raise HTTPException(404, "Peer is not configured")
        return self.storage.set_peer_enabled(peer_id, enabled)

    def stage_publisher_key(self, publisher_id: str, key_id: str, pem: str, expected_fingerprint: str) -> dict:
        if publisher_id not in self.config.trusted_publishers:
            raise HTTPException(404, "Publisher identity is not configured")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", key_id):
            raise HTTPException(422, "Invalid publisher key ID")
        try:
            public_key = serialization.load_pem_public_key(pem.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            raise HTTPException(422, "Public key PEM is invalid") from None
        if not isinstance(public_key, Ed25519PublicKey):
            raise HTTPException(422, "Publisher key must be Ed25519")
        fingerprint = _key_fingerprint(public_key)
        if not re.fullmatch(r"[0-9a-f]{64}", expected_fingerprint) or not hmac.compare_digest(fingerprint, expected_fingerprint):
            raise HTTPException(409, "Out-of-band public-key fingerprint confirmation failed")
        return self.storage.stage_key(publisher_id, key_id, public_key)

    def activate_publisher_key(self, publisher_id: str, key_id: str, expected_fingerprint: str) -> dict:
        return self.storage.activate_key(publisher_id, key_id, expected_fingerprint)

    def revoke_publisher_key(self, publisher_id: str, key_id: str, expected_fingerprint: str) -> dict:
        if publisher_id == self.config.node_id and key_id == self.config.key_id:
            raise HTTPException(409, "Rotate the local key and restart the node before revoking its active signing key")
        return self.storage.revoke_key(publisher_id, key_id, expected_fingerprint)

    def observe_event(self, observation: SecurityEventObservation) -> dict:
        """Apply explicit policy and aggregate eligible telemetry locally.

        Event IDs are one-way hashed for local replay deduplication and never
        enter a signed intelligence record or API response.
        """
        policy = self.config.publication_policy
        if not policy.enabled:
            return {"eligible": False, "reason": "publication_disabled"}
        if observation.source_system not in policy.allowed_sources:
            return {"eligible": False, "reason": "source_not_allowed"}
        classification = policy.event_type_classifications.get(observation.event_type.casefold())
        if classification is None:
            return {"eligible": False, "reason": "event_type_not_mapped"}
        rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if rank[observation.severity] < rank[policy.minimum_severity]:
            return {"eligible": False, "reason": "severity_below_threshold"}
        if observation.source_ip is None:
            return {"eligible": False, "reason": "source_ip_missing"}
        address = ip_address(str(observation.source_ip))
        if policy.require_global_ip and not address.is_global:
            return {"eligible": False, "reason": "non_public_indicator"}
        indicator_type = "ipv4" if address.version == 4 else "ipv6"
        indicator = address.compressed
        event_fingerprint = sha256(_canonical({
            "source_system": observation.source_system,
            "sensor_id": observation.sensor_id,
            "external_event_id": observation.external_event_id,
        })).hexdigest()
        candidate_key = sha256(_canonical({
            "indicator": indicator,
            "indicator_type": indicator_type,
            "classification": classification,
            "source_system": observation.source_system,
        })).hexdigest()
        with self._lock:
            duplicate, candidate = self.storage.record_observation(
                fingerprint=event_fingerprint,
                candidate_key=candidate_key,
                indicator=indicator,
                indicator_type=indicator_type,
                classification=classification,
                source_system=observation.source_system,
                severity=observation.severity,
                occurred_at=observation.occurred_at,
            )
            if candidate["observation_count"] < policy.minimum_observations:
                return {
                    "eligible": True,
                    "status": "duplicate_event" if duplicate else "below_publication_threshold",
                    "observation_count": candidate["observation_count"],
                    "required_observations": policy.minimum_observations,
                    "record_id": None,
                }
            previously_published = candidate["published_record_id"] is not None
            record_id = candidate["published_record_id"] or f"auto-{candidate_key[:40]}"
            envelope = self.storage.get(record_id)
            if envelope is None:
                record = ThreatIntelRecord(
                    record_id=record_id,
                    publisher_id=self.config.node_id,
                    key_id=self.config.key_id,
                    created_at=datetime.now(timezone.utc),
                    indicator_type=indicator_type,
                    indicator=indicator,
                    classification=classification,
                    severity=candidate["severity"],
                    source_system=candidate["source_system"],
                    first_seen=datetime.fromisoformat(candidate["first_seen"]),
                    last_seen=datetime.fromisoformat(candidate["last_seen"]),
                    observation_count=candidate["observation_count"],
                )
                envelope = self.publish(record)
            self.storage.mark_candidate_published(candidate_key, envelope.record.record_id)
            return {
                "eligible": True,
                "status": (
                    "duplicate_event" if duplicate
                    else "already_published" if previously_published
                    else "published"
                ),
                "observation_count": candidate["observation_count"],
                "required_observations": policy.minimum_observations,
                "record_id": envelope.record.record_id,
            }

    def _sign(self, record: ThreatIntelRecord) -> SignedThreatIntel:
        data = record.model_dump(mode="json", by_alias=True)
        canonical = _canonical(data)
        digest = sha256(canonical).hexdigest()
        signature = self.config.private_key.sign(SIGNING_DOMAIN + canonical + b"\0" + digest.encode("ascii"))
        return SignedThreatIntel(record=record, digest=digest, signature=base64.b64encode(signature).decode("ascii"))

    def publish(self, record: ThreatIntelRecord) -> SignedThreatIntel:
        if record.publisher_id != self.config.node_id or record.key_id != self.config.key_id:
            raise HTTPException(400, "Published record identity does not match this node")
        envelope = self._sign(record)
        self.storage.put(envelope, "local")
        return envelope

    @staticmethod
    def _verify_envelope(envelope: SignedThreatIntel, public_key: Ed25519PublicKey) -> None:
        canonical = _canonical(envelope.record.model_dump(mode="json", by_alias=True))
        digest = sha256(canonical).hexdigest()
        if not hmac.compare_digest(digest, envelope.digest):
            raise HTTPException(400, "Threat-intelligence record digest is invalid")
        try:
            signature = base64.b64decode(envelope.signature, validate=True)
            public_key.verify(signature, SIGNING_DOMAIN + canonical + b"\0" + digest.encode("ascii"))
        except (ValueError, InvalidSignature):
            raise HTTPException(400, "Threat-intelligence record signature is invalid") from None

    def import_record(self, envelope: SignedThreatIntel, authorization: str) -> Literal["stored", "duplicate"]:
        record = envelope.record
        peer = self.config.trusted_publishers.get(record.publisher_id)
        if peer is None:
            raise HTTPException(403, "Publisher is not trusted by this node")
        scheme, _, token = authorization.partition(" ")
        if scheme.casefold() != "bearer" or not hmac.compare_digest(token, peer.bearer_token):
            raise HTTPException(401, "Node authentication failed")
        trusted_key = self.storage.publisher_key(record.publisher_id, record.key_id)
        if trusted_key is None or trusted_key[2] != "active":
            raise HTTPException(403, "Publisher key is not active in this node's trust registry")
        if peer.allowed_sources is not None and record.source_system not in peer.allowed_sources:
            raise HTTPException(403, "Publisher policy does not allow this source system")
        if peer.allowed_classifications is not None and record.classification not in peer.allowed_classifications:
            raise HTTPException(403, "Publisher policy does not allow this classification")
        if record.observation_count < peer.minimum_observations:
            raise HTTPException(403, "Publisher policy requires more observations")
        self._verify_envelope(envelope, trusted_key[0])
        existing = self.storage.get(record.record_id)
        if existing is not None:
            if existing.digest != envelope.digest:
                raise HTTPException(409, "Record ID was already used with different contents")
            return "duplicate"
        now = datetime.now(timezone.utc)
        created = record.created_at.astimezone(timezone.utc)
        if created > now + timedelta(minutes=5) or created < now - MAX_RECORD_AGE:
            raise HTTPException(400, "Threat-intelligence record timestamp is outside the accepted window")
        status, _relation = self.storage.put_import(envelope)
        return status

    async def sync_peer(self, peer_id: str, record_id: str, transport: httpx.AsyncBaseTransport | None = None) -> dict:
        endpoint = self.config.peers.get(peer_id)
        if endpoint is None:
            raise HTTPException(404, "Peer is not configured")
        if not self.storage.peer_state(peer_id)["enabled"]:
            raise HTTPException(409, "Peer is disabled")
        envelope = self.storage.get(record_id)
        if envelope is None or envelope.record.publisher_id != self.config.node_id:
            raise HTTPException(404, "Locally published record not found")
        peer_reachable = False
        try:
            async with httpx.AsyncClient(transport=transport, timeout=5.0) as client:
                peer_headers = {"Authorization": f"Bearer {endpoint.bearer_token}"}
                health = await client.get(endpoint.base_url.rstrip("/") + "/health", headers=peer_headers)
                if health.status_code != 200:
                    raise httpx.HTTPStatusError("peer health check failed", request=health.request, response=health)
                health_body = health.json()
                if not isinstance(health_body, dict) or health_body.get("node_id") != peer_id:
                    raise ValueError("configured peer identity mismatch")
                peer_reachable = True
                self.storage.record_peer_result(peer_id, success=True)
                response = await client.post(
                    endpoint.base_url.rstrip("/") + "/v1/intelligence/import",
                    headers=peer_headers,
                    json=envelope.model_dump(mode="json", by_alias=True),
                )
                response.raise_for_status()
                result = response.json()
                if (
                    not isinstance(result, dict)
                    or result.get("record_id") != record_id
                    or result.get("digest") != envelope.digest
                    or result.get("status") not in {"stored", "duplicate"}
                    or result.get("state") not in {"pending", "approved", "rejected", "expired", "revoked"}
                    or result.get("signature_valid") is not True
                ):
                    raise ValueError("peer returned an invalid import acknowledgement")
            self.storage.record_peer_result(peer_id, success=True)
            self.storage.record_sync_attempt(peer_id, record_id, True)
            return result
        except (httpx.HTTPError, ValueError):
            self.storage.record_sync_attempt(peer_id, record_id, False, "exchange_rejected" if peer_reachable else "peer_unavailable")
            if peer_reachable:
                # Preserve the last known connection health while incrementing
                # failures for the rejected record exchange.
                self.storage.record_peer_result(peer_id, success=False, error_code="exchange_rejected")
                with self.storage._lock, sqlite3.connect(self.storage.path) as db:
                    db.execute("UPDATE network_peer_registry SET status='degraded' WHERE peer_id=?", (peer_id,))
                raise HTTPException(502, "Peer is reachable but the exchange failed or was rejected") from None
            self.storage.record_peer_result(peer_id, success=False, error_code="peer_unavailable")
            raise HTTPException(502, "Configured peer is unavailable") from None

    async def check_peer(self, peer_id: str, transport: httpx.AsyncBaseTransport | None = None) -> dict:
        endpoint = self.config.peers.get(peer_id)
        if endpoint is None:
            raise HTTPException(404, "Peer is not configured")
        state = self.storage.peer_state(peer_id)
        if not state["enabled"]:
            state["status"] = "disabled"
            return {"peer_id": peer_id, **state, "remote_node_id": None}
        try:
            async with httpx.AsyncClient(transport=transport, timeout=5.0) as client:
                response = await client.get(
                    endpoint.base_url.rstrip("/") + "/health",
                    headers={"Authorization": f"Bearer {endpoint.bearer_token}"},
                )
                response.raise_for_status()
                info = response.json()
                if not isinstance(info, dict) or info.get("node_id") != peer_id:
                    raise ValueError("configured peer identity mismatch")
            state = self.storage.record_peer_result(peer_id, success=True)
            return {**state, "remote_node_id": info.get("node_id")}
        except (httpx.HTTPError, ValueError):
            state = self.storage.record_peer_result(peer_id, success=False, error_code="peer_unavailable")
            return {**state, "remote_node_id": None}

    def dashboard_summary(self) -> dict:
        counts = self.storage.state_counts()
        return {
            "node": {"node_id": self.config.node_id, "status": "healthy"},
            "peers": self.peers(),
            "intelligence": {
                "state_counts": counts,
                "pending_count": counts.get("pending", 0),
                "approved_count": counts.get("approved", 0),
                "rejected_count": counts.get("rejected", 0),
                "expired_count": counts.get("expired", 0),
                "revoked_count": counts.get("revoked", 0),
                "records": self.storage.list(50),
            },
            "sync_failures": self.storage.sync_failure_count(),
            "confidence_definition": "min(0.95, 0.35 + 0.10 * log2(signed observation_count)); heuristic evidence score, not a probability.",
        }

    def health(self) -> dict:
        return {"status": "healthy", "node_id": self.config.node_id}

    def authenticate_peer(self, authorization: str) -> None:
        scheme, _, token = authorization.partition(" ")
        valid = False
        if scheme.casefold() == "bearer":
            for peer in self.config.trusted_publishers.values():
                valid = hmac.compare_digest(token, peer.bearer_token) or valid
        if not valid:
            raise HTTPException(401, "Node authentication failed")


async def _read_bounded_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(413, "Threat-intelligence request is too large")
    return bytes(body)


def create_node_app(node: ReplicationNode) -> FastAPI:
    """Create an independently configured node API; no DB is opened on import."""
    app = FastAPI(title=f"Honeypot Network Node {node.config.node_id}", version="1.0")
    app.state.replication_node = node
    if node.config.dashboard_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(node.config.dashboard_origins),
            allow_credentials=False,
            allow_methods=["GET"],
            allow_headers=["Authorization", "Accept"],
        )

    def require_admin(authorization: str | None) -> None:
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.casefold() != "bearer" or not hmac.compare_digest(token, node.config.admin_token):
            raise HTTPException(401, "Node administrator authentication required")

    def require_dashboard(authorization: str | None) -> None:
        expected = node.config.dashboard_token or node.config.admin_token
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.casefold() != "bearer" or not hmac.compare_digest(token, expected):
            raise HTTPException(401, "Node dashboard read token required")

    @app.get("/health")
    async def health(authorization: str | None = Header(default=None)):
        node.authenticate_peer(authorization or "")
        return node.health()

    @app.post("/v1/intelligence/publish", status_code=201)
    async def publish(request: Request, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        raw = await _read_bounded_body(request)
        try:
            record = ThreatIntelRecord.model_validate_json(raw)
        except ValidationError:
            raise HTTPException(422, "Threat-intelligence record is invalid") from None
        return node.publish(record).model_dump(mode="json", by_alias=True)

    @app.post("/v1/intelligence/import")
    async def import_record(request: Request, authorization: str | None = Header(default=None)):
        raw = await _read_bounded_body(request)
        try:
            envelope = SignedThreatIntel.model_validate_json(raw)
        except ValidationError:
            raise HTTPException(422, "Signed threat-intelligence record is invalid") from None
        state = node.import_record(envelope, authorization or "")
        entry = node.storage.get_entry(envelope.record.record_id)
        return {
            "record_id": envelope.record.record_id,
            "digest": envelope.digest,
            "status": state,
            "state": entry[1] if entry is not None else "unknown",
            "signature_valid": True,
        }

    @app.get("/v1/dashboard/summary")
    async def dashboard_summary(authorization: str | None = Header(default=None)):
        require_dashboard(authorization)
        return node.dashboard_summary()

    @app.post("/v1/intelligence/observe")
    async def observe(request: Request, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        raw = await _read_bounded_body(request)
        try:
            observation = SecurityEventObservation.model_validate_json(raw)
        except ValidationError:
            raise HTTPException(422, "Security event observation is invalid") from None
        return node.observe_event(observation)

    @app.get("/v1/intelligence")
    async def list_intelligence(authorization: str | None = Header(default=None), limit: int = 100):
        require_admin(authorization)
        if not 1 <= limit <= 500:
            raise HTTPException(422, "limit must be between 1 and 500")
        return {"node_id": node.config.node_id, "records": node.storage.list(limit)}

    @app.get("/v1/intelligence/{record_id}")
    async def get_intelligence(record_id: str, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        entry = node.storage.get_entry(record_id)
        if entry is None:
            raise HTTPException(404, "Threat-intelligence record not found")
        envelope, state = entry
        key_entry = node.storage.publisher_key(envelope.record.publisher_id, envelope.record.key_id)
        if key_entry is None:
            raise HTTPException(403, "Stored publisher key is not in the local registry")
        public_key, _fingerprint, key_status = key_entry
        node._verify_envelope(envelope, public_key)
        return {
            **envelope.model_dump(mode="json", by_alias=True),
            "state": state,
            "signature_valid": True,
            "publisher_trust_status": key_status,
            "expires_at": (envelope.record.created_at + MAX_RECORD_AGE).isoformat(),
            "confidence_score": round(min(0.95, 0.35 + 0.1 * math.log2(envelope.record.observation_count)), 4),
            "confidence_basis": "Heuristic from signed aggregate observation_count only; not a probability or truth claim.",
            "relations": node.storage.relations_for_record(record_id),
            "audit": node.storage.audit_for_record(record_id),
        }

    @app.post("/v1/intelligence/{record_id}/approve")
    async def approve_intelligence(record_id: str, request: Request, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        raw = await _read_bounded_body(request)
        try:
            decision = DecisionRequest.model_validate_json(raw)
        except ValidationError:
            raise HTTPException(422, "Approval reason is invalid") from None
        return node.storage.transition_record(record_id, "approved", decision.reason)

    @app.post("/v1/intelligence/{record_id}/reject")
    async def reject_intelligence(record_id: str, request: Request, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        raw = await _read_bounded_body(request)
        try:
            decision = DecisionRequest.model_validate_json(raw)
        except ValidationError:
            raise HTTPException(422, "Rejection reason is invalid") from None
        return node.storage.transition_record(record_id, "rejected", decision.reason)

    @app.get("/v1/intelligence/{record_id}/audit")
    async def intelligence_audit(record_id: str, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        if node.storage.get(record_id) is None:
            raise HTTPException(404, "Threat-intelligence record not found")
        return {"record_id": record_id, "audit": node.storage.audit_for_record(record_id)}

    @app.get("/v1/publishers")
    async def list_publishers(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"publishers": node.storage.list_keys()}

    @app.get("/v1/publishers/audit")
    async def publisher_key_audit(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"events": node.storage.key_audit()}

    @app.post("/v1/publishers/{publisher_id}/keys", status_code=201)
    async def stage_publisher_key(publisher_id: str, request: Request, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        raw = await _read_bounded_body(request)
        try:
            payload = PublisherKeyStageRequest.model_validate_json(raw)
        except ValidationError:
            raise HTTPException(422, "Publisher key request is invalid") from None
        return node.stage_publisher_key(publisher_id, payload.key_id, payload.public_key_pem, payload.expected_fingerprint)

    @app.post("/v1/publishers/{publisher_id}/keys/{key_id}/activate")
    async def activate_publisher_key(publisher_id: str, key_id: str, request: Request, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        try:
            payload = FingerprintConfirmation.model_validate_json(await _read_bounded_body(request))
        except ValidationError:
            raise HTTPException(422, "Fingerprint confirmation is invalid") from None
        return node.activate_publisher_key(publisher_id, key_id, payload.expected_fingerprint)

    @app.post("/v1/publishers/{publisher_id}/keys/{key_id}/revoke")
    async def revoke_publisher_key(publisher_id: str, key_id: str, request: Request, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        try:
            payload = FingerprintConfirmation.model_validate_json(await _read_bounded_body(request))
        except ValidationError:
            raise HTTPException(422, "Fingerprint confirmation is invalid") from None
        return node.revoke_publisher_key(publisher_id, key_id, payload.expected_fingerprint)

    @app.get("/v1/peers")
    async def list_peers(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"node_id": node.config.node_id, "peers": node.peers()}

    @app.post("/v1/peers/{peer_id}/enable")
    async def enable_peer(peer_id: str, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return node.set_peer_enabled(peer_id, True)

    @app.post("/v1/peers/{peer_id}/disable")
    async def disable_peer(peer_id: str, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return node.set_peer_enabled(peer_id, False)

    @app.post("/v1/peers/{peer_id}/sync/{record_id}")
    async def sync(peer_id: str, record_id: str, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return await node.sync_peer(peer_id, record_id)

    @app.get("/v1/peers/{peer_id}/health")
    async def peer_health(peer_id: str, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return await node.check_peer(peer_id)

    return app


def load_node_app_from_environment() -> FastAPI:
    """Load explicit operator configuration from HONEYPOT_NODE_CONFIG JSON."""
    path = os.getenv("HONEYPOT_NODE_CONFIG", "")
    if not path:
        raise RuntimeError("HONEYPOT_NODE_CONFIG must name a node configuration JSON file")
    config_path = Path(path)
    config_data = json.loads(config_path.read_text(encoding="utf-8"))
    private_pem = Path(config_data["private_key_file"]).read_bytes()
    password_env = config_data.get("private_key_password_env")
    password = os.getenv(password_env).encode("utf-8") if password_env and os.getenv(password_env) else None
    if password_env and password is None:
        raise ValueError(f"Environment variable {password_env} is required to unlock the node key")
    private_key = serialization.load_pem_private_key(private_pem, password=password)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Node key file must contain an Ed25519 private key")

    def secret(env_name: str) -> str:
        value = os.getenv(env_name, "")
        if len(value) < 32:
            raise ValueError(f"Environment variable {env_name} must contain at least 32 characters")
        return value

    trusted = {}
    for peer_id, entry in config_data.get("trusted_publishers", {}).items():
        public = serialization.load_pem_public_key(Path(entry["public_key_file"]).read_bytes())
        if not isinstance(public, Ed25519PublicKey):
            raise ValueError("Trusted peer key must be Ed25519")
        trusted[peer_id] = TrustedPeer(
            entry["key_id"], public, secret(entry["incoming_token_env"]),
            frozenset(entry["allowed_sources"]) if "allowed_sources" in entry else None,
            frozenset(entry["allowed_classifications"]) if "allowed_classifications" in entry else None,
            int(entry.get("minimum_observations", 1)),
        )
    peers = {
        peer_id: PeerEndpoint(entry["base_url"], secret(entry["outgoing_token_env"]))
        for peer_id, entry in config_data.get("peers", {}).items()
    }
    config = NodeConfig(
        node_id=config_data["node_id"], key_id=config_data["key_id"],
        private_key=private_key, database_path=config_data["database_path"],
        admin_token=secret(config_data["admin_token_env"]),
        trusted_publishers=trusted, peers=peers,
        publication_policy=ThreatPublicationPolicy.model_validate(
            config_data.get("publication_policy", {})
        ),
        dashboard_token=(secret(config_data["dashboard_token_env"]) if config_data.get("dashboard_token_env") else None),
        dashboard_origins=tuple(config_data.get("dashboard_origins", ())),
    )
    return create_node_app(ReplicationNode(config))
