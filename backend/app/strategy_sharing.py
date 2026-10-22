"""Locally verified, signed strategy packages (v1; no network transport)."""

from __future__ import annotations

import base64
import gc
import json
import os
import sqlite3
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock
from typing import Literal, TYPE_CHECKING
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError

from app.evaluation.models import EvaluationSummary
from app.honeypot.bundles import BundleConsistencyValidator
from app.intelligence.fingerprint_schema import (
    ShareableFingerprintExportV1,
    export_digest,
)

if TYPE_CHECKING:
    from app.honeypot.bundles import SyntheticDecoyBundle
    from app.intelligence.fingerprint_schema import ShareableFingerprintExportV1


SHARING_SCHEMA = "decentralized_honeypot.strategy_share"
SHARING_VERSION = 1
SIGNING_DOMAIN = b"decentralized-honeypot:strategy-sharing:v1\0"
STRATEGIES = Literal["neutral_response", "file_decoy", "credential_decoy", "database_decoy", "expanded_decoy_path"]
ASSET_TYPES = Literal["identities", "database_records", "files", "api_resources"]
RELATION_TYPES = Literal["has_identity", "has_database_record", "has_file", "exposed_as_api_resource"]


class SharedBundleTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_version: Literal[1] = 1
    strategy: STRATEGIES
    asset_types: list[ASSET_TYPES] = Field(max_length=4)
    relationship_types: list[RELATION_TYPES] = Field(max_length=4)
    synthetic_only: Literal[True] = True

    def validate_consistency(self) -> None:
        if len(set(self.asset_types)) != len(self.asset_types) or len(set(self.relationship_types)) != len(self.relationship_types):
            raise ValueError("Bundle template categories must be unique")
        expected = {
            "identities": "has_identity", "database_records": "has_database_record",
            "files": "has_file", "api_resources": "exposed_as_api_resource",
        }
        if set(self.relationship_types) != {expected[t] for t in self.asset_types}:
            raise ValueError("Bundle template relationships do not match asset types")
        required = {
            "neutral_response": set(), "file_decoy": {"files"},
            "credential_decoy": {"identities"}, "database_decoy": {"database_records"},
            "expanded_decoy_path": {"identities", "database_records", "files"},
        }[self.strategy]
        if not required.issubset(self.asset_types):
            raise ValueError("Bundle template is incomplete for its strategy")

    @classmethod
    def from_bundle(cls, bundle: SyntheticDecoyBundle) -> "SharedBundleTemplate":
        assets = []
        for field, name in (("identities", "identities"), ("database_records", "database_records"), ("files", "files"), ("api_resources", "api_resources")):
            if getattr(bundle, field):
                assets.append(name)
        links = {"identities": "has_identity", "database_records": "has_database_record", "files": "has_file", "api_resources": "exposed_as_api_resource"}
        model = cls(strategy=bundle.selected_strategy, asset_types=assets, relationship_types=[links[x] for x in assets])
        model.validate_consistency()
        return model


class StrategyShareRecord(BaseModel):
    """Strict public record. v1 imports reject unknown fields and versions."""
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_name: Literal[SHARING_SCHEMA] = SHARING_SCHEMA
    schema_version: Literal[1] = SHARING_VERSION
    record_id: StrictStr = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    organization_id: StrictStr = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    key_id: StrictStr = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    digest_algorithm: Literal["SHA-256"] = "SHA-256"
    signature_algorithm: Literal["Ed25519"] = "Ed25519"
    strategy: STRATEGIES
    fingerprint: ShareableFingerprintExportV1
    fingerprint_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    bundle_template: SharedBundleTemplate
    bundle_template_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    signature: StrictStr = Field(min_length=1, max_length=256)


class ImportResponse(BaseModel):
    record_id: str
    state: Literal["pending", "evaluated", "active", "evaluation_failed"]
    digest: str
    signature_valid: bool
    bundle_valid: bool
    evaluation: EvaluationSummary | None = None
    evaluation_passed: bool | None = None


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def record_digest_fields(record: StrategyShareRecord | dict) -> dict:
    data = record.model_dump(mode="json") if isinstance(record, StrategyShareRecord) else dict(record)
    data.pop("digest", None)
    data.pop("signature", None)
    return data


def canonical_record_bytes(record: StrategyShareRecord | dict) -> bytes:
    return _canonical(record_digest_fields(record))


def calculate_record_digest(record: StrategyShareRecord | dict) -> str:
    return sha256(canonical_record_bytes(record)).hexdigest()


def signing_payload(record: StrategyShareRecord | dict) -> bytes:
    data = record.model_dump(mode="json") if isinstance(record, StrategyShareRecord) else dict(record)
    return SIGNING_DOMAIN + canonical_record_bytes(data) + b"\0" + str(data["digest"]).encode("ascii")


def parse_trusted_keys(raw: str) -> dict[str, tuple[str, Ed25519PublicKey]]:
    """Parse operator-provisioned trust; this never trusts record-supplied keys."""
    try:
        config = json.loads(raw)
        if not isinstance(config, dict):
            raise ValueError("Trust configuration must be an object")
        trusted: dict[str, tuple[str, Ed25519PublicKey]] = {}
        for key_id, entry in config.items():
            if not isinstance(key_id, str) or not isinstance(entry, dict):
                raise ValueError("Each trusted key requires an ID and configuration")
            organization_id = entry["organization_id"]
            pem = entry["public_key"]
            if not isinstance(organization_id, str) or not organization_id:
                raise ValueError("Trusted key organization ID is invalid")
            if not isinstance(pem, str):
                raise ValueError("Trusted public key must be PEM text")
            public = serialization.load_pem_public_key(pem.encode("utf-8"))
            if not isinstance(public, Ed25519PublicKey):
                raise ValueError("Trusted keys must use Ed25519")
            trusted[key_id] = (organization_id, public)
        return trusted
    except Exception as exc:
        raise ValueError("HONEYPOT_STRATEGY_SHARING_TRUSTED_KEYS is invalid") from exc


class StrategySharingStorage:
    """Isolated additive store for imported packages and their audit state."""
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS strategy_imports (record_id TEXT PRIMARY KEY, digest TEXT NOT NULL, record_json TEXT NOT NULL, state TEXT NOT NULL, audit_json TEXT NOT NULL, evaluation_json TEXT, evaluation_passed INTEGER)")

    def add_pending(self, record: StrategyShareRecord) -> None:
        with self._lock, sqlite3.connect(self.path) as db:
            try:
                timestamp = datetime.now(timezone.utc).isoformat()
                audit = [
                    {"event": name, "at": timestamp}
                    for name in (
                        "imported", "digest_verified", "signature_verified",
                        "bundle_validated",
                    )
                ]
                db.execute(
                    "INSERT INTO strategy_imports VALUES (?, ?, ?, 'pending', ?, NULL, NULL)",
                    (record.record_id, record.digest, record.model_dump_json(), json.dumps(audit)),
                )
            except sqlite3.IntegrityError as exc:
                raise HTTPException(409, "Strategy record ID has already been imported") from exc

    def get(self, record_id: str) -> dict | None:
        with self._lock, sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM strategy_imports WHERE record_id=?", (record_id,)).fetchone()
        if row is None:
            return None
        return dict(row)

    def set_evaluation(self, record_id: str, result: EvaluationSummary, passed: bool) -> None:
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state, audit_json FROM strategy_imports WHERE record_id=?", (record_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Imported strategy not found")
            if row[0] == "active":
                raise HTTPException(409, "Active strategy cannot be reevaluated")
            audit = json.loads(row[1])
            audit.append({"event": "evaluation_completed" if passed else "evaluation_failed", "at": datetime.now(timezone.utc).isoformat()})
            db.execute("UPDATE strategy_imports SET state=?, audit_json=?, evaluation_json=?, evaluation_passed=? WHERE record_id=?", ("evaluated" if passed else "evaluation_failed", json.dumps(audit), result.model_dump_json(), int(passed), record_id))

    def set_evaluation_failure(self, record_id: str) -> None:
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state, audit_json FROM strategy_imports WHERE record_id=?", (record_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Imported strategy not found")
            if row[0] == "active":
                raise HTTPException(409, "Active strategy cannot be reevaluated")
            audit = json.loads(row[1])
            audit.append({"event": "evaluation_execution_error", "at": datetime.now(timezone.utc).isoformat()})
            db.execute("UPDATE strategy_imports SET state='evaluation_failed', audit_json=?, evaluation_json=NULL, evaluation_passed=0 WHERE record_id=?", (json.dumps(audit), record_id))

    def activate(self, record_id: str, verify_record) -> None:
        with self._lock, sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state, evaluation_passed, audit_json, record_json FROM strategy_imports WHERE record_id=?", (record_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Imported strategy not found")
            if row[0] != "evaluated" or row[1] != 1:
                raise HTTPException(409, "Strategy requires a passing local evaluation before activation")
            verify_record(StrategyShareRecord.model_validate_json(row[3]))
            audit = json.loads(row[2])
            audit.append({"event": "activated", "at": datetime.now(timezone.utc).isoformat()})
            db.execute("UPDATE strategy_imports SET state='active', audit_json=? WHERE record_id=?", (json.dumps(audit), record_id))


class StrategySharingService:
    def __init__(self, storage: StrategySharingStorage, trusted_keys: dict[str, tuple[str, Ed25519PublicKey]], signer: Ed25519PrivateKey | None = None, signer_organization: str | None = None, evaluation_runner=None):
        self.storage, self.trusted_keys, self.signer = storage, dict(trusted_keys), signer
        self.signer_organization = signer_organization
        self.evaluation_runner = evaluation_runner or self._isolated_evaluate

    def create_record(self, organization_id: str, key_id: str, strategy: str, fingerprint: ShareableFingerprintExportV1, bundle: SyntheticDecoyBundle) -> StrategyShareRecord:
        if self.signer is None or organization_id != self.signer_organization:
            raise HTTPException(503, "A dedicated strategy-sharing signing key and organization ID are required")
        trusted = self.trusted_keys.get(key_id)
        if trusted is None or trusted[0] != organization_id or trusted[1].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) != self.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw):
            raise HTTPException(503, "The configured signer must match an explicitly trusted organization key")
        bundle_validation = BundleConsistencyValidator().validate(bundle)
        if not bundle_validation.valid:
            raise HTTPException(422, "Source bundle failed consistency validation")
        template = SharedBundleTemplate.from_bundle(bundle)
        if template.strategy != strategy: raise HTTPException(422, "Bundle strategy does not match requested strategy")
        template_json = _canonical(template.model_dump(mode="json"))
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        draft = {"schema_name": SHARING_SCHEMA, "schema_version": 1, "record_id": uuid4().hex, "organization_id": organization_id, "key_id": key_id, "digest_algorithm": "SHA-256", "signature_algorithm": "Ed25519", "strategy": strategy, "fingerprint": fingerprint.model_dump(mode="json"), "fingerprint_sha256": export_digest(fingerprint), "bundle_template": template.model_dump(mode="json"), "bundle_template_sha256": sha256(template_json).hexdigest(), "created_at": created_at}
        digest = calculate_record_digest(draft)
        signature = base64.b64encode(self.signer.sign(SIGNING_DOMAIN + _canonical(draft) + b"\0" + digest.encode("ascii"))).decode("ascii")
        return StrategyShareRecord.model_validate_json(_canonical({**draft, "digest": digest, "signature": signature}))

    def import_record(self, payload: dict) -> ImportResponse:
        if not isinstance(payload, dict):
            raise HTTPException(422, "Invalid strategy-sharing schema")
        if payload.get("schema_version") != SHARING_VERSION:
            raise HTTPException(422, "Unsupported strategy-sharing schema version")
        try:
            record = StrategyShareRecord.model_validate_json(_canonical(payload))
        except (ValidationError, TypeError, ValueError) as exc:
            raise HTTPException(422, "Invalid strategy-sharing schema") from exc
        self._verify_record(record)
        self.storage.add_pending(record)
        return ImportResponse(record_id=record.record_id, state="pending", digest=record.digest, signature_valid=True, bundle_valid=True)

    def _verify_record(self, record: StrategyShareRecord) -> None:
        if record.fingerprint_sha256 != export_digest(record.fingerprint): raise HTTPException(422, "Fingerprint digest mismatch")
        if record.bundle_template_sha256 != sha256(_canonical(record.bundle_template.model_dump(mode="json"))).hexdigest(): raise HTTPException(422, "Bundle template digest mismatch")
        if record.digest != calculate_record_digest(record): raise HTTPException(422, "Strategy record digest mismatch")
        try: record.bundle_template.validate_consistency()
        except ValueError as exc: raise HTTPException(422, f"Invalid sanitized bundle template: {exc}") from exc
        if record.bundle_template.strategy != record.strategy: raise HTTPException(422, "Bundle template strategy mismatch")
        trusted = self.trusted_keys.get(record.key_id)
        if trusted is None: raise HTTPException(403, "Signing key is not trusted")
        if trusted[0] != record.organization_id: raise HTTPException(403, "Signing key is not trusted for this organization")
        try:
            signature = base64.b64decode(record.signature, validate=True)
            trusted[1].verify(signature, signing_payload(record))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise HTTPException(422, "Strategy record signature is invalid") from exc

    def evaluate(self, record_id: str) -> ImportResponse:
        stored = self.storage.get(record_id)
        if stored is None: raise HTTPException(404, "Imported strategy not found")
        if stored["state"] == "active": raise HTTPException(409, "Active strategy cannot be reevaluated")
        record = StrategyShareRecord.model_validate_json(stored["record_json"])
        self._verify_record(record)
        try:
            result = self.evaluation_runner(record)
            target_count = result.overall.strategy_selection_counts.get(record.strategy, 0)
            passed = result.status == "completed" and result.overall.failed_runs == 0 and target_count > 0
        except Exception as exc:
            # A real result object is required for audit; evaluation exceptions are not converted into fabricated metrics.
            self.storage.set_evaluation_failure(record_id)
            raise HTTPException(500, "Local strategy evaluation failed") from None
        self.storage.set_evaluation(record_id, result, passed)
        return self.get(record_id)

    def activate(self, record_id: str) -> ImportResponse:
        self.storage.activate(record_id, self._verify_record)
        return self.get(record_id)

    def get(self, record_id: str) -> ImportResponse:
        row = self.storage.get(record_id)
        if row is None: raise HTTPException(404, "Imported strategy not found")
        result = EvaluationSummary.model_validate_json(row["evaluation_json"]) if row["evaluation_json"] else None
        if result is not None:
            # Keep measured aggregate metrics, but do not expose per-run actor,
            # event, decoy, or bundle identifiers through this API response.
            result = result.model_copy(update={"runs": []})
        return ImportResponse(record_id=record_id, state=row["state"], digest=row["digest"], signature_valid=True, bundle_valid=True, evaluation=result, evaluation_passed=bool(row["evaluation_passed"]) if row["evaluation_passed"] is not None else None)

    @staticmethod
    def _isolated_evaluate(record: StrategyShareRecord) -> EvaluationSummary:
        """Run the existing evaluation service using only temporary stores."""
        with TemporaryDirectory(prefix="honeypot-strategy-eval-") as temp:
            result = StrategySharingService._run_isolated_evaluation(Path(temp))
            gc.collect()
            return result

    @staticmethod
    def _run_isolated_evaluation(root: Path) -> EvaluationSummary:
        # Import application services only when an evaluation is requested.
        # Several existing modules initialize their own persistent stores at
        # import time, so delaying these imports also keeps test collection
        # from opening those stores through this module.
        from app.adaptation.service import AdaptiveHoneypotService
        from app.adaptation.storage import SQLiteAdaptationStorage
        from app.evaluation.models import EvaluationRequest
        from app.evaluation.service import EvaluationService
        from app.evaluation.storage import SQLiteEvaluationStorage
        from app.events.store import EventStore
        from app.honeypot.bundle_generator import BehaviorConditionedBundleGenerator
        from app.honeypot.generator import BehaviorConditionedDecoyGenerator
        from app.honeypot.interaction import InteractionWorkflow
        from app.honeypot.registry import GeneratedDecoyRegistry
        from app.honeypot.service import HoneypotService
        from app.intelligence.service import BehavioralIntelligenceService
        from app.ledger.service import EventLedger
        from app.ledger.storage import SQLiteLedgerStorage
        from app.simulation.service import AttackSimulationService
        from app.simulation.storage import SQLiteSimulationStorage

        events = EventStore()
        ledger = EventLedger(SQLiteLedgerStorage(root / "ledger.sqlite3"))
        registry = GeneratedDecoyRegistry(root / "decoys.sqlite3")
        history = SQLiteAdaptationStorage(root / "adaptation.sqlite3")
        adaptation = AdaptiveHoneypotService(events, history)
        intelligence = BehavioralIntelligenceService(events)
        honeypot = HoneypotService(events, ledger, registry)
        workflow = InteractionWorkflow(honeypot, intelligence, adaptation, BehaviorConditionedDecoyGenerator(), registry, BehaviorConditionedBundleGenerator(), BundleConsistencyValidator())
        simulations = AttackSimulationService(workflow, honeypot, events, intelligence, adaptation, registry, SQLiteSimulationStorage(root / "simulations.sqlite3"))
        evaluation = EvaluationService(simulations, SQLiteEvaluationStorage(root / "evaluations.sqlite3"))
        return evaluation.run(EvaluationRequest(repetitions=1, policy_modes=["behavior_conditioned"]))


def load_runtime_service() -> StrategySharingService:
    """Load explicit trust configuration; imported keys are never self-trusted."""
    raw = os.getenv("HONEYPOT_STRATEGY_SHARING_TRUSTED_KEYS", "{}")
    try:
        trusted = parse_trusted_keys(raw)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    signer = None
    signer_path = os.getenv("HONEYPOT_STRATEGY_SHARING_PRIVATE_KEY_PATH")
    organization = os.getenv("HONEYPOT_STRATEGY_SHARING_ORGANIZATION_ID")
    if signer_path:
        key = serialization.load_pem_private_key(Path(signer_path).read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey): raise RuntimeError("Strategy-sharing key must be Ed25519")
        signer = key
    return StrategySharingService(StrategySharingStorage(Path(__file__).resolve().parents[2] / "data" / "strategy_sharing.sqlite3"), trusted, signer, organization)


class _LazyStrategySharingService:
    """Defer directory/database creation until a sharing API is actually used."""
    def __init__(self) -> None:
        self._service: StrategySharingService | None = None
        self._lock = Lock()

    def _get_service(self) -> StrategySharingService:
        if self._service is None:
            with self._lock:
                if self._service is None:
                    self._service = load_runtime_service()
        return self._service

    def __getattr__(self, name: str):
        return getattr(self._get_service(), name)


strategy_sharing_service = _LazyStrategySharingService()
