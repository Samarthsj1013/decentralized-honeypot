"""Stable fingerprint contract, safe sharing projection, and ML vector adapter.

This module deliberately adapts the operational v1 fingerprint instead of
changing its fields or semantics. Hashes produced here identify canonical
content; they do not anonymize it.
"""

from collections import Counter
from datetime import datetime
from hashlib import sha256
import json
from math import isfinite
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)

from app.intelligence.service import BehavioralFingerprint


FINGERPRINT_SCHEMA_NAME = "decentralized_honeypot.behavioral_fingerprint"
FINGERPRINT_SCHEMA_VERSION = 1
VECTOR_SCHEMA_NAME = "decentralized_honeypot.behavioral_vector"
VECTOR_SCHEMA_VERSION = 1
MAX_EVENT_COUNT = 100_000
FrequencyCount = Annotated[StrictInt, Field(ge=0, le=MAX_EVENT_COUNT)]

ACTION_CATEGORIES = ("view", "read", "attempt_login", "query", "other")
DECOY_CATEGORIES = ("file", "credential", "database_record", "other")
RISK_CATEGORIES = ("low", "medium", "high")

# Values are exported from this fixed sequence. Feature order is an API contract.
VECTOR_FEATURE_ORDER = (
    "event_count",
    "unique_decoys_accessed",
    "unique_actions",
    "action_frequency.view",
    "action_frequency.read",
    "action_frequency.attempt_login",
    "action_frequency.query",
    "action_frequency.other",
    "decoy_type_frequencies_available",
    "decoy_frequency.file",
    "decoy_frequency.credential",
    "decoy_frequency.database_record",
    "decoy_frequency.other",
    "credential_probing",
    "database_probing",
    "file_probing",
    "repeated_access",
    "timing_reliable",
    "elapsed_seconds.value",
    "elapsed_seconds.missing",
    "interactions_per_minute.value",
    "interactions_per_minute.missing",
    "risk_score",
    "risk_level.low",
    "risk_level.medium",
    "risk_level.high",
)


class FingerprintContractV1(BaseModel):
    """Validated internal v1 representation; not intended for sharing as-is."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    schema_name: Literal[FINGERPRINT_SCHEMA_NAME]
    schema_version: Literal[1]
    fingerprint_version: Literal[1]
    actor_id: StrictStr = Field(min_length=1, max_length=64)
    event_count: StrictInt = Field(ge=0, le=MAX_EVENT_COUNT)
    unique_decoys_accessed: StrictInt = Field(ge=0, le=MAX_EVENT_COUNT)
    unique_actions: StrictInt = Field(ge=0, le=MAX_EVENT_COUNT)
    action_sequence: list[StrictStr] = Field(max_length=MAX_EVENT_COUNT)
    action_frequencies: dict[StrictStr, FrequencyCount] = Field(default_factory=dict)
    decoy_types_accessed: list[StrictStr] = Field(max_length=1000)
    decoy_type_frequencies: dict[StrictStr, FrequencyCount] = Field(default_factory=dict)
    credential_probing: StrictBool
    database_probing: StrictBool
    file_probing: StrictBool
    repeated_access: StrictBool
    elapsed_seconds: StrictFloat | None = Field(default=None, ge=0, le=1_000_000_000, allow_inf_nan=False)
    interactions_per_minute: StrictFloat | None = Field(default=None, ge=0, le=1_000_000, allow_inf_nan=False)
    timing_reliable: StrictBool
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    risk_score: StrictInt = Field(ge=0, le=100)
    risk_level: Literal["low", "medium", "high"]
    reasons: list[StrictStr] = Field(default_factory=list, max_length=1000)
    assessment_type: Literal["heuristic_baseline"] = "heuristic_baseline"

    @model_validator(mode="after")
    def validate_consistency(self):
        if self.unique_actions > self.event_count:
            raise ValueError("unique_actions cannot exceed event_count")
        if self.unique_decoys_accessed > self.event_count:
            raise ValueError("unique_decoys_accessed cannot exceed event_count")
        if self.unique_actions != len(set(self.action_sequence)):
            raise ValueError("unique_actions must match action_sequence")
        if len(self.action_sequence) != self.event_count:
            raise ValueError("action_sequence length must equal event_count")
        for category in [*self.action_sequence, *self.decoy_types_accessed,
                         *self.action_frequencies, *self.decoy_type_frequencies]:
            if not category.strip() or len(category) > 80:
                raise ValueError("categorical values must be non-empty and at most 80 characters")
        if any(count < 0 for count in (*self.action_frequencies.values(),
                                       *self.decoy_type_frequencies.values())):
            raise ValueError("feature frequencies cannot be negative")

        if self.action_frequencies:
            if sum(self.action_frequencies.values()) != self.event_count:
                raise ValueError("action frequencies must sum to event_count")
            if any(count == 0 for count in self.action_frequencies.values()):
                raise ValueError("observed action frequency values must be positive")
            if _normalized_counts(self.action_frequencies, ACTION_CATEGORIES) != _normalized_counts(
                Counter(self.action_sequence), ACTION_CATEGORIES
            ):
                raise ValueError("action frequencies disagree with action_sequence")
        if sum(self.decoy_type_frequencies.values()) > self.event_count:
            raise ValueError("decoy type frequencies cannot exceed event_count")
        category_set = {category.strip().lower() for category in self.decoy_types_accessed}
        if len(category_set) != len(self.decoy_types_accessed):
            raise ValueError("decoy_types_accessed must contain unique categories")
        if self.decoy_type_frequencies and {
            category.strip().lower() for category in self.decoy_type_frequencies
        } != category_set:
            raise ValueError("decoy type frequencies disagree with decoy_types_accessed")
        if self.decoy_type_frequencies and any(
            count == 0 for count in self.decoy_type_frequencies.values()
        ):
            raise ValueError("observed decoy frequency values must be positive")
        if self.credential_probing != ("attempt_login" in self.action_sequence):
            raise ValueError("credential_probing disagrees with action_sequence")
        if self.database_probing != ("query" in self.action_sequence):
            raise ValueError("database_probing disagrees with action_sequence")
        expected_file_probing = (
            "file" in category_set or "read" in self.action_sequence
        )
        if self.file_probing != expected_file_probing:
            raise ValueError("file_probing disagrees with observed actions or decoy categories")
        expected_risk_level = (
            "high" if self.risk_score >= 60 else
            "medium" if self.risk_score >= 15 else "low"
        )
        if self.risk_level != expected_risk_level:
            raise ValueError("risk_level disagrees with risk_score thresholds")
        if any(len(reason) > 1000 for reason in self.reasons):
            raise ValueError("reason text exceeds the supported limit")

        if self.first_seen is not None and self.last_seen is not None:
            try:
                timestamp_span = (self.last_seen - self.first_seen).total_seconds()
            except TypeError:
                if self.timing_reliable:
                    raise ValueError("reliable timing requires comparable timestamps")
            else:
                if timestamp_span < 0:
                    raise ValueError("last_seen cannot precede first_seen")

        if self.timing_reliable:
            if self.elapsed_seconds is None or self.elapsed_seconds <= 0:
                raise ValueError("reliable timing requires positive elapsed_seconds")
            if self.interactions_per_minute is None:
                raise ValueError("reliable timing requires interactions_per_minute")
            if self.first_seen is None or self.last_seen is None:
                raise ValueError("reliable timing requires comparable timestamps")
            try:
                span = (self.last_seen - self.first_seen).total_seconds()
            except (TypeError, AttributeError) as exc:
                raise ValueError("timestamps must be comparable datetimes") from exc
            if not isfinite(span) or span <= 0:
                raise ValueError("reliable timing requires a positive comparable time span")
            if abs(span - self.elapsed_seconds) > 0.000002:
                raise ValueError("elapsed_seconds disagrees with the timestamp span")
            expected_rate = round(self.event_count / span * 60, 4)
            if abs(expected_rate - self.interactions_per_minute) > 0.0001:
                raise ValueError("interactions_per_minute disagrees with event_count and time span")
        elif self.elapsed_seconds is not None or self.interactions_per_minute is not None:
            raise ValueError("unreliable or unavailable timing features must be null")
        return self


class ShareableFingerprintExportV1(BaseModel):
    """Explicit allowlist; contains no actor key, timestamps, sequence, or prose."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)

    schema_name: Literal[FINGERPRINT_SCHEMA_NAME] = FINGERPRINT_SCHEMA_NAME
    schema_version: Literal[1] = FINGERPRINT_SCHEMA_VERSION
    event_count: StrictInt = Field(ge=0, le=MAX_EVENT_COUNT)
    unique_decoys_accessed: StrictInt = Field(ge=0, le=MAX_EVENT_COUNT)
    unique_actions: StrictInt = Field(ge=0, le=MAX_EVENT_COUNT)
    action_frequencies: dict[StrictStr, FrequencyCount]
    decoy_type_frequencies: dict[StrictStr, FrequencyCount]
    decoy_type_frequencies_available: StrictBool
    credential_probing: StrictBool
    database_probing: StrictBool
    file_probing: StrictBool
    repeated_access: StrictBool
    timing_reliable: StrictBool
    elapsed_time_band: Literal["under_1m", "1_to_10m", "10_to_60m", "over_60m"] | None
    interaction_rate_band: Literal["low", "moderate", "high"] | None
    risk_level: Literal["low", "medium", "high"]

    @field_validator("action_frequencies")
    @classmethod
    def fixed_action_categories(cls, value):
        if set(value) != set(ACTION_CATEGORIES):
            raise ValueError("action_frequencies must contain the fixed schema categories")
        return value

    @field_validator("decoy_type_frequencies")
    @classmethod
    def fixed_decoy_categories(cls, value):
        if set(value) != set(DECOY_CATEGORIES):
            raise ValueError("decoy_type_frequencies must contain the fixed schema categories")
        return value

    @model_validator(mode="after")
    def validate_export(self):
        if sum(self.action_frequencies.values()) != self.event_count:
            raise ValueError("shareable action frequencies must sum to event_count")
        if not self.decoy_type_frequencies_available and any(
            self.decoy_type_frequencies.values()
        ):
            raise ValueError("unavailable decoy frequencies must be zero-filled")
        if self.timing_reliable != (
            self.elapsed_time_band is not None
            and self.interaction_rate_band is not None
        ):
            raise ValueError("timing bands must match timing_reliable")
        return self


class FingerprintVectorV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    schema_name: Literal[VECTOR_SCHEMA_NAME] = VECTOR_SCHEMA_NAME
    schema_version: Literal[1] = VECTOR_SCHEMA_VERSION
    fingerprint_schema_name: Literal[FINGERPRINT_SCHEMA_NAME] = FINGERPRINT_SCHEMA_NAME
    fingerprint_schema_version: Literal[1] = FINGERPRINT_SCHEMA_VERSION
    feature_order: tuple[StrictStr, ...]
    values: tuple[StrictFloat, ...]

    @model_validator(mode="after")
    def validate_vector(self):
        if self.feature_order != VECTOR_FEATURE_ORDER:
            raise ValueError("feature_order does not match vector schema v1")
        if len(self.values) != len(VECTOR_FEATURE_ORDER):
            raise ValueError("vector length does not match vector schema v1")
        if not all(isfinite(value) for value in self.values):
            raise ValueError("vector values must be finite")
        return self


class FingerprintShareResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    export: ShareableFingerprintExportV1
    canonical_json: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    digest_semantics: Literal["canonical-content-integrity-only"] = (
        "canonical-content-integrity-only"
    )


class FingerprintSchemaError(ValueError):
    """A sanitized validation error suitable for API responses."""

    def __init__(self, errors: list[dict[str, str]]) -> None:
        self.errors = errors
        super().__init__("Fingerprint does not satisfy the supported schema")


def _normalized_counts(counts, categories: tuple[str, ...]) -> dict[str, int]:
    normalized = {category: 0 for category in categories}
    for raw_category, count in counts.items():
        category = raw_category.strip().lower()
        normalized[category if category in normalized and category != "other" else "other"] += int(count)
    return normalized


def validate_fingerprint_payload(
    payload: dict[str, Any],
) -> tuple[FingerprintContractV1, str]:
    """Validate schema v1 and adapt legacy API v1 objects lacking schema metadata."""
    normalized = dict(payload)
    compatibility = "native_v1"
    if "schema_name" not in normalized and "schema_version" not in normalized:
        if normalized.get("fingerprint_version", 1) != 1:
            raise FingerprintSchemaError([{
                "field": "fingerprint_version",
                "code": "unsupported_legacy_version",
                "message": "Only legacy fingerprint_version 1 is supported",
            }])
        normalized["schema_name"] = FINGERPRINT_SCHEMA_NAME
        normalized["schema_version"] = 1
        normalized.setdefault("fingerprint_version", 1)
        compatibility = "legacy_fingerprint_v1"
    try:
        return FingerprintContractV1.model_validate(normalized), compatibility
    except ValidationError as exc:
        errors = [
            {
                "field": ".".join(str(part) for part in error["loc"]),
                "code": error["type"],
                "message": error["msg"],
            }
            for error in exc.errors()
        ]
        raise FingerprintSchemaError(errors) from exc


def contract_from_operational(
    fingerprint: BehavioralFingerprint,
) -> FingerprintContractV1:
    payload = fingerprint.model_dump(mode="python")
    payload.update({
        "schema_name": FINGERPRINT_SCHEMA_NAME,
        "schema_version": FINGERPRINT_SCHEMA_VERSION,
    })
    # Earlier v1 records could omit aggregates; derive action counts only from
    # the verified ordered action sequence. Unknown decoy frequencies stay missing.
    if not payload.get("action_frequencies") and payload["action_sequence"]:
        payload["action_frequencies"] = dict(Counter(payload["action_sequence"]))
    return FingerprintContractV1.model_validate(payload)


def to_shareable_export(
    fingerprint: FingerprintContractV1 | BehavioralFingerprint,
) -> ShareableFingerprintExportV1:
    contract = (
        fingerprint
        if isinstance(fingerprint, FingerprintContractV1)
        else contract_from_operational(fingerprint)
    )
    action_counts = contract.action_frequencies or dict(Counter(contract.action_sequence))
    elapsed_band = None
    rate_band = None
    if contract.timing_reliable:
        elapsed = contract.elapsed_seconds
        elapsed_band = (
            "under_1m" if elapsed < 60 else
            "1_to_10m" if elapsed < 600 else
            "10_to_60m" if elapsed < 3600 else "over_60m"
        )
        rate = contract.interactions_per_minute
        rate_band = "low" if rate < 1 else "moderate" if rate < 10 else "high"
    return ShareableFingerprintExportV1(
        event_count=contract.event_count,
        unique_decoys_accessed=contract.unique_decoys_accessed,
        unique_actions=contract.unique_actions,
        action_frequencies=_normalized_counts(action_counts, ACTION_CATEGORIES),
        decoy_type_frequencies=_normalized_counts(
            contract.decoy_type_frequencies, DECOY_CATEGORIES
        ),
        decoy_type_frequencies_available=(
            bool(contract.decoy_type_frequencies) or contract.event_count == 0
        ),
        credential_probing=contract.credential_probing,
        database_probing=contract.database_probing,
        file_probing=contract.file_probing,
        repeated_access=contract.repeated_access,
        timing_reliable=contract.timing_reliable,
        elapsed_time_band=elapsed_band,
        interaction_rate_band=rate_band,
        risk_level=contract.risk_level,
    )


def canonical_serialize_export(
    export: ShareableFingerprintExportV1,
) -> str:
    """Return canonical JSON (sorted keys, compact UTF-8-safe, null explicit)."""
    validated = ShareableFingerprintExportV1.model_validate(export.model_dump())
    return json.dumps(
        validated.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def export_digest(export: ShareableFingerprintExportV1) -> str:
    """SHA-256 content digest; integrity/idempotency aid, not anonymization."""
    return sha256(canonical_serialize_export(export).encode("utf-8")).hexdigest()


class BehavioralFingerprintVectorizer:
    """Deterministic fixed-width adapter for future scikit-learn models."""

    feature_order = VECTOR_FEATURE_ORDER

    def vectorize(
        self,
        fingerprint: FingerprintContractV1 | BehavioralFingerprint,
    ) -> FingerprintVectorV1:
        contract = (
            fingerprint
            if isinstance(fingerprint, FingerprintContractV1)
            else contract_from_operational(fingerprint)
        )
        actions = _normalized_counts(
            contract.action_frequencies or Counter(contract.action_sequence),
            ACTION_CATEGORIES,
        )
        decoys = _normalized_counts(contract.decoy_type_frequencies, DECOY_CATEGORIES)
        decoy_counts_available = bool(contract.decoy_type_frequencies) or contract.event_count == 0
        values: list[float] = [
            float(contract.event_count),
            float(contract.unique_decoys_accessed),
            float(contract.unique_actions),
            *(float(actions[key]) for key in ACTION_CATEGORIES),
            float(decoy_counts_available),
            *(float(decoys[key]) for key in DECOY_CATEGORIES),
            float(contract.credential_probing),
            float(contract.database_probing),
            float(contract.file_probing),
            float(contract.repeated_access),
            float(contract.timing_reliable),
            float(contract.elapsed_seconds or 0.0),
            float(contract.elapsed_seconds is None),
            float(contract.interactions_per_minute or 0.0),
            float(contract.interactions_per_minute is None),
            float(contract.risk_score),
            *(float(contract.risk_level == category) for category in RISK_CATEGORIES),
        ]
        vector = FingerprintVectorV1(
            feature_order=VECTOR_FEATURE_ORDER,
            values=tuple(values),
        )
        if len(vector.values) != len(self.feature_order) or not all(
            isfinite(value) for value in vector.values
        ):
            raise ValueError("Vectorizer produced an invalid feature vector")
        return vector


def fingerprint_schema_metadata() -> dict[str, Any]:
    """Machine-readable definitions and compatibility policy for API/docs."""
    vector_definitions = {}
    for name in VECTOR_FEATURE_ORDER:
        if name.endswith(".missing") or name.endswith("_available"):
            kind = "boolean_indicator_encoded_as_float"
        elif name.startswith("risk_level."):
            kind = "one_hot_boolean_encoded_as_float"
        elif name.startswith("action_frequency.") or name.startswith("decoy_frequency."):
            kind = "numeric_category_count"
        elif name in {
            "credential_probing", "database_probing", "file_probing",
            "repeated_access", "timing_reliable",
        }:
            kind = "boolean_encoded_as_float"
        else:
            kind = "numeric"
        vector_definitions[name] = {
            "type": kind,
            "missing_value": "0 with explicit indicator when applicable",
        }
    return {
        "schema_name": FINGERPRINT_SCHEMA_NAME,
        "schema_version": FINGERPRINT_SCHEMA_VERSION,
        "compatibility": {
            "supported_operational_versions": [1],
            "legacy_payloads_without_schema_metadata": "Accepted only when fingerprint_version is 1; metadata is added by the adapter.",
            "unsupported_versions": "Rejected; never silently reinterpreted.",
            "missing_counts": "Empty action frequencies derive from action_sequence; empty decoy frequencies remain unavailable and have an explicit availability indicator in exports and vectors.",
            "missing_timing": "Null values remain unavailable; vector value is zero only alongside a missing indicator.",
            "unknown_categories": "Trimmed and lowercased, then aggregated into the fixed other bucket.",
        },
        "privacy_export_allowlist": [
            "schema_name", "schema_version",
            "event_count", "unique_decoys_accessed", "unique_actions",
            "action_frequencies", "decoy_type_frequencies",
            "decoy_type_frequencies_available",
            "credential_probing", "database_probing", "file_probing",
            "repeated_access", "timing_reliable", "elapsed_time_band",
            "interaction_rate_band", "risk_level",
        ],
        "excluded_from_export": [
            "actor_id", "action_sequence", "first_seen", "last_seen",
            "reasons", "event_id", "decoy_id", "payload", "filesystem_path",
            "username", "email", "ip_address", "credentials", "tokens",
        ],
        "vector_schema_name": VECTOR_SCHEMA_NAME,
        "vector_schema_version": VECTOR_SCHEMA_VERSION,
        "vector_feature_order": list(VECTOR_FEATURE_ORDER),
        "vector_feature_definitions": vector_definitions,
        "vector_missing_value_policy": "Null timing maps to value 0 plus a missing-indicator value 1. Missing legacy decoy counts have an availability indicator of 0. Unknown categories map to fixed other dimensions.",
        "feature_definitions": {
            "event_count": {"type": "numeric_count", "semantics": "Recorded interactions for the actor."},
            "unique_decoys_accessed": {"type": "numeric_count", "semantics": "Distinct decoy IDs accessed."},
            "unique_actions": {"type": "numeric_count", "semantics": "Distinct action strings observed."},
            "action_frequencies": {"type": "categorical_counts", "categories": list(ACTION_CATEGORIES), "semantics": "Unknown action labels aggregate to other."},
            "decoy_type_frequencies": {"type": "categorical_counts", "categories": list(DECOY_CATEGORIES), "semantics": "Unknown decoy categories aggregate to other; missing legacy counts stay unavailable; see decoy_type_frequencies_available."},
            "probing_indicators": {"type": "boolean", "semantics": "Observed login, database, or file probing; not predictions."},
            "repeated_access": {"type": "boolean", "semantics": "At least one decoy ID was accessed more than once."},
            "timing_reliable": {"type": "boolean", "semantics": "Timestamp comparability and positive time span were verified."},
            "elapsed_seconds": {"type": "nullable_numeric", "semantics": "Exact internal span only when timing_reliable; omitted from shareable export."},
            "interactions_per_minute": {"type": "nullable_numeric", "semantics": "Derived only when timing_reliable; export is bucketed."},
            "risk_score": {"type": "numeric_score", "range": [0, 100], "semantics": "Existing heuristic score; not ML output."},
            "risk_level": {"type": "categorical", "categories": list(RISK_CATEGORIES), "semantics": "Existing heuristic category."},
        },
    }
