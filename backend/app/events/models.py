
from datetime import datetime, timezone
from math import isfinite
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, StrictStr, field_validator


class DecoyAsset(BaseModel):
    """Metadata for a synthetic honeypot asset."""

    model_config = ConfigDict(frozen=True)

    decoy_id: str
    name: str
    decoy_type: Literal["file", "credential", "database_record"]
    description: str


class InteractionRequest(BaseModel):
    """Input describing a simulated interaction with a decoy."""

    actor_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Synthetic identifier for the test actor",
    )

    action: Literal["view", "read", "attempt_login", "query"]


class HoneypotEvent(BaseModel):
    """A recorded interaction with a decoy asset."""

    event_id: str
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    decoy_id: str
    actor_id: str
    action: str
    event_type: Literal["decoy_interaction", "external_telemetry"] = "decoy_interaction"
    severity: Literal["low", "medium", "high", "critical"] = "high"
    source: Literal["simulator", "external"] = "simulator"
    source_system: str | None = None
    sensor_id: str | None = None
    source_event_id: str | None = None
    telemetry_event_type: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    attributes: dict[str, Any] | None = None


def _validate_json_tree(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> None:
    """Bound generic JSON values before they enter event history or the ledger."""
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > 512:
        raise ValueError("attributes contain too many JSON values")
    if depth > 6:
        raise ValueError("attributes exceed the maximum nesting depth")
    if value is None or type(value) in (bool, int):
        return
    if type(value) is float:
        if not isfinite(value):
            raise ValueError("attributes must contain finite numbers")
        return
    if isinstance(value, str):
        if len(value) > 2048 or "\x00" in value:
            raise ValueError("attribute strings are too long or contain NUL")
        return
    if isinstance(value, list):
        if len(value) > 128:
            raise ValueError("attribute arrays contain too many items")
        for item in value:
            _validate_json_tree(item, depth=depth + 1, budget=budget)
        return
    if isinstance(value, dict):
        if len(value) > 64:
            raise ValueError("attribute objects contain too many fields")
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 128 or "\x00" in key:
                raise ValueError("attribute keys must be non-empty and bounded")
            _validate_json_tree(item, depth=depth + 1, budget=budget)
        return
    raise ValueError("attributes must contain JSON-compatible values")


class TelemetryIngestRequest(BaseModel):
    """Normalized, inert event envelope accepted from an external sensor."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source_system: Literal["generic", "zeek", "suricata", "cowrie"] = "generic"
    sensor_id: StrictStr = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    external_event_id: StrictStr = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    occurred_at: datetime
    event_type: StrictStr = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: StrictStr | None = Field(default=None, max_length=32, pattern=r"^[A-Za-z0-9_.+-]+$")
    attributes: dict[str, Any] = Field(default_factory=dict, max_length=64)

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        return value

    @field_validator("attributes")
    @classmethod
    def bound_attributes(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_json_tree(value)
        return value
