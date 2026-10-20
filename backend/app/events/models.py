
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


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
    event_type: Literal["decoy_interaction"] = "decoy_interaction"
    severity: Literal["low", "medium", "high"] = "high"
    source: Literal["simulator"] = "simulator"
