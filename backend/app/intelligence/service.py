
from collections import Counter
from datetime import datetime
from math import isfinite
from typing import Literal

from pydantic import BaseModel, Field

from app.events.models import HoneypotEvent
from app.events.store import EventStore, event_store


class BehavioralFingerprint(BaseModel):
    """Versioned, deterministic summary of observable synthetic interactions."""

    fingerprint_version: int = Field(default=1, ge=1)
    actor_id: str
    event_count: int
    unique_decoys_accessed: int
    unique_actions: int
    action_sequence: list[str]
    action_frequencies: dict[str, int] = Field(default_factory=dict)
    decoy_types_accessed: list[str]
    decoy_type_frequencies: dict[str, int] = Field(default_factory=dict)
    credential_probing: bool = False
    database_probing: bool = False
    file_probing: bool = False
    repeated_access: bool = False
    elapsed_seconds: float | None = None
    interactions_per_minute: float | None = None
    timing_reliable: bool = False
    first_seen: datetime
    last_seen: datetime
    risk_score: int
    risk_level: Literal["low", "medium", "high"]
    reasons: list[str]
    assessment_type: Literal["heuristic_baseline"] = "heuristic_baseline"


class BehavioralIntelligenceService:
    """Creates evidence-backed summaries from recorded decoy events."""

    DECOY_TYPES = {
        "decoy-finance-001": "file",
        "decoy-credential-001": "credential",
        "decoy-database-001": "database_record",
    }

    @classmethod
    def _decoy_type(cls, decoy_id: str) -> str | None:
        if decoy_id in cls.DECOY_TYPES:
            return cls.DECOY_TYPES[decoy_id]
        if decoy_id.startswith("generated-credential-"):
            return "credential"
        if decoy_id.startswith("generated-database_record-"):
            return "database_record"
        if decoy_id.startswith("generated-file-"):
            return "file"
        if decoy_id.endswith("-identity"):
            return "credential"
        if decoy_id.endswith("-record"):
            return "database_record"
        if decoy_id.endswith("-file"):
            return "file"
        return None

    def __init__(self, store: EventStore) -> None:
        self._store = store

    def analyze_actor(
        self,
        actor_id: str,
    ) -> BehavioralFingerprint | None:
        events = [
            event
            for event in self._store.list_events()
            if event.actor_id == actor_id
        ]

        if not events:
            return None

        return self._build_fingerprint(actor_id, events)

    def analyze_all(self) -> list[BehavioralFingerprint]:
        events = self._store.list_events()
        actor_ids = sorted({event.actor_id for event in events})

        return [
            self._build_fingerprint(
                actor_id,
                [
                    event
                    for event in events
                    if event.actor_id == actor_id
                ],
            )
            for actor_id in actor_ids
        ]

    @classmethod
    def _build_fingerprint(
        cls,
        actor_id: str,
        events: list[HoneypotEvent],
    ) -> BehavioralFingerprint:
        has_timezone = [
            event.timestamp.utcoffset() is not None for event in events
        ]
        timestamps_comparable = len(set(has_timezone)) <= 1
        ordered_events = (
            sorted(events, key=lambda event: event.timestamp)
            if timestamps_comparable
            else list(events)
        )

        decoy_ids = {event.decoy_id for event in ordered_events}
        action_counts = Counter(
            event.action for event in ordered_events
        )

        decoy_type_counts = Counter(
            decoy_type
            for event in ordered_events
            if (decoy_type := cls._decoy_type(event.decoy_id)) is not None
        )
        decoy_types = sorted(decoy_type_counts)
        try:
            elapsed = (
                ordered_events[-1].timestamp - ordered_events[0].timestamp
            ).total_seconds()
        except TypeError:
            elapsed = float("nan")
        timing_reliable = timestamps_comparable and isfinite(elapsed) and elapsed > 0
        interactions_per_minute = (
            round(len(ordered_events) / elapsed * 60, 4)
            if timing_reliable
            else None
        )

        score = 0
        reasons: list[str] = []

        if len(ordered_events) >= 5:
            score += 20
            reasons.append("Repeated decoy interactions")

        if len(decoy_ids) >= 2:
            score += 25
            reasons.append("Multiple distinct decoys accessed")

        if "attempt_login" in action_counts:
            score += 20
            reasons.append("Login attempt against a decoy")

        if "query" in action_counts:
            score += 15
            reasons.append("Database decoy query observed")

        if len(decoy_types) >= 3:
            score += 20
            reasons.append("Interactions span all decoy categories")

        score = min(score, 100)

        if score >= 60:
            risk_level = "high"
        elif score >= 15:
            risk_level = "medium"
        else:
            risk_level = "low"

        if not reasons:
            reasons.append(
                "No additional heuristic risk indicators observed"
            )

        return BehavioralFingerprint(
            actor_id=actor_id,
            event_count=len(ordered_events),
            unique_decoys_accessed=len(decoy_ids),
            unique_actions=len(action_counts),
            action_sequence=[
                event.action for event in ordered_events
            ],
            action_frequencies=dict(sorted(action_counts.items())),
            decoy_types_accessed=decoy_types,
            decoy_type_frequencies=dict(sorted(decoy_type_counts.items())),
            credential_probing=action_counts["attempt_login"] > 0,
            database_probing=action_counts["query"] > 0,
            file_probing=(
                "file" in decoy_type_counts or action_counts["read"] > 0
            ),
            repeated_access=max(
                Counter(event.decoy_id for event in ordered_events).values(),
                default=0,
            ) > 1,
            elapsed_seconds=round(elapsed, 6) if timing_reliable else None,
            interactions_per_minute=interactions_per_minute,
            timing_reliable=timing_reliable,
            first_seen=ordered_events[0].timestamp,
            last_seen=ordered_events[-1].timestamp,
            risk_score=score,
            risk_level=risk_level,
            reasons=reasons,
        )


intelligence_service = BehavioralIntelligenceService(event_store)
