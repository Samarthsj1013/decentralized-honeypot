
from collections import Counter
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.events.models import HoneypotEvent
from app.events.store import EventStore, event_store


class BehavioralFingerprint(BaseModel):
    """Summary of observed interactions for one synthetic actor."""

    actor_id: str
    event_count: int
    unique_decoys_accessed: int
    unique_actions: int
    action_sequence: list[str]
    decoy_types_accessed: list[str]
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
        ordered_events = sorted(
            events,
            key=lambda event: event.timestamp,
        )

        decoy_ids = {event.decoy_id for event in ordered_events}
        action_counts = Counter(
            event.action for event in ordered_events
        )

        decoy_types = sorted(
            {
                cls.DECOY_TYPES[event.decoy_id]
                for event in ordered_events
                if event.decoy_id in cls.DECOY_TYPES
            }
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
        elif score >= 30:
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
            decoy_types_accessed=decoy_types,
            first_seen=ordered_events[0].timestamp,
            last_seen=ordered_events[-1].timestamp,
            risk_score=score,
            risk_level=risk_level,
            reasons=reasons,
        )


intelligence_service = BehavioralIntelligenceService(event_store)
