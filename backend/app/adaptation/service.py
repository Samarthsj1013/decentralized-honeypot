
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel

from backend.app.events.models import HoneypotEvent
from backend.app.events.store import EventStore


class AdaptationDecision(BaseModel):
    actor_id: str
    event_count: int
    risk_level: Literal["low", "medium", "high"]
    selected_strategy: Literal[
        "neutral_response",
        "credential_decoy",
        "database_decoy",
        "expanded_decoy_path",
    ]
    reason: str
    observed_actions: list[str]
    observed_decoys: list[str]
    simulation_only: bool = True


class AdaptiveHoneypotService:
    """
    Deterministic adaptation policy for a local honeypot simulation.

    This service selects a simulated strategy from recorded events.
    It does not change real network controls or expose real credentials.
    """

    def __init__(self, store: EventStore) -> None:
        self._store = store

    def analyze_actor(self, actor_id: str) -> AdaptationDecision:
        events: list[HoneypotEvent] = [
            event
            for event in self._store.list_events()
            if event.actor_id == actor_id
        ]

        if not events:
            raise HTTPException(
                status_code=404,
                detail="No recorded events found for this actor",
            )

        actions = {event.action for event in events}
        decoys = {event.decoy_id for event in events}

        login_attempts = sum(
            event.action == "attempt_login" for event in events
        )
        database_queries = sum(
            event.action == "query" for event in events
        )

        if (
            len(decoys) >= 2
            and login_attempts > 0
            and database_queries > 0
        ):
            strategy = "expanded_decoy_path"
            risk_level = "high"
            reason = (
                "The actor interacted with multiple decoys and performed "
                "both login attempts and database queries."
            )

        elif login_attempts > 0:
            strategy = "credential_decoy"
            risk_level = "medium"
            reason = (
                "A login attempt was observed; select a simulated "
                "credential-focused decoy response."
            )

        elif database_queries > 0:
            strategy = "database_decoy"
            risk_level = "medium"
            reason = (
                "A database query was observed; select a simulated "
                "database-focused decoy response."
            )

        else:
            strategy = "neutral_response"
            risk_level = "low"
            reason = (
                "No login attempts or database queries were observed; "
                "retain the neutral simulated response."
            )

        return AdaptationDecision(
            actor_id=actor_id,
            event_count=len(events),
            risk_level=risk_level,
            selected_strategy=strategy,
            reason=reason,
            observed_actions=sorted(actions),
            observed_decoys=sorted(decoys),
        )


from backend.app.events.store import event_store

adaptive_honeypot_service = AdaptiveHoneypotService(event_store)
