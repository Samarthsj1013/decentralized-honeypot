from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel

from app.adaptation.storage import SQLiteAdaptationStorage
from app.events.models import HoneypotEvent
from app.events.store import EventStore


AdaptationStrategy = Literal[
    "neutral_response",
    "credential_decoy",
    "database_decoy",
    "expanded_decoy_path",
]


class AdaptationDecision(BaseModel):
    actor_id: str
    event_count: int
    risk_level: Literal["low", "medium", "high"]
    selected_strategy: AdaptationStrategy
    reason: str
    observed_actions: list[str]
    observed_decoys: list[str]
    simulation_only: bool = True
    decision_id: int | None = None
    created_at: datetime | None = None


class AdaptiveHoneypotService:
    """
    Behavior-driven adaptation policy with persistent decision history.

    Decisions are simulations only. This service does not change
    real network controls or expose real credentials.
    """

    def __init__(
        self,
        store: EventStore,
        history_storage: SQLiteAdaptationStorage | None = None,
    ) -> None:
        self._store = store

        if history_storage is None:
            database_path = (
                Path(__file__).resolve().parents[3]
                / "data"
                / "event_ledger.sqlite3"
            )
            history_storage = SQLiteAdaptationStorage(database_path)

        self._history_storage = history_storage

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
            event.action == "attempt_login"
            for event in events
        )
        database_queries = sum(
            event.action == "query"
            for event in events
        )

        # Choose a strategy from the actor's accumulated behavior.
        if (
            len(decoys) >= 2
            and login_attempts > 0
            and database_queries > 0
        ):
            strategy: AdaptationStrategy = "expanded_decoy_path"
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

        # Compare with the previous saved decision for this actor.
        previous_history = self._history_storage.list_decisions(
            actor_id=actor_id,
            limit=1,
        )

        previous_strategy = None
        if previous_history:
            previous_strategy = previous_history[-1].get(
                "selected_strategy"
            )

        if (
            previous_strategy is not None
            and previous_strategy != strategy
        ):
            reason += (
                f" Strategy changed from {previous_strategy} "
                f"to {strategy} after reassessing accumulated behavior."
            )

        created_at = datetime.now(timezone.utc)

        decision_data = {
            "actor_id": actor_id,
            "event_count": len(events),
            "risk_level": risk_level,
            "selected_strategy": strategy,
            "reason": reason,
            "observed_actions": sorted(actions),
            "observed_decoys": sorted(decoys),
            "simulation_only": True,
            "created_at": created_at.isoformat(),
        }

        saved_decision = self._history_storage.append_decision(
            decision_data
        )

        return AdaptationDecision(
            actor_id=actor_id,
            event_count=len(events),
            risk_level=risk_level,
            selected_strategy=strategy,
            reason=reason,
            observed_actions=sorted(actions),
            observed_decoys=sorted(decoys),
            simulation_only=True,
            decision_id=saved_decision["decision_id"],
            created_at=created_at,
        )

    def get_decision_history(
        self,
        actor_id: str,
        limit: int = 50,
    ) -> list[dict]:
        return self._history_storage.list_decisions(
            actor_id=actor_id,
            limit=limit,
        )


from app.events.store import event_store

adaptive_honeypot_service = AdaptiveHoneypotService(event_store)