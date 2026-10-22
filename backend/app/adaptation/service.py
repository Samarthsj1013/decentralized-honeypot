from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, Field

from app.adaptation.storage import SQLiteAdaptationStorage
from app.events.store import EventStore
from app.intelligence.service import (
    BehavioralFingerprint,
    BehavioralIntelligenceService,
)


AdaptationStrategy = Literal[
    "neutral_response",
    "file_decoy",
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
    fingerprint_version: int = 1
    influencing_features: dict[str, int | float | bool | list[str]] = Field(
        default_factory=dict
    )
    strategy_changed_from: AdaptationStrategy | None = None
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
        self._intelligence = BehavioralIntelligenceService(store)

        if history_storage is None:
            database_path = (
                Path(__file__).resolve().parents[3]
                / "data"
                / "event_ledger.sqlite3"
            )
            history_storage = SQLiteAdaptationStorage(database_path)

        self._history_storage = history_storage

    def analyze_actor(self, actor_id: str) -> AdaptationDecision:
        decision = self.preview_actor(actor_id)
        previous = self._history_storage.list_decisions(actor_id, limit=1)
        previous_strategy = (
            previous[-1]["selected_strategy"] if previous else None
        )
        changed_from = (
            previous_strategy
            if previous_strategy != decision.selected_strategy
            else None
        )
        reason = decision.reason
        if changed_from is not None:
            reason += f" Strategy changed from {changed_from} to {decision.selected_strategy}."
        created_at = datetime.now(timezone.utc)
        saved = self._history_storage.append_decision(
            decision.model_copy(
                update={
                    "reason": reason,
                    "strategy_changed_from": changed_from,
                    "created_at": created_at,
                }
            ).model_dump(mode="json", exclude={"decision_id"})
        )
        return decision.model_copy(
            update={
                "decision_id": saved["decision_id"],
                "created_at": created_at,
                "reason": reason,
                "strategy_changed_from": changed_from,
            }
        )

    def record_decision(self, fingerprint: BehavioralFingerprint) -> AdaptationDecision:
        """Persist a decision produced by an interaction write."""
        # The event has already been stored. Reuse the pure preview builder so
        # the exact observed fingerprint, not a later query, drives this row.
        decision = self._decision_for_fingerprint(fingerprint)
        previous = self._history_storage.list_decisions(
            fingerprint.actor_id, limit=1
        )
        previous_strategy = previous[-1]["selected_strategy"] if previous else None
        changed_from = (
            previous_strategy
            if previous_strategy != decision.selected_strategy
            else None
        )
        reason = decision.reason
        if changed_from is not None:
            reason += f" Strategy changed from {changed_from} to {decision.selected_strategy}."
        created_at = datetime.now(timezone.utc)
        saved = self._history_storage.append_decision(
            decision.model_copy(
                update={
                    "reason": reason,
                    "strategy_changed_from": changed_from,
                    "created_at": created_at,
                }
            ).model_dump(mode="json", exclude={"decision_id"})
        )
        return decision.model_copy(
            update={
                "decision_id": saved["decision_id"],
                "created_at": created_at,
                "reason": reason,
                "strategy_changed_from": changed_from,
            }
        )

    def preview_actor(self, actor_id: str) -> AdaptationDecision:
        """Return the current decision without writing decision history."""
        fingerprint = self._intelligence.analyze_actor(actor_id)
        if fingerprint is None:
            raise HTTPException(
                status_code=404,
                detail="No recorded events found for this actor",
            )
        decision = self._decision_for_fingerprint(fingerprint)
        baseline = self._history_storage.get_observed_strategy(actor_id)
        changed_from = (
            baseline
            if baseline is not None and baseline != decision.selected_strategy
            else None
        )
        if changed_from is None:
            history = self._history_storage.list_decisions(actor_id, limit=1)
            if history and history[-1]["selected_strategy"] == decision.selected_strategy:
                changed_from = history[-1]["strategy_changed_from"]
        if changed_from is not None:
            return decision.model_copy(
                update={
                    "strategy_changed_from": changed_from,
                    "reason": (
                        f"{decision.reason} The most recent recorded decision "
                        f"changed from {changed_from} to {decision.selected_strategy}."
                    ),
                }
            )
        return decision

    def _decision_for_fingerprint(
        self, fingerprint: BehavioralFingerprint
    ) -> AdaptationDecision:
        actor_id = fingerprint.actor_id
        return AdaptationDecision(
            actor_id=actor_id,
            event_count=fingerprint.event_count,
            risk_level=fingerprint.risk_level,
            selected_strategy=self.select_strategy(fingerprint),
            reason=self._decision_reason(fingerprint),
            observed_actions=sorted(fingerprint.action_frequencies),
            observed_decoys=sorted(
                {
                    event.decoy_id
                    for event in self._store.list_events()
                    if event.actor_id == actor_id
                }
            ),
            fingerprint_version=fingerprint.fingerprint_version,
            influencing_features=self._influencing_features(fingerprint),
            simulation_only=True,
        )

    @staticmethod
    def select_strategy(fingerprint: BehavioralFingerprint) -> AdaptationStrategy:
        if (
            fingerprint.credential_probing
            and fingerprint.database_probing
            and fingerprint.unique_decoys_accessed >= 2
        ):
            return "expanded_decoy_path"
        if fingerprint.credential_probing:
            return "credential_decoy"
        if fingerprint.database_probing:
            return "database_decoy"
        if fingerprint.file_probing:
            return "file_decoy"
        return "neutral_response"

    @staticmethod
    def _influencing_features(
        fingerprint: BehavioralFingerprint,
    ) -> dict[str, int | float | bool | list[str]]:
        return {
            "credential_probing": fingerprint.credential_probing,
            "database_probing": fingerprint.database_probing,
            "unique_decoys_accessed": fingerprint.unique_decoys_accessed,
            "decoy_types_accessed": fingerprint.decoy_types_accessed,
            "repeated_access": fingerprint.repeated_access,
            "event_count": fingerprint.event_count,
        }

    @classmethod
    def _decision_reason(cls, fingerprint: BehavioralFingerprint) -> str:
        strategy = cls.select_strategy(fingerprint)
        if strategy == "expanded_decoy_path":
            return (
                "Multiple decoys include credential probing and database "
                "probing; select the expanded simulated decoy path."
            )
        if strategy == "credential_decoy":
            return "Credential probing was observed; select a simulated credential decoy."
        if strategy == "database_decoy":
            return "Database probing was observed; select a simulated database decoy."
        if strategy == "file_decoy":
            return "File probing was observed; select a simulated file decoy."
        return "No credential or database probing was observed; retain the neutral simulated response."

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
