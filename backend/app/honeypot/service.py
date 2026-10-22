from uuid import uuid4

from fastapi import HTTPException, status

from app.events.models import (
    DecoyAsset,
    HoneypotEvent,
    InteractionRequest,
)
from app.events.store import EventStore
from app.ledger.service import EventLedger, event_ledger


class HoneypotService:
    """Manages synthetic decoys and records their interactions."""

    def __init__(
        self,
        store: EventStore,
        ledger: EventLedger | None = None,
        registry=None,
    ) -> None:
        self._store = store
        self._ledger = ledger if ledger is not None else event_ledger
        self._registry = registry

        self._decoys = {
            "decoy-finance-001": DecoyAsset(
                decoy_id="decoy-finance-001",
                name="quarterly_financial_report.txt",
                decoy_type="file",
                description="Synthetic financial report for testing.",
            ),
            "decoy-credential-001": DecoyAsset(
                decoy_id="decoy-credential-001",
                name="service_credentials",
                decoy_type="credential",
                description="Fake credential record; no real secrets.",
            ),
            "decoy-database-001": DecoyAsset(
                decoy_id="decoy-database-001",
                name="customer_backup_record",
                decoy_type="database_record",
                description="Synthetic database record for testing.",
            ),
        }

        self._load_generated_decoys()

    def _load_generated_decoys(self) -> None:
        """Load persisted generated decoys into the active decoy collection."""
        if self._registry is None:
            return

        for generated in self._registry.list_all():
            self._add_generated_decoy(generated)

    def _add_generated_decoy(self, generated) -> DecoyAsset:
        """Convert a persisted or newly generated decoy into a DecoyAsset."""
        decoy = DecoyAsset(
            decoy_id=generated.decoy_id,
            name=generated.name,
            decoy_type=generated.decoy_type,
            description=generated.description,
        )
        self._decoys[decoy.decoy_id] = decoy
        return decoy

    def register_generated_decoys(self, generated_decoys) -> list[DecoyAsset]:
        """Add generated decoys to the active collection."""
        return [
            self._add_generated_decoy(generated)
            for generated in generated_decoys
        ]

    def list_decoys(self) -> list[DecoyAsset]:
        return list(self._decoys.values())

    def get_decoy(self, decoy_id: str) -> DecoyAsset:
        decoy = self._decoys.get(decoy_id)

        if decoy is None and self._registry is not None:
            generated = self._registry.get(decoy_id)
            if generated is not None:
                decoy = self._add_generated_decoy(generated)

        if decoy is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Decoy asset not found",
            )

        return decoy

    def record_interaction(
        self,
        decoy_id: str,
        request: InteractionRequest,
    ) -> HoneypotEvent:
        self.get_decoy(decoy_id)

        event = HoneypotEvent(
            event_id=str(uuid4()),
            decoy_id=decoy_id,
            actor_id=request.actor_id,
            action=request.action,
        )

        self._store.add(event)
        self._ledger.append(event)

        return event
