
from uuid import uuid4

from fastapi import HTTPException, status

from backend.app.events.models import (
    DecoyAsset,
    HoneypotEvent,
    InteractionRequest,
)
from backend.app.events.store import EventStore


class HoneypotService:
    """Manages synthetic decoys and records their interactions."""

    def __init__(self, store: EventStore) -> None:
        self._store = store
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

    def list_decoys(self) -> list[DecoyAsset]:
        return list(self._decoys.values())

    def get_decoy(self, decoy_id: str) -> DecoyAsset:
        decoy = self._decoys.get(decoy_id)

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

        return self._store.add(event)
