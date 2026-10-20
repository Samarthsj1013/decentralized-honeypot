
from fastapi import APIRouter, HTTPException, Query, status

from backend.app.events.models import (
    DecoyAsset,
    HoneypotEvent,
    InteractionRequest,
)
from backend.app.events.store import event_store
from backend.app.honeypot.service import HoneypotService

router = APIRouter(prefix="/api/v1", tags=["Honeypot"])

service = HoneypotService(event_store)


@router.get("/decoys", response_model=list[DecoyAsset])
async def list_decoys() -> list[DecoyAsset]:
    """List the registered synthetic decoy assets."""
    return service.list_decoys()


@router.get("/decoys/{decoy_id}", response_model=DecoyAsset)
async def get_decoy(decoy_id: str) -> DecoyAsset:
    """Retrieve metadata for one registered decoy."""
    return service.get_decoy(decoy_id)


@router.post(
    "/decoys/{decoy_id}/interactions",
    response_model=HoneypotEvent,
    status_code=status.HTTP_201_CREATED,
)
async def record_interaction(
    decoy_id: str,
    request: InteractionRequest,
) -> HoneypotEvent:
    """Record a simulated interaction with a decoy."""
    return service.record_interaction(decoy_id, request)


@router.get("/events", response_model=list[HoneypotEvent])
async def list_events(
    limit: int = Query(default=50, ge=1, le=200),
) -> list[HoneypotEvent]:
    """Return the most recent recorded interactions."""
    events = event_store.list_events()
    return list(reversed(events[-limit:]))


@router.get("/events/{event_id}", response_model=HoneypotEvent)
async def get_event(event_id: str) -> HoneypotEvent:
    """Retrieve one event by its unique ID."""
    event = event_store.get(event_id)

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Event not found",
        )

    return event
