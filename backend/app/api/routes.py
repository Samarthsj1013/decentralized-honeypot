
from fastapi import APIRouter, HTTPException, Query, status

from backend.app.events.models import (
    DecoyAsset,
    HoneypotEvent,
    InteractionRequest,
)
from backend.app.events.store import event_store
from backend.app.honeypot.service import HoneypotService
from backend.app.intelligence.service import (
    BehavioralFingerprint,
    intelligence_service,
)

router = APIRouter(prefix="/api/v1")

honeypot_service = HoneypotService(event_store)


@router.get(
    "/decoys",
    response_model=list[DecoyAsset],
    tags=["Honeypot"],
)
async def list_decoys() -> list[DecoyAsset]:
    """List the registered synthetic decoy assets."""
    return honeypot_service.list_decoys()


@router.get(
    "/decoys/{decoy_id}",
    response_model=DecoyAsset,
    tags=["Honeypot"],
)
async def get_decoy(decoy_id: str) -> DecoyAsset:
    """Retrieve metadata for one registered decoy."""
    return honeypot_service.get_decoy(decoy_id)


@router.post(
    "/decoys/{decoy_id}/interactions",
    response_model=HoneypotEvent,
    status_code=status.HTTP_201_CREATED,
    tags=["Honeypot"],
)
async def record_interaction(
    decoy_id: str,
    request: InteractionRequest,
) -> HoneypotEvent:
    """Record a simulated interaction with a decoy."""
    return honeypot_service.record_interaction(decoy_id, request)


@router.get(
    "/events",
    response_model=list[HoneypotEvent],
    tags=["Honeypot"],
)
async def list_events(
    limit: int = Query(default=50, ge=1, le=200),
) -> list[HoneypotEvent]:
    """Return the most recent recorded interactions."""
    events = event_store.list_events()
    return list(reversed(events[-limit:]))


@router.get(
    "/events/{event_id}",
    response_model=HoneypotEvent,
    tags=["Honeypot"],
)
async def get_event(event_id: str) -> HoneypotEvent:
    """Retrieve one event by its unique ID."""
    event = event_store.get(event_id)

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Event not found",
        )

    return event


@router.get(
    "/intelligence/fingerprints",
    response_model=list[BehavioralFingerprint],
    tags=["Threat Intelligence"],
)
async def list_fingerprints() -> list[BehavioralFingerprint]:
    """Analyze all synthetic actors with recorded interactions."""
    return intelligence_service.analyze_all()


@router.get(
    "/intelligence/fingerprints/{actor_id}",
    response_model=BehavioralFingerprint,
    tags=["Threat Intelligence"],
)
async def get_fingerprint(actor_id: str) -> BehavioralFingerprint:
    """Analyze the recorded behavior of one synthetic actor."""
    fingerprint = intelligence_service.analyze_actor(actor_id)

    if fingerprint is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No recorded events found for this actor",
        )

    return fingerprint
