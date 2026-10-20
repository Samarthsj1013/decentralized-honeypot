
from fastapi import APIRouter, HTTPException, Query

from backend.app.adaptation.service import (
    AdaptationDecision,
    adaptive_honeypot_service,
)
from backend.app.events.models import (
    DecoyAsset,
    HoneypotEvent,
    InteractionRequest,
)
from backend.app.events.store import event_store
from backend.app.honeypot.service import HoneypotService
from backend.app.intelligence.ml_service import (
    MLBehaviorAssessment,
    ml_intelligence_service,
)
from backend.app.intelligence.service import (
    BehavioralFingerprint,
    intelligence_service,
)
from backend.app.ledger.checkpoint import (
    CheckpointVerification,
    SignedCheckpoint,
    checkpoint_service,
)
from backend.app.ledger.service import (
    LedgerEntry,
    LedgerVerification,
    event_ledger,
)

router = APIRouter(prefix="/api/v1")
honeypot_service = HoneypotService(event_store)


@router.get("/decoys", response_model=list[DecoyAsset], tags=["Honeypot"])
async def list_decoys():
    return honeypot_service.list_decoys()


@router.get(
    "/decoys/{decoy_id}",
    response_model=DecoyAsset,
    tags=["Honeypot"],
)
async def get_decoy(decoy_id: str):
    return honeypot_service.get_decoy(decoy_id)


@router.post(
    "/decoys/{decoy_id}/interactions",
    response_model=HoneypotEvent,
    status_code=201,
    tags=["Honeypot"],
)
async def record_interaction(
    decoy_id: str,
    request: InteractionRequest,
):
    return honeypot_service.record_interaction(decoy_id, request)


@router.get(
    "/events",
    response_model=list[HoneypotEvent],
    tags=["Honeypot"],
)
async def list_events(limit: int = Query(default=50, ge=1, le=200)):
    return list(reversed(event_store.list_events()[-limit:]))


@router.get(
    "/events/{event_id}",
    response_model=HoneypotEvent,
    tags=["Honeypot"],
)
async def get_event(event_id: str):
    event = event_store.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get(
    "/intelligence/fingerprints",
    response_model=list[BehavioralFingerprint],
    tags=["Threat Intelligence"],
)
async def list_fingerprints():
    return intelligence_service.analyze_all()


@router.get(
    "/intelligence/fingerprints/{actor_id}",
    response_model=BehavioralFingerprint,
    tags=["Threat Intelligence"],
)
async def get_fingerprint(actor_id: str):
    fingerprint = intelligence_service.analyze_actor(actor_id)
    if fingerprint is None:
        raise HTTPException(
            status_code=404,
            detail="No recorded events found for this actor",
        )
    return fingerprint


@router.get(
    "/intelligence/ml/{actor_id}",
    response_model=MLBehaviorAssessment,
    tags=["Machine Learning"],
)
async def assess_actor_with_ml(actor_id: str):
    return ml_intelligence_service.analyze_actor(actor_id)


@router.get(
    "/adaptation/{actor_id}",
    response_model=AdaptationDecision,
    tags=["Adaptive Honeypot"],
)
async def get_adaptation_decision(actor_id: str):
    return adaptive_honeypot_service.analyze_actor(actor_id)


@router.get(
    "/ledger",
    response_model=list[LedgerEntry],
    tags=["Event Ledger"],
)
async def list_ledger_entries(
    limit: int = Query(default=50, ge=1, le=200),
):
    entries = event_ledger.list_entries()
    return list(reversed(entries[-limit:]))


@router.get(
    "/ledger/verify",
    response_model=LedgerVerification,
    tags=["Event Ledger"],
)
async def verify_ledger():
    return event_ledger.verify_chain()


@router.get(
    "/ledger/integrity",
    tags=["Event Ledger"],
)
async def get_ledger_integrity():
    startup = event_ledger.startup_verification
    current = event_ledger.verify_chain()

    return {
        "startup": startup.model_dump(),
        "current": current.model_dump(),
        "integrity_valid": current.valid,
        "entries_checked": current.entries_checked,
    }


@router.post(
    "/ledger/checkpoint",
    response_model=SignedCheckpoint,
    tags=["Signed Checkpoints"],
)
async def create_ledger_checkpoint():
    verification = event_ledger.verify_chain()

    if not verification.valid:
        raise HTTPException(
            status_code=409,
            detail="Cannot checkpoint an invalid ledger.",
        )

    return checkpoint_service.create_checkpoint()


@router.post(
    "/ledger/checkpoint/verify",
    response_model=CheckpointVerification,
    tags=["Signed Checkpoints"],
)
async def verify_ledger_checkpoint(checkpoint: SignedCheckpoint):
    return checkpoint_service.verify_checkpoint(checkpoint)
