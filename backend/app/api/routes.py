from fastapi import APIRouter, HTTPException, Query

from app.adaptation.service import (
    AdaptationDecision,
    adaptive_honeypot_service,
)
from app.analytics.service import AnalyticsService
from app.events.models import (
    DecoyAsset,
    HoneypotEvent,
    InteractionRequest,
)
from app.events.store import event_store
from app.evaluation.models import EvaluationRequest, EvaluationSummary
from app.evaluation.service import EvaluationService
from app.evaluation.storage import SQLiteEvaluationStorage
from app.honeypot.generator import (
    BehaviorConditionedDecoyGenerator,
    GeneratedDecoy,
)
from app.honeypot.interaction import InteractionWorkflow
from app.honeypot.registry import generated_decoy_registry
from app.honeypot.service import HoneypotService
from app.intelligence.ml_service import (
    MLBehaviorAssessment,
    ml_intelligence_service,
)
from app.intelligence.service import (
    BehavioralFingerprint,
    intelligence_service,
)
from app.ledger.checkpoint import (
    CheckpointVerification,
    SignedCheckpoint,
    checkpoint_service,
)
from app.ledger.service import (
    LedgerEntry,
    LedgerVerification,
    event_ledger,
)
from app.simulation.models import (
    SimulationRunRequest,
    SimulationRunSummary,
    SimulationScenario,
)
from app.simulation.service import AttackSimulationService
from app.simulation.storage import SQLiteSimulationStorage

router = APIRouter(prefix="/api/v1")

honeypot_service = HoneypotService(
    store=event_store,
    ledger=event_ledger,
    registry=generated_decoy_registry,
)

decoy_generator = BehaviorConditionedDecoyGenerator()

analytics_service = AnalyticsService(
    store=event_store,
    history_storage=adaptive_honeypot_service._history_storage,
)

interaction_workflow = InteractionWorkflow(
    honeypot=honeypot_service,
    intelligence=intelligence_service,
    adaptation=adaptive_honeypot_service,
    generator=decoy_generator,
    registry=generated_decoy_registry,
)

attack_simulation_service = AttackSimulationService(
    workflow=interaction_workflow,
    honeypot=honeypot_service,
    event_store=event_store,
    intelligence=intelligence_service,
    adaptation=adaptive_honeypot_service,
    registry=generated_decoy_registry,
    storage=SQLiteSimulationStorage(),
)

evaluation_service = EvaluationService(
    simulations=attack_simulation_service,
    storage=SQLiteEvaluationStorage(),
)


# ---------------------------------------------------------------------
# Honeypot
# ---------------------------------------------------------------------

@router.get(
    "/decoys",
    response_model=list[DecoyAsset],
    tags=["Honeypot"],
)
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
    return interaction_workflow.record_interaction(decoy_id, request)


@router.get(
    "/simulation/scenarios",
    response_model=list[SimulationScenario],
    tags=["Attack Simulation"],
)
async def list_simulation_scenarios():
    return attack_simulation_service.list_scenarios()


@router.post(
    "/simulation/runs",
    response_model=SimulationRunSummary,
    status_code=201,
    tags=["Attack Simulation"],
)
async def run_simulation(request: SimulationRunRequest):
    return attack_simulation_service.run(request)


@router.get(
    "/simulation/runs/{simulation_id}",
    response_model=SimulationRunSummary,
    tags=["Attack Simulation"],
)
async def get_simulation_run(simulation_id: str):
    return attack_simulation_service.get_run(simulation_id)


@router.post(
    "/evaluations",
    response_model=EvaluationSummary,
    status_code=201,
    tags=["Simulation Evaluation"],
)
def run_evaluation(request: EvaluationRequest):
    return evaluation_service.run(request)


@router.get(
    "/evaluations/{evaluation_id}",
    response_model=EvaluationSummary,
    tags=["Simulation Evaluation"],
)
def get_evaluation(evaluation_id: str):
    return evaluation_service.get_evaluation(evaluation_id)


# ---------------------------------------------------------------------
# Behavior-conditioned decoy generation
# ---------------------------------------------------------------------

@router.post(
    "/decoys/generate/{actor_id}",
    response_model=list[GeneratedDecoy],
    status_code=200,
    tags=["Adaptive Honeypot"],
)
async def generate_actor_decoys(
    actor_id: str,
    limit: int = Query(default=3, ge=1, le=10),
):
    fingerprint = intelligence_service.analyze_actor(actor_id)

    if fingerprint is None:
        raise HTTPException(
            status_code=404,
            detail="No recorded events found for this actor",
        )

    decoys = decoy_generator.generate(
        fingerprint=fingerprint,
        limit=limit,
    )

    saved_decoys = generated_decoy_registry.save_many(decoys)
    honeypot_service.register_generated_decoys(saved_decoys)

    return saved_decoys


# ---------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------

@router.get(
    "/events",
    response_model=list[HoneypotEvent],
    tags=["Honeypot"],
)
async def list_events(
    limit: int = Query(default=50, ge=1, le=200),
):
    return list(reversed(event_store.list_events()[-limit:]))


@router.get(
    "/events/{event_id}",
    response_model=HoneypotEvent,
    tags=["Honeypot"],
)
async def get_event(event_id: str):
    event = event_store.get_event(event_id)

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Event not found",
        )

    return event


# ---------------------------------------------------------------------
# Behavioral threat intelligence
# ---------------------------------------------------------------------

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


# ---------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------

@router.get(
    "/analytics/summary",
    tags=["Analytics"],
)
async def get_analytics_summary(
    recent_limit: int = Query(default=10, ge=1, le=100),
):
    return analytics_service.get_summary(
        recent_limit=recent_limit,
    )


# ---------------------------------------------------------------------
# Machine learning
# ---------------------------------------------------------------------

@router.get(
    "/intelligence/ml/{actor_id}",
    response_model=MLBehaviorAssessment,
    tags=["Machine Learning"],
)
async def assess_actor_with_ml(actor_id: str):
    return ml_intelligence_service.analyze_actor(actor_id)


# ---------------------------------------------------------------------
# Adaptive honeypot
# ---------------------------------------------------------------------

@router.get(
    "/adaptation/{actor_id}",
    response_model=AdaptationDecision,
    tags=["Adaptive Honeypot"],
)
async def get_adaptation_decision(actor_id: str):
    return adaptive_honeypot_service.analyze_actor(actor_id)


@router.get(
    "/adaptation/{actor_id}/history",
    tags=["Adaptive Honeypot"],
)
async def get_adaptation_history(
    actor_id: str,
    limit: int = Query(default=50, ge=1, le=200),
):
    return adaptive_honeypot_service.get_decision_history(
        actor_id=actor_id,
        limit=limit,
    )


# ---------------------------------------------------------------------
# Event ledger
# ---------------------------------------------------------------------

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


# ---------------------------------------------------------------------
# Signed checkpoints
# ---------------------------------------------------------------------

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
async def verify_ledger_checkpoint(
    checkpoint: SignedCheckpoint,
):
    return checkpoint_service.verify_checkpoint(checkpoint)
