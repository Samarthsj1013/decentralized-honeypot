import asyncio
import hmac
import json
import os
from urllib.parse import urlsplit

import httpx

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import IPvAnyAddress, ValidationError

from app.adaptation.service import (
    AdaptationDecision,
    adaptive_honeypot_service,
)
from app.analytics.service import AnalyticsService
from app.events.models import (
    DecoyAsset,
    HoneypotEvent,
    InteractionRequest,
    TelemetryIngestRequest,
)
from app.events.store import event_store
from app.experiments.models import ExperimentRequest, ExperimentResult
from app.experiments.service import ExperimentService
from app.experiments.storage import ExperimentStorage
from app.evaluation.models import EvaluationRequest, EvaluationSummary
from app.evaluation.service import EvaluationService
from app.evaluation.storage import SQLiteEvaluationStorage
from app.honeypot.generator import (
    BehaviorConditionedDecoyGenerator,
    GeneratedDecoy,
)
from app.honeypot.interaction import InteractionWorkflow
from app.honeypot.bundle_generator import BehaviorConditionedBundleGenerator
from app.honeypot.bundles import (
    BundleConsistencyValidator, BundleGenerationResponse, BundleValidationResult,
    SyntheticDecoyBundle,
)
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
from app.intelligence.fingerprint_schema import (
    BehavioralFingerprintVectorizer,
    FingerprintSchemaError,
    FingerprintShareResponse,
    canonical_serialize_export,
    contract_from_operational,
    export_digest,
    fingerprint_schema_metadata,
    to_shareable_export,
    validate_fingerprint_payload,
)
from app.incidents.models import Incident, IncidentPage, IncidentStats
from app.incidents.service import IncidentService
from app.incidents.storage import SQLiteIncidentStorage
from app.profiling.models import (
    AttackerBehaviorProfile,
    DeceptionRecommendation,
    ProfileList,
    ProfileRecomputeRequest,
    ProfileRecomputeResponse,
    ProfileStats,
    RecommendationList,
)
from app.profiling.service import AttackerProfileService
from app.profiling.storage import SQLiteProfileStorage
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
from app.strategy_sharing import (
    ImportResponse,
    StrategyShareRecord,
    strategy_sharing_service,
)
from app.telemetry.alerts import TelemetryAlertService
from app.telemetry.live import LiveUpdateHub
from app.telemetry.models import CowrieEventSummary, TelemetryAlert, TelemetryIngestResponse, cowrie_summary, live_summary
from app.telemetry.service import MAX_TELEMETRY_BODY_BYTES, TelemetryIngestionService

router = APIRouter(prefix="/api/v1")


async def _evaluate_intelligence_collection(event: HoneypotEvent) -> dict:
    """Optionally send only the approved event identity projection to a local node collector."""
    base_url = os.getenv("HONEYPOT_INTEL_COLLECTOR_URL", "").strip().rstrip("/")
    token = os.getenv("HONEYPOT_INTEL_COLLECTOR_TOKEN", "")
    if not base_url and not token:
        return {"status": "disabled"}
    parsed = urlsplit(base_url)
    if (
        not base_url or len(token) < 32 or parsed.scheme not in {"http", "https"}
        or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment
    ):
        return {"status": "misconfigured"}
    if event.source != "external" or not event.sensor_id or not event.source_event_id or not event.source_ip:
        return {"status": "not_eligible"}
    projection = {
        "source_system": event.source_system or "generic",
        "sensor_id": event.sensor_id,
        "external_event_id": event.source_event_id,
        "occurred_at": event.timestamp.isoformat(),
        "event_type": event.telemetry_event_type or event.action,
        "severity": event.severity,
        "source_ip": event.source_ip,
    }
    try:
        async with httpx.AsyncClient(timeout=3.0, follow_redirects=False) as client:
            response = await client.post(
                f"{base_url}/v1/intelligence/observe", json=projection,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            )
        if response.status_code != 200 or len(response.content) > 16 * 1024:
            return {"status": "unavailable"}
        result = response.json()
        if not isinstance(result, dict):
            return {"status": "unavailable"}
        allowed = {"eligible", "reason", "observation_count", "required_observations", "record_id"}
        return {
            "status": "evaluated", "outcome": result.get("status"),
            **{key: result[key] for key in allowed if key in result},
        }
    except (httpx.HTTPError, ValueError):
        return {"status": "unavailable"}


@router.get("/network-node/dashboard", tags=["Network Operations"])
async def network_node_dashboard():
    """Proxy the separately configured local node summary without browser credentials."""
    base_url = os.getenv("HONEYPOT_NODE_DASHBOARD_URL", "").strip().rstrip("/")
    token = os.getenv("HONEYPOT_NODE_DASHBOARD_TOKEN", "")
    if not base_url or len(token) < 32:
        raise HTTPException(503, "Network node dashboard is not configured on the backend")
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HTTPException(503, "Network node dashboard URL configuration is invalid")
    try:
        async with httpx.AsyncClient(timeout=3.0, follow_redirects=False) as client:
            result = await client.get(
                f"{base_url}/v1/dashboard/summary",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            )
        if result.status_code != 200 or len(result.content) > 256 * 1024:
            raise HTTPException(503, "Configured network node dashboard is unavailable")
        payload = result.json()
        if not isinstance(payload, dict):
            raise HTTPException(503, "Configured network node returned an invalid summary")
        return payload
    except HTTPException:
        raise
    except (httpx.HTTPError, ValueError):
        raise HTTPException(503, "Configured network node dashboard is unavailable") from None

honeypot_service = HoneypotService(
    store=event_store,
    ledger=event_ledger,
    registry=generated_decoy_registry,
)

decoy_generator = BehaviorConditionedDecoyGenerator()
bundle_generator = BehaviorConditionedBundleGenerator()
bundle_validator = BundleConsistencyValidator()
fingerprint_vectorizer = BehavioralFingerprintVectorizer()

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
    bundle_generator=bundle_generator,
    bundle_validator=bundle_validator,
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

telemetry_ingestion_service = TelemetryIngestionService(event_store, event_ledger)
telemetry_alert_service = TelemetryAlertService()
live_update_hub = LiveUpdateHub()
incident_service = IncidentService(SQLiteIncidentStorage())
attacker_profile_service = AttackerProfileService(
    event_store,
    SQLiteProfileStorage(),
    incident_storage=incident_service.storage,
)
experiment_service = ExperimentService(ExperimentStorage())


def _on_event_recorded(event: HoneypotEvent) -> None:
    live_update_hub.publish_event(event)
    alert = telemetry_alert_service.inspect(event)
    if alert is not None:
        live_update_hub.publish_alert(alert)


event_store.subscribe(_on_event_recorded)


def _bearer_token(authorization: str | None) -> str | None:
    if authorization is None:
        return None
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.casefold() != "bearer" or not token or " " in token:
        return None
    return token


def _reject_json_constant(value: str):
    raise ValueError(f"Invalid JSON constant: {value}")


async def _bounded_request_body(request: Request) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_TELEMETRY_BODY_BYTES:
                raise HTTPException(413, "Telemetry request body is too large")
        except ValueError as exc:
            raise HTTPException(400, "Invalid Content-Length header") from exc
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_TELEMETRY_BODY_BYTES:
            raise HTTPException(413, "Telemetry request body is too large")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post(
    "/telemetry/ingest",
    response_model=TelemetryIngestResponse,
    status_code=201,
    tags=["Live Telemetry"],
    summary="Ingest a normalized external telemetry event",
    description=(
        "Requires a configured bearer token. JSON is treated as inert data; "
        "requests are limited to 32 KiB and deduplicated by source, sensor, "
        "and external event ID."
    ),
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": TelemetryIngestRequest.model_json_schema(),
                }
            },
        }
    },
)
async def ingest_telemetry(
    request: Request,
    response: Response,
    authorization: str | None = Header(default=None),
):
    configured_token = os.getenv("HONEYPOT_TELEMETRY_INGEST_TOKEN", "")
    if len(configured_token.encode("utf-8")) < 32:
        raise HTTPException(
            503,
            "External telemetry ingestion requires a configured token of at least 32 bytes",
        )
    supplied_token = _bearer_token(authorization)
    if supplied_token is None or not hmac.compare_digest(
        supplied_token.encode("utf-8"), configured_token.encode("utf-8")
    ):
        raise HTTPException(
            401,
            "A valid telemetry bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_body = await _bounded_request_body(request)
    try:
        payload_data = json.loads(raw_body, parse_constant=_reject_json_constant)
    except (ValueError, RecursionError):
        raise HTTPException(400, "Malformed JSON telemetry document") from None
    if not isinstance(payload_data, dict):
        raise HTTPException(422, "Telemetry payload must be a JSON object")
    try:
        payload = TelemetryIngestRequest.model_validate(payload_data)
    except ValidationError as exc:
        safe_errors = [
            {"loc": error["loc"], "msg": error["msg"], "type": error["type"]}
            for error in exc.errors()
        ]
        raise HTTPException(422, safe_errors) from None

    event, created = telemetry_ingestion_service.ingest(payload)
    try:
        # Re-run correlation for an exact retry as well: this repairs a prior
        # transient incident-store failure after the event itself was ledgered.
        incident = incident_service.inspect(event)
    except Exception:
        raise HTTPException(
            503,
            "Telemetry was recorded, but incident correlation could not be persisted; safely retry this event",
        ) from None
    if incident is not None:
        live_update_hub.publish_incident(incident.incident_id)
    alert = telemetry_alert_service.get_for_event(event.event_id)
    intelligence_collection = await _evaluate_intelligence_collection(event)
    response.status_code = 201 if created else 200
    return TelemetryIngestResponse(
        accepted=True,
        duplicate=not created,
        event=event,
        alert=alert,
        intelligence_collection=intelligence_collection,
    )


@router.get(
    "/telemetry/alerts",
    response_model=list[TelemetryAlert],
    tags=["Live Telemetry"],
)
async def list_telemetry_alerts(limit: int = Query(default=50, ge=1, le=100)):
    return telemetry_alert_service.list_alerts(limit)


@router.get("/telemetry/cowrie/events", response_model=list[CowrieEventSummary], tags=["Live Telemetry"])
async def list_cowrie_events(limit: int = Query(default=30, ge=1, le=100)):
    events = reversed(event_store.list_events())
    summaries = []
    for event in events:
        summary = cowrie_summary(event)
        if summary is not None:
            summaries.append(summary)
            if len(summaries) >= limit:
                break
    return summaries


@router.get("/incidents/stats", response_model=IncidentStats, tags=["Incidents"])
async def get_incident_stats():
    return incident_service.stats()


@router.get("/incidents", response_model=IncidentPage, tags=["Incidents"])
async def list_incidents(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=1000000),
    status: str | None = Query(default=None, pattern="^(open|acknowledged|resolved)$"),
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical)$"),
    source_ip: IPvAnyAddress | None = Query(default=None),
):
    items, total = incident_service.list(limit, offset, status, severity, str(source_ip) if source_ip else None)
    return IncidentPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/incidents/{incident_id}", response_model=Incident, tags=["Incidents"])
async def get_incident(incident_id: str):
    return incident_service.get(incident_id)


@router.post("/incidents/{incident_id}/acknowledge", response_model=Incident, tags=["Incidents"])
async def acknowledge_incident(incident_id: str):
    return incident_service.transition(incident_id, "acknowledged")


@router.post("/incidents/{incident_id}/resolve", response_model=Incident, tags=["Incidents"])
async def resolve_incident(incident_id: str):
    return incident_service.transition(incident_id, "resolved")


# ---------------------------------------------------------------------
# ML attacker profiles and simulation-only deception recommendations
# ---------------------------------------------------------------------

@router.get("/profiles/stats", response_model=ProfileStats, tags=["Behavior Profiles"])
async def get_profile_stats():
    return attacker_profile_service.stats()


@router.get("/profiles", response_model=ProfileList, tags=["Behavior Profiles"])
async def list_behavior_profiles(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=100_000),
):
    items, total = attacker_profile_service.list_profiles(limit, offset)
    return {"items": items, "total": total}


@router.post("/profiles/recompute", response_model=ProfileRecomputeResponse, tags=["Behavior Profiles"])
async def recompute_behavior_profiles(body: ProfileRecomputeRequest = ProfileRecomputeRequest()):
    profiles, recommendations_created = attacker_profile_service.recompute(body.window_seconds)
    return ProfileRecomputeResponse(
        profiles_updated=len(profiles),
        recommendations_created=recommendations_created,
        observation_window_seconds=body.window_seconds,
        model_version=attacker_profile_service.model_version,
        profiles=profiles,
    )


@router.get("/profiles/{profile_id}", response_model=AttackerBehaviorProfile, tags=["Behavior Profiles"])
async def get_behavior_profile(profile_id: str):
    return attacker_profile_service.get_profile(profile_id)


@router.get("/deception/recommendations", response_model=RecommendationList, tags=["Adaptive Deception"])
async def list_deception_recommendations(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
):
    items, total = attacker_profile_service.list_recommendations(limit, offset)
    return {"items": items, "total": total}


@router.post("/deception/recommendations/{recommendation_id}/evaluate", response_model=DeceptionRecommendation, tags=["Adaptive Deception"])
async def evaluate_deception_recommendation(recommendation_id: str):
    return attacker_profile_service.evaluate_recommendation(recommendation_id)


@router.post("/deception/recommendations/{recommendation_id}/approve", response_model=DeceptionRecommendation, tags=["Adaptive Deception"])
async def approve_deception_recommendation(recommendation_id: str):
    return attacker_profile_service.approve_recommendation(recommendation_id)


@router.get(
    "/telemetry/stream",
    tags=["Live Telemetry"],
    summary="Stream recent events and alerts using SSE",
    response_class=StreamingResponse,
)
async def stream_live_updates(
    request: Request,
    after_event_id: str | None = Query(default=None, max_length=80),
):
    async def generate():
        subscriber_id, queue = live_update_hub.subscribe()
        emitted: set[str] = set()
        cursor = request.headers.get("last-event-id") or after_event_id
        if cursor and cursor.startswith("alert-"):
            cursor = "external-" + cursor.removeprefix("alert-")
        try:
            yield "retry: 3000\n\n"
            snapshot = event_store.list_events()
            start_index = -1
            if cursor:
                start_index = next(
                    (index for index, event in enumerate(snapshot) if event.event_id == cursor),
                    max(-1, len(snapshot) - 21),
                )
            else:
                start_index = max(-1, len(snapshot) - 21)
            for event in snapshot[start_index + 1:]:
                message = {
                    "kind": "event",
                    "id": event.event_id,
                    "data": live_summary(event).model_dump(mode="json"),
                }
                emitted.add(f"event:{message['id']}")
                yield live_update_hub.encode(message)
                alert = telemetry_alert_service.get_for_event(event.event_id)
                if alert is not None:
                    alert_message = {
                        "kind": "alert",
                        "id": alert.alert_id,
                        "data": alert.model_dump(mode="json"),
                    }
                    emitted.add(f"alert:{alert.alert_id}")
                    yield live_update_hub.encode(alert_message)
                cowrie = cowrie_summary(event)
                if cowrie is not None:
                    cowrie_message = {"kind": "cowrie", "id": event.event_id, "data": cowrie.model_dump(mode="json")}
                    emitted.add(f"cowrie:{event.event_id}")
                    yield live_update_hub.encode(cowrie_message)

            while not await request.is_disconnected():
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                key = f"{message['kind']}:{message['id']}"
                if key in emitted:
                    continue
                emitted.add(key)
                yield live_update_hub.encode(message)
        finally:
            live_update_hub.unsubscribe(subscriber_id)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/strategy-sharing/exports/{actor_id}", response_model=StrategyShareRecord, tags=["Strategy Sharing"])
async def create_strategy_share(actor_id: str):
    """Create a sanitized signed package with the separately configured org key."""
    import os

    fingerprint = intelligence_service.analyze_actor(actor_id)
    if fingerprint is None:
        raise HTTPException(status_code=404, detail="No recorded events found for this actor")
    decision = adaptive_honeypot_service.preview_actor(actor_id)
    source_bundle = next(
        (bundle for bundle in reversed(generated_decoy_registry.list_bundles(actor_id))
         if bundle.selected_strategy == decision.selected_strategy),
        None,
    )
    if source_bundle is None:
        source_bundle = bundle_generator.generate_bundle(
            fingerprint, decision.selected_strategy, decision.reason
        )
    key_id = os.getenv("HONEYPOT_STRATEGY_SHARING_KEY_ID", "")
    organization_id = os.getenv("HONEYPOT_STRATEGY_SHARING_ORGANIZATION_ID", "")
    exported = to_shareable_export(fingerprint)
    return strategy_sharing_service.create_record(
        organization_id, key_id, decision.selected_strategy, exported, source_bundle
    )


@router.post("/strategy-sharing/imports", response_model=ImportResponse, status_code=201, tags=["Strategy Sharing"])
async def import_strategy_share(payload: dict):
    return strategy_sharing_service.import_record(payload)


@router.get("/strategy-sharing/imports/{record_id}", response_model=ImportResponse, tags=["Strategy Sharing"])
async def get_strategy_share(record_id: str):
    return strategy_sharing_service.get(record_id)


@router.post("/strategy-sharing/imports/{record_id}/evaluate", response_model=ImportResponse, tags=["Strategy Sharing"])
async def evaluate_strategy_share(record_id: str):
    return strategy_sharing_service.evaluate(record_id)


@router.post("/strategy-sharing/imports/{record_id}/activate", response_model=ImportResponse, tags=["Strategy Sharing"])
async def activate_strategy_share(record_id: str):
    return strategy_sharing_service.activate(record_id)


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


@router.post(
    "/bundles/generate/{actor_id}", response_model=BundleGenerationResponse,
    tags=["Adaptive Honeypot"],
)
async def generate_actor_bundle(
    actor_id: str,
    scenario_id: str | None = Query(default=None, max_length=80),
):
    fingerprint = intelligence_service.analyze_actor(actor_id)
    if fingerprint is None:
        raise HTTPException(status_code=404, detail="No recorded events found for this actor")
    decision = adaptive_honeypot_service.preview_actor(actor_id)
    bundle = bundle_generator.generate_bundle(
        fingerprint, decision.selected_strategy, decision.reason, scenario_id
    )
    validation = bundle_validator.validate(bundle)
    if not validation.valid:
        raise HTTPException(status_code=422, detail=validation.model_dump(mode="json"))
    decoys = bundle_generator.to_generated_decoys(bundle)
    created = generated_decoy_registry.save_bundle(bundle, decoys)
    honeypot_service.register_generated_decoys(decoys)
    return BundleGenerationResponse(
        bundle=bundle, validation=validation,
        registered_decoy_ids=[decoy.decoy_id for decoy in decoys], created=created,
    )


@router.get("/bundles/{bundle_id}/validation", response_model=BundleValidationResult, tags=["Adaptive Honeypot"])
async def validate_saved_bundle(bundle_id: str):
    bundle = generated_decoy_registry.get_bundle(bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Decoy bundle not found")
    return bundle_validator.validate(bundle)


@router.get("/bundles/{bundle_id}", response_model=SyntheticDecoyBundle, tags=["Adaptive Honeypot"])
async def get_saved_bundle(bundle_id: str):
    bundle = generated_decoy_registry.get_bundle(bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Decoy bundle not found")
    return bundle


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


# ---------------------------------------------------------------------
# Offline synthetic baseline/adaptive experiments
# ---------------------------------------------------------------------

@router.post("/experiments/run", response_model=ExperimentResult, status_code=201, tags=["Experiments"])
def run_experiment(request: ExperimentRequest):
    return experiment_service.run(request)


@router.get("/experiments", tags=["Experiments"])
def list_experiments(limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0, le=100000)):
    items, total = experiment_service.list(limit, offset)
    summaries = [{"experiment_id": item.experiment_id, "created_at": item.created_at, "seed": item.seed, "scenarios": item.scenarios, "repetitions": item.repetitions, "modes": item.modes, "execution_time_seconds": item.execution_time_seconds} for item in items]
    return {"items": summaries, "total": total, "limit": limit, "offset": offset}


@router.get("/experiments/{experiment_id}", response_model=ExperimentResult, tags=["Experiments"])
def get_experiment(experiment_id: str):
    return experiment_service.get(experiment_id)


@router.get("/experiments/{experiment_id}/results", tags=["Experiments"])
def get_experiment_results(experiment_id: str):
    return experiment_service.get(experiment_id).scenario_results


@router.get("/experiments/{experiment_id}/comparison", tags=["Experiments"])
def get_experiment_comparison(experiment_id: str):
    return experiment_service.get(experiment_id).comparison


@router.get("/experiments/{experiment_id}/report", tags=["Experiments"])
def get_experiment_report(experiment_id: str, format: str = Query(default="json", pattern="^(json|csv|markdown)$")):
    content, media_type = experiment_service.report(experiment_id, format)
    extension = {"json": "json", "csv": "csv", "markdown": "md"}[format]
    return Response(content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="experiment-{experiment_id}.{extension}"'})


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
    "/intelligence/fingerprints/schema",
    tags=["Threat Intelligence"],
)
async def get_fingerprint_schema():
    return fingerprint_schema_metadata()


@router.post(
    "/intelligence/fingerprints/validate",
    tags=["Threat Intelligence"],
)
async def validate_fingerprint(payload: dict):
    try:
        contract, compatibility = validate_fingerprint_payload(payload)
    except FingerprintSchemaError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "message": str(exc),
                "errors": exc.errors,
            },
        ) from exc
    return {
        "valid": True,
        "schema_name": contract.schema_name,
        "schema_version": contract.schema_version,
        "compatibility": compatibility,
    }


@router.get(
    "/intelligence/fingerprints/{actor_id}/export",
    response_model=FingerprintShareResponse,
    tags=["Threat Intelligence"],
)
async def export_actor_fingerprint(actor_id: str):
    fingerprint = intelligence_service.analyze_actor(actor_id)
    if fingerprint is None:
        raise HTTPException(
            status_code=404,
            detail="No recorded events found for this actor",
        )
    # Validate through the adapter while retaining the internal object for policy use.
    contract_from_operational(fingerprint)
    exported = to_shareable_export(fingerprint)
    return FingerprintShareResponse(
        export=exported,
        canonical_json=canonical_serialize_export(exported),
        sha256=export_digest(exported),
    )


@router.get(
    "/intelligence/fingerprints/{actor_id}/vector",
    tags=["Threat Intelligence"],
)
async def vectorize_actor_fingerprint(actor_id: str):
    fingerprint = intelligence_service.analyze_actor(actor_id)
    if fingerprint is None:
        raise HTTPException(
            status_code=404,
            detail="No recorded events found for this actor",
        )
    return fingerprint_vectorizer.vectorize(fingerprint)

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
    return adaptive_honeypot_service.preview_actor(actor_id)


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
