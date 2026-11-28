
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router as honeypot_router
from app.events.models import HoneypotEvent
from app.events.store import event_store
from app.ledger.service import event_ledger
from app.security import access_control_status, auth_router, authorize_api_request, configured_cors_origins


# The append-only ledger is the durable interaction source. Restore its
# events so fingerprinting and adaptation work after an application restart.
for ledger_entry in event_ledger.list_entries():
    event_store.add_event(
        HoneypotEvent.model_validate(ledger_entry.event_data)
    )

app = FastAPI(
    title="Decentralized Honeypot Network",
    description=(
        "An experimental cybersecurity platform for honeypot "
        "monitoring, behavioral threat analysis, adaptive defense, "
        "and decentralized threat intelligence."
    ),
    version="0.1.0",
)

cors_origins = configured_cors_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Accept", "Authorization", "Content-Type", "X-CSRF-Token"],
)


@app.middleware("http")
async def api_access_control(request, call_next):
    return await authorize_api_request(request, call_next)

app.include_router(honeypot_router)
app.include_router(auth_router)


@app.get("/", tags=["General"])
async def root() -> dict[str, str]:
    return {
        "project": "Decentralized AI Self-Evolving Honeypot Network",
        "status": "running",
        "version": "0.1.0",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health_check() -> JSONResponse:
    ledger_result = event_ledger.verify_persisted_chain()
    ledger_database = "unavailable" if ledger_result.message == "Persisted ledger entries could not be loaded." else "connected"
    profile_model = os.getenv("HONEYPOT_PROFILE_MODEL_PATH") or str(
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "experiments", "results", "attacker_profile_models.joblib")
    )
    environment = os.getenv("HONEYPOT_ENV", "development").strip().casefold()
    api_access_control = access_control_status(
        environment,
        os.getenv("HONEYPOT_API_READ_TOKEN", ""),
        os.getenv("HONEYPOT_API_ADMIN_TOKEN", ""),
    )
    telemetry_token = os.getenv("HONEYPOT_TELEMETRY_INGEST_TOKEN", "")
    core_available = ledger_database == "connected" and ledger_result.valid
    return JSONResponse(
        status_code=200 if core_available else 503,
        content={
            "status": "healthy" if core_available else "degraded",
            "service": "honeypot-backend",
            "version": "0.1.0",
            "components": {
                "backend": "healthy",
                "ledger_database": ledger_database,
                "ledger_integrity": "valid" if ledger_result.valid else "invalid",
                "ledger_entries_checked": ledger_result.entries_checked,
                "profile_model": "available" if os.path.isfile(profile_model) else "not_configured",
                "telemetry_ingestion": "configured" if len(telemetry_token) >= 32 else "not_configured",
                "api_access_control": api_access_control,
                "external_adapters": "not_probed",
            },
            "warnings": [
                "External Zeek, Suricata, and Cowrie processes are not probed by this API."
            ],
        },
    )
