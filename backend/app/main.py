
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router as honeypot_router
from app.events.models import HoneypotEvent
from app.events.store import event_store
from app.ledger.service import event_ledger


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

cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "HONEYPOT_CORS_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Accept", "Content-Type"],
)

app.include_router(honeypot_router)


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
    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "service": "honeypot-backend",
            "version": "0.1.0",
        },
    )
