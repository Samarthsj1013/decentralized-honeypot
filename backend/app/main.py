
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from backend.app.api.routes import router as honeypot_router

app = FastAPI(
    title="Decentralized Honeypot Network",
    description=(
        "An experimental cybersecurity platform for honeypot "
        "monitoring, behavioral threat analysis, adaptive defense, "
        "and decentralized threat intelligence."
    ),
    version="0.1.0",
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
