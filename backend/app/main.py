
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(
    title="Decentralized Honeypot Network",
    description=(
        "An experimental cybersecurity platform for honeypot "
        "monitoring, behavioral threat analysis, adaptive defense, "
        "and decentralized threat intelligence."
    ),
    version="0.1.0",
)


@app.get("/", tags=["General"])
async def root() -> dict[str, str]:
    """Return basic information about the API."""
    return {
        "project": "Decentralized AI Self-Evolving Honeypot Network",
        "status": "running",
        "version": "0.1.0",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health_check() -> JSONResponse:
    """Report whether the API process is responding."""
    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "service": "honeypot-backend",
            "version": "0.1.0",
        },
    )
