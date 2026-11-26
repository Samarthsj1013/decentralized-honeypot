"""Small, read-only ASGI application for the public placement demonstration.

This entry point deliberately does not import the operational application,
its database stores, checkpoint-key manager, telemetry ingestion, or ML code.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import asynccontextmanager
from datetime import date, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field


FIXTURE_PATH = Path(__file__).with_name("public_demo_data.json")
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ALLOWED_PATHS = {"/healthz", "/api/v1/public-demo"}
FORBIDDEN_DB_NAMES = {
    "event_ledger.sqlite3", "generated_decoys.sqlite3", "incidents.sqlite3",
    "attacker_profiles.sqlite3", "simulation_runs.sqlite3", "evaluation_runs.sqlite3",
    "experiments.sqlite3", "strategy_sharing.sqlite3",
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Overview(StrictModel):
    telemetry_events: int = Field(ge=0)
    cowrie_successful_logins: int = Field(ge=0)
    cowrie_session_events: int = Field(ge=0)
    cowrie_failed_logins: int = Field(ge=0)
    cowrie_command_attempts: int = Field(ge=0)
    alerts: int = Field(ge=0)
    incidents: int = Field(ge=0)
    profiles: int = Field(ge=0)
    recommendations: int = Field(ge=0)


class TelemetryRow(StrictModel):
    timestamp: datetime
    source_system: str = Field(min_length=1, max_length=32)
    event_type: str = Field(min_length=1, max_length=64)
    severity: Literal["low", "medium", "high", "critical"]
    summary: str = Field(min_length=1, max_length=240)


class AlertRow(StrictModel):
    timestamp: datetime
    source_system: str = Field(min_length=1, max_length=32)
    severity: Literal["low", "medium", "high", "critical"]
    rule: str = Field(min_length=1, max_length=64)
    summary: str = Field(min_length=1, max_length=240)


class CowrieRow(StrictModel):
    timestamp: datetime
    event_type: str = Field(min_length=1, max_length=64)
    summary: str = Field(min_length=1, max_length=240)


class CowrieActivity(StrictModel):
    successful_logins: int = Field(ge=0)
    session_events: int = Field(ge=0)
    failed_logins: int = Field(ge=0)
    command_attempts: int = Field(ge=0)
    events: list[CowrieRow] = Field(max_length=30)


class IncidentRow(StrictModel):
    severity: Literal["low", "medium", "high", "critical"]
    status: Literal["open", "acknowledged", "resolved"]
    confidence: float = Field(ge=0, le=1)
    observed_at: datetime
    rules: list[str] = Field(max_length=8)
    sensors: list[str] = Field(max_length=8)
    evidence: list[str] = Field(max_length=8)


class ProfileRow(StrictModel):
    classification: Literal[
        "reconnaissance", "authentication_probing", "repeated_connection",
        "suspicious_session", "multi_protocol", "unknown",
    ]
    observations: int = Field(ge=1)
    anomaly_index: float = Field(ge=0, le=1)
    cluster: int = Field(ge=0)
    model_version: str = Field(min_length=1, max_length=64)
    provenance: str = Field(min_length=1, max_length=160)
    basis: str = Field(min_length=1, max_length=240)


class EvaluationRow(StrictModel):
    outcome: Literal["passed", "failed"]
    kind: Literal["isolated_synthetic_workflow_validation"]
    interactions_recorded: int = Field(ge=0)
    interactions_attempted: int = Field(ge=0)
    generated_decoys: int = Field(ge=0)
    elapsed_ms: float = Field(ge=0)
    observed_at: date
    provenance: str = Field(min_length=1, max_length=160)


class RecommendationRow(StrictModel):
    status: Literal["pending", "evaluated", "evaluation_failed", "approved"]
    category: str = Field(min_length=1, max_length=64)
    strategy: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=120)
    summary: str = Field(min_length=1, max_length=240)
    evaluation: EvaluationRow | None = None


class IntelligenceSummary(StrictModel):
    exchange_available_in_prototype: bool
    public_demo_peer_state: Literal["not_connected"]
    note: str = Field(min_length=1, max_length=300)


class DemoSnapshot(StrictModel):
    schema_version: Literal[1]
    label: Literal["Placement Demonstration — Synthetic Security Data"]
    notice: str = Field(min_length=1, max_length=400)
    updated_at: datetime
    overview: Overview
    telemetry: list[TelemetryRow] = Field(max_length=30)
    alerts: list[AlertRow] = Field(max_length=30)
    cowrie: CowrieActivity
    incidents: list[IncidentRow] = Field(max_length=20)
    profiles: list[ProfileRow] = Field(max_length=20)
    recommendations: list[RecommendationRow] = Field(max_length=20)
    intelligence: IntelligenceSummary


def _database_path(explicit_path: str | Path | None = None) -> Path:
    configured_from_app_config = explicit_path is None
    configured = explicit_path or os.getenv("HONEYPOT_DEMO_DB_PATH") or (
        Path(tempfile.gettempdir()) / "honeypot-placement-demo" / "demo.sqlite3"
    )
    path = Path(configured).expanduser().resolve()
    try:
        path.relative_to(REPOSITORY_ROOT)
    except ValueError:
        pass
    else:
        raise RuntimeError("Public demo SQLite storage must be outside the project checkout")
    if configured_from_app_config:
        try:
            path.relative_to(Path(tempfile.gettempdir()).resolve())
        except ValueError as exc:
            raise RuntimeError("Configured public demo SQLite storage must use the ephemeral temp directory") from exc
    if path.name.casefold() in FORBIDDEN_DB_NAMES or path.suffix.casefold() not in {".sqlite", ".sqlite3"}:
        raise RuntimeError("Public demo storage path is invalid")
    return path


def _origins(explicit_origins: list[str] | None = None) -> set[str]:
    raw = explicit_origins
    if raw is None:
        raw = [value.strip() for value in os.getenv("HONEYPOT_CORS_ORIGINS", "").split(",") if value.strip()]
    output: set[str] = set()
    production = os.getenv("HONEYPOT_ENV", "development").strip().casefold() == "production"
    if production and not raw:
        raise RuntimeError("HONEYPOT_CORS_ORIGINS must contain the exact Vercel origin in production")
    for origin in raw:
        parsed = urlsplit(origin)
        if (
            origin == "*" or parsed.scheme not in {"http", "https"} or not parsed.netloc
            or parsed.username or parsed.password or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment or (production and parsed.scheme != "https")
        ):
            raise RuntimeError("Public demo CORS origins must be exact HTTP(S) origins")
        output.add(origin.rstrip("/"))
    return output


def _load_fixture(path: Path = FIXTURE_PATH) -> DemoSnapshot:
    try:
        return DemoSnapshot.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError("Public demo fixture is invalid") from exc


def _canonical(snapshot: DemoSnapshot) -> str:
    return json.dumps(snapshot.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _initialize_store(path: Path, fixture: DemoSnapshot) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _canonical(fixture)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    with sqlite3.connect(path, timeout=10) as db:
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("CREATE TABLE IF NOT EXISTS public_demo_snapshot (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, payload TEXT NOT NULL, digest TEXT NOT NULL)")
        db.execute(
            "INSERT INTO public_demo_snapshot(singleton,schema_version,payload,digest) VALUES(1,?,?,?) "
            "ON CONFLICT(singleton) DO UPDATE SET schema_version=excluded.schema_version,payload=excluded.payload,digest=excluded.digest "
            "WHERE public_demo_snapshot.schema_version != excluded.schema_version",
            (fixture.schema_version, payload, digest),
        )
        row = db.execute("SELECT schema_version,payload,digest FROM public_demo_snapshot WHERE singleton=1").fetchone()
    if row is None or row[0] != fixture.schema_version or hashlib.sha256(row[1].encode("utf-8")).hexdigest() != row[2]:
        raise RuntimeError("Public demo SQLite snapshot failed integrity validation")
    try:
        DemoSnapshot.model_validate_json(row[1])
    except Exception as exc:
        raise RuntimeError("Public demo SQLite snapshot failed schema validation") from exc


def _read_store(path: Path) -> dict:
    uri = f"file:{path.as_posix()}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=5) as db:
            row = db.execute("SELECT schema_version,payload,digest FROM public_demo_snapshot WHERE singleton=1").fetchone()
    except sqlite3.Error as exc:
        raise RuntimeError("Public demo snapshot is temporarily unavailable") from exc
    if row is None or row[0] != 1 or hashlib.sha256(row[1].encode("utf-8")).hexdigest() != row[2]:
        raise RuntimeError("Public demo snapshot integrity check failed")
    try:
        return DemoSnapshot.model_validate_json(row[1]).model_dump(mode="json")
    except Exception as exc:
        raise RuntimeError("Public demo snapshot schema check failed") from exc


def create_app(database_path: str | Path | None = None, *, cors_origins: list[str] | None = None, fixture_path: Path = FIXTURE_PATH) -> FastAPI:
    db_path = _database_path(database_path)
    allowed_origins = _origins(cors_origins)
    fixture = _load_fixture(fixture_path)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            _initialize_store(db_path, fixture)
            _app.state.demo_ready = True
        except (RuntimeError, sqlite3.Error):
            _app.state.demo_ready = False
        yield

    app = FastAPI(
        title="Public Honeypot Placement Demo",
        version="1.0.0-demo",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.demo_database_path = db_path

    @app.middleware("http")
    async def public_read_only_allowlist(request: Request, call_next):
        if request.method != "GET":
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        if request.url.path not in ALLOWED_PATHS or request.url.query:
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") not in allowed_origins:
            return JSONResponse(status_code=403, content={"detail": "Origin is not allowed"})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "public, max-age=60"
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin.rstrip("/")
            response.headers["Vary"] = "Origin"
        return response

    @app.get("/healthz")
    async def healthz(request: Request):
        if not request.app.state.demo_ready:
            return JSONResponse(status_code=503, content={"status": "unavailable", "service": "honeypot-placement-demo"})
        return {"status": "ok", "service": "honeypot-placement-demo"}

    @app.get("/api/v1/public-demo", response_model=DemoSnapshot)
    async def public_demo_snapshot(request: Request):
        if not request.app.state.demo_ready:
            return JSONResponse(status_code=503, content={"detail": "Demo data is temporarily unavailable"})
        try:
            return _read_store(db_path)
        except RuntimeError:
            return JSONResponse(status_code=503, content={"detail": "Demo data is temporarily unavailable"})

    return app


app = create_app()
