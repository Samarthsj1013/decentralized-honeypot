"""Environment-configured bearer-token checks for the local API."""

from __future__ import annotations

import hmac
import json
import os
import secrets
import time
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError

MIN_API_TOKEN_LENGTH = 32
READ_METHODS = {"GET", "HEAD"}
TELEMETRY_INGEST_PATH = "/api/v1/telemetry/ingest"
SESSION_COOKIE = "honeypot_admin_session"
SESSION_TTL_SECONDS = 1800
SESSION_PATH = "/api/v1/auth/session"
MAX_SESSION_REQUEST_BYTES = 1024
auth_router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


class SessionLogin(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    admin_token: StrictStr = Field(min_length=MIN_API_TOKEN_LENGTH, max_length=512)


def _session_store(request: Request) -> dict:
    sessions = getattr(request.app.state, "admin_sessions", None)
    if sessions is None:
        sessions = {}
        request.app.state.admin_sessions = sessions
    return sessions


def _active_session(request: Request) -> tuple[str, dict] | None:
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return None
    sessions = _session_store(request)
    now = time.time()
    for old_id, value in list(sessions.items()):
        if value["expires_at"] <= now:
            sessions.pop(old_id, None)
    session = sessions.get(session_id)
    if session is None or session["expires_at"] <= now:
        return None
    return session_id, session


def _request_origin_allowed(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True
    try:
        allowed = configured_cors_origins()
    except RuntimeError:
        return False
    return origin.rstrip("/") in allowed


def validate_cors_origins(origins: list[str], *, production: bool = False) -> list[str]:
    """Reject wildcard or non-origin CORS values before enabling credentialed cookies."""
    if production and not origins:
        raise RuntimeError("HONEYPOT_CORS_ORIGINS must explicitly list HTTPS origins in production")
    for origin in origins:
        parsed = urlsplit(origin)
        if (
            origin == "*" or parsed.scheme not in {"http", "https"} or not parsed.netloc
            or parsed.username or parsed.password or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment
        ):
            raise RuntimeError("HONEYPOT_CORS_ORIGINS must contain exact HTTP(S) origins; wildcard values are not allowed")
        if production and parsed.scheme != "https":
            raise RuntimeError("Production HONEYPOT_CORS_ORIGINS must use HTTPS")
    return origins


def configured_cors_origins() -> list[str]:
    """Return validated configured origins, with loopback defaults only in development."""
    production = os.getenv("HONEYPOT_ENV", "development").strip().casefold() == "production"
    configured = os.getenv("HONEYPOT_CORS_ORIGINS")
    if production and (configured is None or not configured.strip()):
        raise RuntimeError("HONEYPOT_CORS_ORIGINS must explicitly list HTTPS origins in production")
    if configured is None:
        configured = "" if production else "http://127.0.0.1:5173,http://localhost:5173"
    origins = [origin.strip() for origin in configured.split(",") if origin.strip()]
    return validate_cors_origins(origins, production=production)


def _secure_cookie() -> bool:
    secure = os.getenv("HONEYPOT_SESSION_COOKIE_SECURE", "false").strip().casefold() == "true"
    if os.getenv("HONEYPOT_ENV", "development").strip().casefold() == "production" and not secure:
        raise HTTPException(503, "Secure session cookies must be enabled in production")
    return secure


@auth_router.post("/session")
async def create_admin_session(request: Request, response: Response) -> dict:
    if not _request_origin_allowed(request):
        raise HTTPException(403, "Request origin is not allowed")
    environment = os.getenv("HONEYPOT_ENV", "development").strip().casefold()
    if environment not in {"development", "production"}:
        raise HTTPException(503, "Invalid HONEYPOT_ENV configuration")
    _secure_cookie()
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_SESSION_REQUEST_BYTES:
                raise HTTPException(413, "Session request is too large")
        except ValueError:
            raise HTTPException(400, "Invalid Content-Length header") from None
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_SESSION_REQUEST_BYTES:
            raise HTTPException(413, "Session request is too large")
    try:
        payload = SessionLogin.model_validate_json(bytes(body))
    except ValidationError:
        raise HTTPException(422, "Session request is invalid") from None
    _read_token, admin_token = _configured_tokens()
    if not admin_token or not _valid_config(*_configured_tokens()):
        raise HTTPException(503, "A valid administrative API token must be configured")

    attempts = getattr(request.app.state, "admin_login_attempts", None)
    if attempts is None:
        attempts = {}
        request.app.state.admin_login_attempts = attempts
    now = time.time()
    remote = request.client.host if request.client else "unknown"
    for address, values in list(attempts.items()):
        recent = [stamp for stamp in values if stamp > now - 900]
        if recent:
            attempts[address] = recent
        else:
            attempts.pop(address, None)
    recent = attempts.get(remote, [])
    if len(recent) >= 5:
        raise HTTPException(429, "Too many login attempts; retry after 15 minutes")
    if not hmac.compare_digest(payload.admin_token, admin_token):
        attempts[remote] = [*recent, now]
        if len(attempts) > 2048:
            attempts.pop(next(iter(attempts)))
        raise HTTPException(401, "Administrative authentication failed")

    attempts.pop(remote, None)
    sessions = _session_store(request)
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    sessions[session_id] = {"csrf_token": csrf_token, "expires_at": now + SESSION_TTL_SECONDS, "role": "admin"}
    if len(sessions) > 4096:
        for old_id, value in sorted(sessions.items(), key=lambda item: item[1]["expires_at"]):
            sessions.pop(old_id, None)
            if len(sessions) <= 3072:
                break
    response.set_cookie(
        SESSION_COOKIE, session_id, max_age=SESSION_TTL_SECONDS, httponly=True,
        secure=_secure_cookie(), samesite="strict", path="/api/v1",
    )
    return {"authenticated": True, "role": "admin", "csrf_token": csrf_token, "expires_in": SESSION_TTL_SECONDS}


@auth_router.get("/session")
async def inspect_admin_session(request: Request) -> dict:
    session = _active_session(request)
    if session is None:
        read_token, admin_token = _configured_tokens()
        if (
            os.getenv("HONEYPOT_ENV", "development").strip().casefold() == "development"
            and not read_token and not admin_token
        ):
            return {"authenticated": True, "role": "development", "csrf_token": "", "expires_in": 0}
        raise HTTPException(401, "Administrative session is not active")
    return {"authenticated": True, "role": session[1]["role"], "csrf_token": session[1]["csrf_token"], "expires_in": max(0, int(session[1]["expires_at"] - time.time()))}


@auth_router.delete("/session")
async def delete_admin_session(request: Request, response: Response) -> dict:
    session = _active_session(request)
    if session is not None:
        _session_store(request).pop(session[0], None)
    response.delete_cookie(SESSION_COOKIE, path="/api/v1", httponly=True, secure=_secure_cookie(), samesite="strict")
    return {"authenticated": False}


def _configured_tokens() -> tuple[str, str]:
    return (
        os.getenv("HONEYPOT_API_READ_TOKEN", ""),
        os.getenv("HONEYPOT_API_ADMIN_TOKEN", ""),
    )


def _valid_config(read_token: str, admin_token: str) -> bool:
    tokens_are_long_enough = all(
        not value or len(value) >= MIN_API_TOKEN_LENGTH
        for value in (read_token, admin_token)
    )
    roles_are_distinct = not (
        read_token and admin_token and hmac.compare_digest(read_token, admin_token)
    )
    return tokens_are_long_enough and roles_are_distinct


def access_control_status(environment: str, read_token: str, admin_token: str) -> str:
    """Describe configuration quality without exposing credential values."""
    if environment not in {"development", "production"}:
        return "invalid_environment"
    if not read_token and not admin_token:
        return "production_missing_tokens" if environment == "production" else "development_open"
    if not _valid_config(read_token, admin_token):
        return "invalid_token_configuration"
    if read_token and not admin_token:
        return "reader_only"
    return "configured"


async def authorize_api_request(request: Request, call_next):
    """Require reader credentials for safe methods and admin for mutations.

    No tokens configured means local development mode. Telemetry ingestion is
    excluded because its endpoint independently requires its dedicated token.
    """
    if (
        not request.url.path.startswith("/api/v1/")
        or request.url.path == TELEMETRY_INGEST_PATH
        or (request.url.path == SESSION_PATH and request.method == "POST")
        or request.method == "OPTIONS"
    ):
        return await call_next(request)

    environment = os.getenv("HONEYPOT_ENV", "development").strip().casefold()
    if environment not in {"development", "production"}:
        return JSONResponse(status_code=503, content={"detail": "Invalid HONEYPOT_ENV configuration"})

    read_token, admin_token = _configured_tokens()
    if not read_token and not admin_token:
        if environment == "development":
            return await call_next(request)
        return JSONResponse(status_code=503, content={"detail": "API access tokens must be configured in production"})
    if not _valid_config(read_token, admin_token):
        return JSONResponse(
            status_code=503,
            content={
                "detail": "Invalid token configuration; tokens must be distinct and contain at least 32 characters"
            },
        )

    authorization = request.headers.get("authorization", "")
    scheme, _, supplied = authorization.partition(" ")
    is_admin = scheme.casefold() == "bearer" and bool(admin_token) and hmac.compare_digest(supplied, admin_token)
    if is_admin:
        return await call_next(request)

    session = _active_session(request)
    if session is not None:
        if request.method not in READ_METHODS:
            supplied_csrf = request.headers.get("x-csrf-token", "")
            if not supplied_csrf or not hmac.compare_digest(supplied_csrf, session[1]["csrf_token"]):
                return JSONResponse(status_code=403, content={"detail": "Valid CSRF token required for session-authenticated mutations"})
        request.state.auth_role = session[1]["role"]
        return await call_next(request)

    is_reader = scheme.casefold() == "bearer" and bool(read_token) and hmac.compare_digest(supplied, read_token)
    if is_reader and request.method in READ_METHODS:
        return await call_next(request)
    if is_reader:
        return JSONResponse(status_code=403, content={"detail": "Administrative bearer token required"})
    return JSONResponse(
        status_code=401,
        content={"detail": "API bearer token required"},
        headers={"WWW-Authenticate": "Bearer"},
    )
