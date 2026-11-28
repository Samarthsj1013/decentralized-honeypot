from fastapi.testclient import TestClient

import pytest

from app.api import routes
from uuid import uuid4
from app.experiments.service import ExperimentService
from app.experiments.storage import ExperimentStorage
from app.ledger.service import LedgerVerification, event_ledger
from app.main import app
from app.security import configured_cors_origins, validate_cors_origins

client = TestClient(app)
READ_TOKEN = "read-only-test-token-that-is-long-enough-123456"
ADMIN_TOKEN = "admin-test-token-that-is-long-enough-1234567"


def test_optional_api_tokens_enforce_read_and_admin_access(tmp_path, monkeypatch):
    monkeypatch.setenv("HONEYPOT_API_READ_TOKEN", READ_TOKEN)
    monkeypatch.setenv("HONEYPOT_API_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.setattr(
        routes,
        "experiment_service",
        ExperimentService(ExperimentStorage(tmp_path / "authenticated-experiments.sqlite3")),
    )

    assert client.get("/api/v1/simulation/scenarios").status_code == 401
    read = client.get(
        "/api/v1/simulation/scenarios",
        headers={"Authorization": f"Bearer {READ_TOKEN}"},
    )
    assert read.status_code == 200
    assert client.post(
        "/api/v1/experiments/run",
        json={"scenarios": ["reconnaissance"], "modes": ["baseline"]},
        headers={"Authorization": f"Bearer {READ_TOKEN}"},
    ).status_code == 403

    admin = client.post(
        "/api/v1/experiments/run",
        json={"experiment_id": "auth-test", "scenarios": ["reconnaissance"], "modes": ["baseline"]},
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert admin.status_code == 201
    assert client.get(
        "/api/v1/experiments/auth-test",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    ).status_code == 200


def test_short_configured_token_fails_closed_and_telemetry_keeps_its_own_auth(monkeypatch):
    monkeypatch.setenv("HONEYPOT_API_READ_TOKEN", "short")
    monkeypatch.delenv("HONEYPOT_API_ADMIN_TOKEN", raising=False)
    assert client.get("/api/v1/simulation/scenarios").status_code == 503

    # The telemetry route remains guarded by its own token contract.
    monkeypatch.setenv("HONEYPOT_TELEMETRY_INGEST_TOKEN", "telemetry-token-for-isolated-test-0123456789")
    body = {
        "source_system": "generic", "sensor_id": "security-test-sensor",
        "external_event_id": "security-test-event-auth-check", "occurred_at": "2026-11-07T00:00:00Z",
        "event_type": "connection", "severity": "low", "attributes": {},
    }
    response = client.post(
        "/api/v1/telemetry/ingest", json=body,
        headers={"Authorization": "Bearer telemetry-token-for-isolated-test-0123456789"},
    )
    assert response.status_code == 201


def test_identical_reader_and_admin_tokens_fail_closed(monkeypatch):
    shared_token = "same-reader-admin-token-value-long-enough-123"
    monkeypatch.setenv("HONEYPOT_API_READ_TOKEN", shared_token)
    monkeypatch.setenv("HONEYPOT_API_ADMIN_TOKEN", shared_token)

    response = client.post(
        "/api/v1/experiments/run",
        json={"scenarios": ["reconnaissance"], "modes": ["baseline"]},
        headers={"Authorization": f"Bearer {shared_token}"},
    )
    assert response.status_code == 503
    assert response.json()["detail"].lower().startswith("invalid token")


def test_health_reports_reader_only_configuration(monkeypatch):
    monkeypatch.setenv("HONEYPOT_ENV", "production")
    monkeypatch.setenv("HONEYPOT_API_READ_TOKEN", READ_TOKEN)
    monkeypatch.delenv("HONEYPOT_API_ADMIN_TOKEN", raising=False)

    response = client.get("/health")
    assert response.json()["components"]["api_access_control"] == "reader_only"


def test_interaction_failure_does_not_return_internal_exception(monkeypatch):
    def fail_generation(*_args, **_kwargs):
        raise RuntimeError("C:\\private\\state\\database.sqlite3: schema detail")

    monkeypatch.setattr(
        routes.interaction_workflow._bundle_generator,
        "generate_bundle",
        fail_generation,
    )
    actor_id = "security-error-" + uuid4().hex
    response = client.post(
        "/api/v1/decoys/decoy-finance-001/interactions",
        json={"actor_id": actor_id, "action": "read"},
    )

    assert response.status_code == 500
    assert "adaptive decoy generation or persistence failed" in response.json()["detail"]
    assert "private" not in response.text
    assert "database.sqlite3" not in response.text


def test_health_reports_degraded_ledger_without_exposing_configuration(monkeypatch):
    monkeypatch.setattr(
        event_ledger,
        "verify_persisted_chain",
        lambda: LedgerVerification(
            valid=False, entries_checked=0, first_invalid_sequence=1,
            message="Entry hash does not match its contents.",
        ),
    )
    monkeypatch.setenv("HONEYPOT_API_ADMIN_TOKEN", "do-not-disclose-this-admin-token-value")
    response = client.get("/health")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["components"]["ledger_integrity"] == "invalid"
    assert "do-not-disclose" not in response.text

def test_production_without_api_tokens_fails_closed(monkeypatch):
    monkeypatch.setenv("HONEYPOT_ENV", "production")
    monkeypatch.delenv("HONEYPOT_API_READ_TOKEN", raising=False)
    monkeypatch.delenv("HONEYPOT_API_ADMIN_TOKEN", raising=False)

    response = client.get("/api/v1/simulation/scenarios")
    assert response.status_code == 503
    assert "configured in production" in response.json()["detail"]


def test_unknown_environment_fails_closed(monkeypatch):
    monkeypatch.setenv("HONEYPOT_ENV", "staging")
    monkeypatch.delenv("HONEYPOT_API_READ_TOKEN", raising=False)
    monkeypatch.delenv("HONEYPOT_API_ADMIN_TOKEN", raising=False)

    response = client.get("/api/v1/simulation/scenarios")
    assert response.status_code == 503

def test_health_reports_production_missing_api_tokens(monkeypatch):
    monkeypatch.setenv("HONEYPOT_ENV", "production")
    monkeypatch.delenv("HONEYPOT_API_READ_TOKEN", raising=False)
    monkeypatch.delenv("HONEYPOT_API_ADMIN_TOKEN", raising=False)

    response = client.get("/health")
    body = response.json()

    assert body["components"]["api_access_control"] == "production_missing_tokens"


def test_admin_session_cookie_csrf_protection_and_logout(monkeypatch):
    monkeypatch.setenv("HONEYPOT_ENV", "development")
    monkeypatch.setenv("HONEYPOT_API_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.setenv("HONEYPOT_API_READ_TOKEN", READ_TOKEN)
    app.state.admin_sessions = {}
    app.state.admin_login_attempts = {}
    with TestClient(app) as session_client:
        login = session_client.post("/api/v1/auth/session", json={"admin_token": ADMIN_TOKEN})
        assert login.status_code == 200, login.text
        cookie = login.headers["set-cookie"].casefold()
        assert "httponly" in cookie and "samesite=strict" in cookie and "max-age=1800" in cookie
        assert "secure" not in cookie
        csrf = login.json()["csrf_token"]

        assert session_client.get("/api/v1/simulation/scenarios").status_code == 200
        assert session_client.post("/api/v1/unknown-session-route").status_code == 403
        assert session_client.post(
            "/api/v1/unknown-session-route", headers={"X-CSRF-Token": "wrong"}
        ).status_code == 403
        assert session_client.post(
            "/api/v1/unknown-session-route", headers={"X-CSRF-Token": csrf}
        ).status_code == 404
        assert session_client.delete(
            "/api/v1/auth/session", headers={"X-CSRF-Token": csrf}
        ).status_code == 200
        assert session_client.get("/api/v1/simulation/scenarios").status_code == 401


def test_admin_session_expires_and_login_checks_origin(monkeypatch):
    import time

    monkeypatch.setenv("HONEYPOT_ENV", "development")
    monkeypatch.setenv("HONEYPOT_API_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.setenv("HONEYPOT_CORS_ORIGINS", "http://127.0.0.1:5173")
    app.state.admin_sessions = {}
    app.state.admin_login_attempts = {}
    with TestClient(app) as session_client:
        denied = session_client.post(
            "/api/v1/auth/session", json={"admin_token": ADMIN_TOKEN},
            headers={"Origin": "https://attacker.example"},
        )
        assert denied.status_code == 403
        login = session_client.post(
            "/api/v1/auth/session", json={"admin_token": ADMIN_TOKEN},
            headers={"Origin": "http://127.0.0.1:5173"},
        )
        assert login.status_code == 200
        session_id = session_client.cookies.get("honeypot_admin_session")
        app.state.admin_sessions[session_id]["expires_at"] = time.time() - 1
        assert session_client.get("/api/v1/simulation/scenarios").status_code == 401


def test_development_open_mode_is_explicit_and_does_not_fake_admin_session(monkeypatch):
    monkeypatch.setenv("HONEYPOT_ENV", "development")
    monkeypatch.delenv("HONEYPOT_API_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("HONEYPOT_API_READ_TOKEN", raising=False)
    app.state.admin_sessions = {}
    with TestClient(app) as session_client:
        response = session_client.get("/api/v1/auth/session")
        assert response.status_code == 200
        assert response.json() == {
            "authenticated": True, "role": "development", "csrf_token": "", "expires_in": 0,
        }


def test_credentialed_cors_requires_exact_http_origins():
    assert validate_cors_origins(["http://127.0.0.1:5173"]) == ["http://127.0.0.1:5173"]
    for invalid in ("*", "https://trusted.example/path", "https://user:pass@trusted.example"):
        with pytest.raises(RuntimeError, match=r"exact HTTP\(S\) origins"):
            validate_cors_origins([invalid])


def test_production_cors_requires_explicit_https_origins(monkeypatch):
    monkeypatch.setenv("HONEYPOT_ENV", "production")
    monkeypatch.delenv("HONEYPOT_CORS_ORIGINS", raising=False)
    with pytest.raises(RuntimeError, match="explicitly list HTTPS origins"):
        configured_cors_origins()

    monkeypatch.setenv("HONEYPOT_CORS_ORIGINS", "http://dashboard.example")
    with pytest.raises(RuntimeError, match="must use HTTPS"):
        configured_cors_origins()

    monkeypatch.setenv("HONEYPOT_CORS_ORIGINS", "https://dashboard.example")
    assert configured_cors_origins() == ["https://dashboard.example"]


def test_admin_session_rejects_http_origin_in_production(monkeypatch):
    monkeypatch.setenv("HONEYPOT_ENV", "production")
    monkeypatch.setenv("HONEYPOT_CORS_ORIGINS", "http://dashboard.example")
    monkeypatch.setenv("HONEYPOT_API_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.setenv("HONEYPOT_SESSION_COOKIE_SECURE", "true")
    with TestClient(app) as session_client:
        response = session_client.post(
            "/api/v1/auth/session",
            json={"admin_token": ADMIN_TOKEN},
            headers={"Origin": "http://dashboard.example"},
        )
    assert response.status_code == 403
    assert response.json()["detail"] == "Request origin is not allowed"


def test_admin_login_requires_secure_cookie_in_production(monkeypatch):
    monkeypatch.setenv("HONEYPOT_ENV", "production")
    monkeypatch.setenv("HONEYPOT_API_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.delenv("HONEYPOT_SESSION_COOKIE_SECURE", raising=False)
    with TestClient(app) as session_client:
        denied = session_client.post("/api/v1/auth/session", json={"admin_token": ADMIN_TOKEN})
        assert denied.status_code == 503
        monkeypatch.setenv("HONEYPOT_SESSION_COOKIE_SECURE", "true")
        accepted = session_client.post("/api/v1/auth/session", json={"admin_token": ADMIN_TOKEN})
        assert accepted.status_code == 200
        assert "secure" in accepted.headers["set-cookie"].casefold()


def test_admin_session_rejects_oversized_body_and_invalid_environment(monkeypatch):
    monkeypatch.setenv("HONEYPOT_API_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.setenv("HONEYPOT_ENV", "development")
    with TestClient(app) as session_client:
        oversized = session_client.post(
            "/api/v1/auth/session", content='{"admin_token":"' + ("x" * 2048) + '"}',
            headers={"Content-Type": "application/json"},
        )
        assert oversized.status_code == 413
        monkeypatch.setenv("HONEYPOT_ENV", "staging")
        invalid_environment = session_client.post(
            "/api/v1/auth/session", json={"admin_token": ADMIN_TOKEN}
        )
        assert invalid_environment.status_code == 503


def test_network_node_dashboard_proxy_keeps_node_token_server_side(monkeypatch):
    monkeypatch.setenv("HONEYPOT_NODE_DASHBOARD_URL", "http://127.0.0.1:8101")
    monkeypatch.setenv("HONEYPOT_NODE_DASHBOARD_TOKEN", "node-dashboard-server-token-value-123456")
    observed = {}

    class FakeResponse:
        status_code = 200
        content = b'{"node":{"node_id":"test-node"}}'

        def json(self):
            return {"node": {"node_id": "test-node"}}

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, headers):
            observed.update(url=url, headers=headers)
            return FakeResponse()

    monkeypatch.setattr(routes.httpx, "AsyncClient", FakeClient)
    with TestClient(app) as dashboard_client:
        result = dashboard_client.get(
            "/api/v1/network-node/dashboard",
            headers={"Authorization": f"Bearer {READ_TOKEN}"},
        )
    assert result.status_code == 200
    assert result.json() == {"node": {"node_id": "test-node"}}
    assert observed["url"] == "http://127.0.0.1:8101/v1/dashboard/summary"
    assert observed["headers"]["Authorization"].endswith("node-dashboard-server-token-value-123456")


def test_network_node_dashboard_rejects_remote_plain_http_before_forwarding_token(monkeypatch):
    monkeypatch.setenv("HONEYPOT_NODE_DASHBOARD_URL", "http://node.example.test")
    monkeypatch.setenv("HONEYPOT_NODE_DASHBOARD_TOKEN", "node-dashboard-server-token-value-123456")
    with TestClient(app) as dashboard_client:
        response = dashboard_client.get(
            "/api/v1/network-node/dashboard",
            headers={"Authorization": f"Bearer {READ_TOKEN}"},
        )
    assert response.status_code == 503
    assert "URL configuration is invalid" in response.json()["detail"]


def test_backend_service_url_policy_keeps_remote_bearer_endpoints_tls_only():
    assert routes._safe_backend_service_url("https://node.example.test") is True
    assert routes._safe_backend_service_url("http://127.0.0.1:8101") is True
    assert routes._safe_backend_service_url("http://[::1]:8101") is True
    assert routes._safe_backend_service_url("http://node.example.test") is False
    assert routes._safe_backend_service_url("http://user:secret@node.example.test") is False
    assert routes._safe_backend_service_url("https://node.example.test/?token=secret") is False


def test_sensor_ingestion_intel_projection_is_opt_in_bounded_and_secret_free(monkeypatch):
    import asyncio
    from datetime import datetime, timezone
    from app.events.models import HoneypotEvent

    monkeypatch.setenv("HONEYPOT_INTEL_COLLECTOR_URL", "http://127.0.0.1:8101")
    monkeypatch.setenv("HONEYPOT_INTEL_COLLECTOR_TOKEN", "collector-server-token-value-123456789")
    observed = {}

    class FakeResponse:
        status_code = 200
        content = b'{"eligible":true,"status":"published","observation_count":3,"record_id":"auto-test"}'

        def json(self):
            return {"eligible": True, "status": "published", "observation_count": 3, "record_id": "auto-test"}

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, url, json, headers):
            observed.update(url=url, json=json, headers=headers)
            return FakeResponse()

    monkeypatch.setattr(routes.httpx, "AsyncClient", FakeClient)
    event = HoneypotEvent(
        event_id="internal-event-id", timestamp=datetime.now(timezone.utc),
        decoy_id="external-telemetry", actor_id="private-actor-id",
        action="cowrie_login_failed", event_type="external_telemetry",
        severity="medium", source="external", source_system="cowrie",
        sensor_id="cowrie-sensor", source_event_id="external-source-event",
        telemetry_event_type="cowrie_login_failed", source_ip="203.0.113.5",
        attributes={"password": "MUST_NOT_FORWARD", "raw": "PRIVATE"},
    )
    result = asyncio.run(routes._evaluate_intelligence_collection(event))
    assert result == {
        "status": "evaluated", "outcome": "published", "eligible": True, "observation_count": 3,
        "record_id": "auto-test",
    }
    assert observed["url"].endswith("/v1/intelligence/observe")
    assert "collector-server-token-value" in observed["headers"]["Authorization"]
    assert set(observed["json"]) == {
        "source_system", "sensor_id", "external_event_id", "occurred_at",
        "event_type", "severity", "source_ip",
    }
    assert "MUST_NOT_FORWARD" not in str(observed)
    assert "private-actor-id" not in str(observed)


def test_intel_collection_is_disabled_without_backend_configuration(monkeypatch):
    import asyncio
    from datetime import datetime, timezone
    from app.events.models import HoneypotEvent

    monkeypatch.delenv("HONEYPOT_INTEL_COLLECTOR_URL", raising=False)
    monkeypatch.delenv("HONEYPOT_INTEL_COLLECTOR_TOKEN", raising=False)
    event = HoneypotEvent(
        event_id="event", timestamp=datetime.now(timezone.utc), decoy_id="external",
        actor_id="actor", action="read", event_type="external_telemetry",
        source="external", source_system="generic", sensor_id="sensor",
        source_event_id="source-id", source_ip="203.0.113.8",
    )
    assert asyncio.run(routes._evaluate_intelligence_collection(event)) == {"status": "disabled"}


def test_collector_outage_is_reported_without_raising_or_forwarding_raw_data(monkeypatch):
    import asyncio
    from datetime import datetime, timezone
    from app.events.models import HoneypotEvent

    monkeypatch.setenv("HONEYPOT_INTEL_COLLECTOR_URL", "http://127.0.0.1:8101")
    monkeypatch.setenv("HONEYPOT_INTEL_COLLECTOR_TOKEN", "collector-server-token-value-123456789")

    class FailedClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, *_args, **_kwargs):
            import httpx
            raise httpx.ConnectError("private endpoint details")

    monkeypatch.setattr(routes.httpx, "AsyncClient", FailedClient)
    event = HoneypotEvent(
        event_id="event", timestamp=datetime.now(timezone.utc), decoy_id="external",
        actor_id="actor", action="cowrie_login_failed", event_type="external_telemetry",
        source="external", source_system="cowrie", sensor_id="sensor", source_event_id="source-id",
        telemetry_event_type="cowrie_login_failed", source_ip="203.0.113.8",
    )
    assert asyncio.run(routes._evaluate_intelligence_collection(event)) == {"status": "unavailable"}


def test_authenticated_sensor_ingest_persists_before_optional_intel_collection(monkeypatch):
    from app.events.store import EventStore
    from app.telemetry.service import TelemetryIngestionService

    telemetry_token = "telemetry-ingest-token-long-enough-for-tests-123"
    collector_token = "collector-server-token-value-123456789"
    monkeypatch.setenv("HONEYPOT_TELEMETRY_INGEST_TOKEN", telemetry_token)
    monkeypatch.setenv("HONEYPOT_INTEL_COLLECTOR_URL", "http://127.0.0.1:8101")
    monkeypatch.setenv("HONEYPOT_INTEL_COLLECTOR_TOKEN", collector_token)

    class MemoryLedger:
        def __init__(self):
            self.entries = []

        def append(self, event):
            self.entries.append(event)

    ledger = MemoryLedger()
    store = EventStore()
    monkeypatch.setattr(routes, "telemetry_ingestion_service", TelemetryIngestionService(store, ledger))
    monkeypatch.setattr(routes.incident_service, "inspect", lambda _event: None)
    monkeypatch.setattr(routes.telemetry_alert_service, "get_for_event", lambda _event_id: None)
    sent_projection = {}

    class FakeResponse:
        status_code = 200
        content = b'{"eligible":true,"status":"below_publication_threshold","observation_count":1,"required_observations":3}'

        def json(self):
            return {"eligible": True, "status": "below_publication_threshold", "observation_count": 1, "required_observations": 3}

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, url, json, headers):
            sent_projection.update(url=url, json=json, headers=headers)
            return FakeResponse()

    monkeypatch.setattr(routes.httpx, "AsyncClient", FakeClient)
    body = {
        "source_system": "cowrie", "sensor_id": "cowrie-demo",
        "external_event_id": "cowrie-event-001", "occurred_at": "2026-11-15T12:00:00Z",
        "event_type": "cowrie_login_failed", "severity": "medium",
        "source_ip": "203.0.113.88", "attributes": {"authentication_outcome": "failed"},
    }
    with TestClient(app) as sensor_client:
        response = sensor_client.post(
            "/api/v1/telemetry/ingest", json=body,
            headers={"Authorization": f"Bearer {telemetry_token}"},
        )
    assert response.status_code == 201, response.text
    assert response.json()["intelligence_collection"] == {
        "status": "evaluated", "outcome": "below_publication_threshold",
        "eligible": True, "observation_count": 1, "required_observations": 3,
    }
    assert len(store.list_events()) == len(ledger.entries) == 1
    assert sent_projection["headers"]["Authorization"] == f"Bearer {collector_token}"
    assert sent_projection["json"]["event_type"] == "cowrie_login_failed"
    assert "attributes" not in sent_projection["json"]
