import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.public_demo import REPOSITORY_ROOT, create_app


ORIGIN = "https://placement-demo.example"


def test_public_demo_exposes_one_sanitized_snapshot_and_health_only(tmp_path, monkeypatch):
    monkeypatch.setenv("HONEYPOT_ENV", "production")
    database = tmp_path / "demo.sqlite3"
    with TestClient(create_app(database, cors_origins=[ORIGIN])) as client:
        response = client.get("/api/v1/public-demo", headers={"Origin": ORIGIN})
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == ORIGIN
        snapshot = response.json()
        assert snapshot["label"] == "Placement Demonstration — Synthetic Security Data"
        assert snapshot["overview"]["telemetry_events"] == 15
        assert snapshot["cowrie"]["successful_logins"] == 3
        assert snapshot["profiles"][0]["anomaly_index"] == 0.438
        assert snapshot["recommendations"][0]["evaluation"]["interactions_recorded"] == 8
        assert client.get("/healthz").json() == {"status": "ok", "service": "honeypot-placement-demo"}

        def assert_safe(value):
            forbidden = {"actor_id", "profile_id", "event_id", "source_ip", "destination_ip", "password", "credentials", "private_key", "fingerprint", "raw_event", "payload"}
            if isinstance(value, dict):
                assert forbidden.isdisjoint(value)
                for child in value.values():
                    assert_safe(child)
            elif isinstance(value, list):
                for child in value:
                    assert_safe(child)

        assert_safe(snapshot)


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/events",
        "/api/v1/telemetry/alerts",
        "/api/v1/telemetry/cowrie/events",
        "/api/v1/profiles",
        "/api/v1/ledger/entries",
        "/api/v1/ledger/verify",
        "/api/v1/strategy-sharing/imports/test",
        "/api/v1/simulation/scenarios",
        "/api/v1/network-node/dashboard",
        "/api/v1/auth/session",
        "/docs",
        "/openapi.json",
    ],
)
def test_public_demo_denies_unapproved_reads(tmp_path, path):
    with TestClient(create_app(tmp_path / "demo.sqlite3", cors_origins=[ORIGIN])) as client:
        assert client.get(path).status_code == 404


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/api/v1/public-demo"),
        ("post", "/api/v1/auth/session"),
        ("delete", "/api/v1/auth/session"),
        ("post", "/api/v1/telemetry/ingest"),
        ("post", "/api/v1/profiles/recompute"),
        ("post", "/api/v1/deception/recommendations/x/approve"),
        ("post", "/api/v1/deception/recommendations/x/evaluate"),
        ("post", "/api/v1/experiments/run"),
        ("post", "/api/v1/evaluations"),
        ("post", "/api/v1/interactions"),
        ("post", "/api/v1/simulation/run"),
        ("post", "/api/v1/ledger/checkpoint"),
        ("post", "/api/v1/strategy-sharing/imports"),
        ("post", "/api/v1/strategy-sharing/imports/id/activate"),
        ("post", "/api/v1/decoys/generate"),
        ("post", "/api/v1/network-node/sync"),
    ],
)
def test_public_demo_denies_all_mutations(tmp_path, method, path):
    with TestClient(create_app(tmp_path / "demo.sqlite3", cors_origins=[ORIGIN])) as client:
        response = client.request(method.upper(), path, json={})
        assert response.status_code == 404


def test_public_demo_origin_policy_is_exact(tmp_path, monkeypatch):
    monkeypatch.setenv("HONEYPOT_ENV", "production")
    with TestClient(create_app(tmp_path / "demo.sqlite3", cors_origins=[ORIGIN])) as client:
        assert client.get("/api/v1/public-demo", headers={"Origin": "https://attacker.example"}).status_code == 403
        assert client.get("/api/v1/public-demo", headers={"Origin": ORIGIN}).status_code == 200


def test_public_demo_seed_is_deterministic_and_idempotent_across_restarts(tmp_path):
    database = tmp_path / "demo.sqlite3"
    with TestClient(create_app(database, cors_origins=[ORIGIN])) as client:
        first = client.get("/api/v1/public-demo").json()
    with TestClient(create_app(database, cors_origins=[ORIGIN])) as client:
        second = client.get("/api/v1/public-demo").json()
    assert first == second
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT count(*) FROM public_demo_snapshot").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence'").fetchone()[0] == 1


def test_public_entry_point_import_does_not_load_operator_app_or_ml_or_write_store(tmp_path):
    repo_root = REPOSITORY_ROOT
    database = Path(tempfile.gettempdir()) / f"public-demo-import-{uuid4().hex}.sqlite3"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root / "backend")
    env["HONEYPOT_ENV"] = "development"
    env["HONEYPOT_DEMO_DB_PATH"] = str(database)
    env.pop("HONEYPOT_CORS_ORIGINS", None)
    code = (
        "import json,sys; import app.public_demo; "
        "print(json.dumps({'operator_app':'app.main' in sys.modules, "
        "'ml_loaded':any(n == 'sklearn' or n.startswith('sklearn.') or n == 'numpy' or n.startswith('numpy.') or n == 'pandas' or n.startswith('pandas.') for n in sys.modules)}))"
    )
    result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == {"operator_app": False, "ml_loaded": False}
    assert not database.exists()


def test_demo_database_path_cannot_target_project_or_operational_database(tmp_path):
    with pytest.raises(RuntimeError, match="outside the project checkout"):
        create_app(REPOSITORY_ROOT / "data" / "unrelated.sqlite3", cors_origins=[ORIGIN])
    with pytest.raises(RuntimeError, match="storage path is invalid"):
        create_app(tmp_path / "event_ledger.sqlite3", cors_origins=[ORIGIN])
    assert not (REPOSITORY_ROOT / "data" / "unrelated.sqlite3").exists()


def test_environment_database_path_must_remain_ephemeral(monkeypatch, tmp_path):
    monkeypatch.setenv("HONEYPOT_DEMO_DB_PATH", str(tmp_path / "outside-temp.sqlite3"))
    with pytest.raises(RuntimeError, match="ephemeral temp directory"):
        create_app(cors_origins=[ORIGIN])


def test_public_demo_fails_closed_on_bad_production_cors_configuration(monkeypatch, tmp_path):
    monkeypatch.setenv("HONEYPOT_ENV", "production")
    monkeypatch.delenv("HONEYPOT_CORS_ORIGINS", raising=False)
    with pytest.raises(RuntimeError, match="exact Vercel origin"):
        create_app(tmp_path / "demo.sqlite3")
    with pytest.raises(RuntimeError, match=r"exact HTTP\(S\) origins"):
        create_app(tmp_path / "other.sqlite3", cors_origins=["*"])


def test_tampered_demo_snapshot_fails_closed(tmp_path):
    database = tmp_path / "demo.sqlite3"
    with TestClient(create_app(database, cors_origins=[ORIGIN])):
        pass
    with sqlite3.connect(database) as db:
        row = db.execute("SELECT payload FROM public_demo_snapshot").fetchone()
        payload = json.loads(row[0])
        payload["notice"] = "modified"
        db.execute("UPDATE public_demo_snapshot SET payload=? WHERE singleton=1", (json.dumps(payload),))
    with TestClient(create_app(database, cors_origins=[ORIGIN])) as client:
        response = client.get("/api/v1/public-demo")
        assert response.status_code == 503
        assert response.json() == {"detail": "Demo data is temporarily unavailable"}
