from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.network.replication import (
    NodeConfig,
    PeerEndpoint,
    ReplicationNode,
    SecurityEventObservation,
    SignedThreatIntel,
    ThreatIntelRecord,
    ThreatPublicationPolicy,
    TrustedPeer,
    create_node_app,
)


TOKEN_A = "node-a-test-token-000000000000000000000000000000"
TOKEN_B = "node-b-test-token-000000000000000000000000000000"
ADMIN_A = "node-a-admin-token-0000000000000000000000000000"
ADMIN_B = "node-b-admin-token-0000000000000000000000000000"
ADMIN_C = "node-c-admin-token-0000000000000000000000000000"


def make_node(tmp_path, node_id, key_id, private_key, *, trusted=None, peers=None, publication_policy=None):
    config = NodeConfig(
        node_id=node_id,
        key_id=key_id,
        private_key=private_key,
        database_path=tmp_path / f"{node_id}.sqlite3",
        admin_token={"node-a": ADMIN_A, "node-b": ADMIN_B, "node-c": ADMIN_C}[node_id],
        trusted_publishers=trusted or {},
        peers=peers or {},
        publication_policy=publication_policy or ThreatPublicationPolicy(),
    )
    return ReplicationNode(config)


def observation(node_id, key_id):
    now = datetime.now(timezone.utc)
    return ThreatIntelRecord(
        record_id=f"intel-{node_id}-001",
        publisher_id=node_id,
        key_id=key_id,
        created_at=now,
        indicator_type="ipv4",
        indicator="198.51.100.77",
        classification="brute_force",
        severity="high",
        source_system="cowrie",
        first_seen=now,
        last_seen=now,
        observation_count=3,
    )


def test_two_independent_nodes_exchange_signed_intelligence_over_http(tmp_path):
    key_a, key_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    node_a = make_node(
        tmp_path, "node-a", "node-a-key", key_a,
        trusted={"node-b": TrustedPeer("node-b-key", key_b.public_key(), TOKEN_B)},
        peers={"node-b": PeerEndpoint("http://node-b.test", TOKEN_A)},
    )
    node_b = make_node(
        tmp_path, "node-b", "node-b-key", key_b,
        trusted={"node-a": TrustedPeer("node-a-key", key_a.public_key(), TOKEN_A)},
    )
    app_b = create_node_app(node_b)
    envelope = node_a.publish(observation("node-a", "node-a-key"))

    response = asyncio.run(node_a.sync_peer("node-b", envelope.record.record_id, httpx.ASGITransport(app=app_b)))

    assert response == {
        "record_id": envelope.record.record_id,
        "digest": envelope.digest,
        "status": "stored",
        "state": "pending",
        "signature_valid": True,
    }
    assert node_b.storage.list()[0]["state"] == "pending"
    assert node_a.storage.path != node_b.storage.path
    assert node_a.storage.get(envelope.record.record_id).record.publisher_id == "node-a"
    assert node_b.storage.get(envelope.record.record_id).record.publisher_id == "node-a"
    detail = TestClient(app_b).get(
        f"/v1/intelligence/{envelope.record.record_id}",
        headers={"Authorization": f"Bearer {ADMIN_B}"},
    )
    assert detail.status_code == 200
    assert detail.json()["signature_valid"] is True
    assert detail.json()["state"] == "pending"
    health = asyncio.run(node_a.check_peer("node-b", httpx.ASGITransport(app=app_b)))
    assert health["status"] == "healthy"
    assert health["remote_node_id"] == "node-b"


def test_http_import_rejects_unknown_publisher_wrong_token_and_tampering(tmp_path):
    key_a, key_b, key_c = (Ed25519PrivateKey.generate() for _ in range(3))
    node_a = make_node(
        tmp_path, "node-a", "node-a-key", key_a,
        trusted={"node-b": TrustedPeer("node-b-key", key_b.public_key(), TOKEN_B)},
        peers={"node-b": PeerEndpoint("http://node-b.test", TOKEN_A)},
    )
    node_b = make_node(
        tmp_path, "node-b", "node-b-key", key_b,
        trusted={"node-a": TrustedPeer("node-a-key", key_a.public_key(), TOKEN_A)},
    )
    node_c = make_node(tmp_path, "node-c", "node-c-key", key_c)
    envelope = node_a.publish(observation("node-a", "node-a-key"))
    client_b, client_c = TestClient(create_node_app(node_b)), TestClient(create_node_app(node_c))
    payload = envelope.model_dump(mode="json")

    assert client_b.get("/health").status_code == 401
    assert client_b.post("/v1/intelligence/import", json=payload).status_code == 401
    assert client_c.post(
        "/v1/intelligence/import", json=payload,
        headers={"Authorization": f"Bearer {TOKEN_A}"},
    ).status_code == 403
    tampered = {**payload, "record": {**payload["record"], "indicator": "203.0.113.9"}}
    assert client_b.post(
        "/v1/intelligence/import", json=tampered,
        headers={"Authorization": f"Bearer {TOKEN_A}"},
    ).status_code == 400
    assert node_b.storage.list() == []


def test_duplicate_delivery_is_idempotent_and_changed_record_id_reuse_is_rejected(tmp_path):
    key_a, key_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    node_a = make_node(
        tmp_path, "node-a", "node-a-key", key_a,
        trusted={"node-b": TrustedPeer("node-b-key", key_b.public_key(), TOKEN_B)},
        peers={"node-b": PeerEndpoint("http://node-b.test", TOKEN_A)},
    )
    node_b = make_node(
        tmp_path, "node-b", "node-b-key", key_b,
        trusted={"node-a": TrustedPeer("node-a-key", key_a.public_key(), TOKEN_A)},
    )
    app_b = create_node_app(node_b)
    envelope = node_a.publish(observation("node-a", "node-a-key"))
    transport = httpx.ASGITransport(app=app_b)

    first = asyncio.run(node_a.sync_peer("node-b", envelope.record.record_id, transport))
    second = asyncio.run(node_a.sync_peer("node-b", envelope.record.record_id, transport))
    assert first["status"] == "stored"
    assert second["status"] == "duplicate"
    assert len(node_b.storage.list()) == 1

    altered_record = envelope.record.model_copy(update={"indicator": "203.0.113.4"})
    conflicting = envelope.model_copy(update={"record": altered_record})
    with pytest.raises(HTTPException) as error:
        node_b.import_record(conflicting, f"Bearer {TOKEN_A}")
    assert error.value.status_code == 400  # digest is verified before duplicate handling


def test_replay_requires_valid_signature_and_peer_failure_is_reported(tmp_path):
    key_a, key_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    node_a = make_node(
        tmp_path, "node-a", "node-a-key", key_a,
        trusted={"node-b": TrustedPeer("node-b-key", key_b.public_key(), TOKEN_B)},
        peers={"node-b": PeerEndpoint("http://127.0.0.1:1", TOKEN_A)},
    )
    node_b = make_node(
        tmp_path, "node-b", "node-b-key", key_b,
        trusted={"node-a": TrustedPeer("node-a-key", key_a.public_key(), TOKEN_A)},
    )
    envelope = node_a.publish(observation("node-a", "node-a-key"))
    assert node_b.import_record(envelope, f"Bearer {TOKEN_A}") == "stored"
    assert node_b.import_record(envelope, f"Bearer {TOKEN_A}") == "duplicate"
    invalid_signature = envelope.model_copy(update={"signature": "eA=="})
    with pytest.raises(HTTPException) as error:
        node_b.import_record(invalid_signature, f"Bearer {TOKEN_A}")
    assert error.value.status_code == 400
    health = asyncio.run(node_a.check_peer("node-b"))
    assert health["status"] == "unavailable"
    with pytest.raises(HTTPException) as error:
        asyncio.run(node_a.sync_peer("node-b", envelope.record.record_id))
    assert error.value.status_code == 502
    assert node_a.storage.get(envelope.record.record_id) is not None


def test_expired_but_correctly_signed_record_is_rejected(tmp_path):
    key_a, key_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    node_a = make_node(tmp_path, "node-a", "node-a-key", key_a)
    node_b = make_node(
        tmp_path, "node-b", "node-b-key", key_b,
        trusted={"node-a": TrustedPeer("node-a-key", key_a.public_key(), TOKEN_A)},
    )
    old = observation("node-a", "node-a-key").model_copy(
        update={"created_at": datetime.now(timezone.utc) - timedelta(days=31)}
    )
    envelope = node_a.publish(old)

    with pytest.raises(HTTPException) as error:
        node_b.import_record(envelope, f"Bearer {TOKEN_A}")

    assert error.value.status_code == 400
    assert node_b.storage.list() == []


def test_peer_endpoint_must_return_the_configured_node_identity(tmp_path):
    key_a, key_c = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    node_a = make_node(
        tmp_path, "node-a", "node-a-key", key_a,
        trusted={"node-b": TrustedPeer("node-b-key", Ed25519PrivateKey.generate().public_key(), TOKEN_B)},
        peers={"node-b": PeerEndpoint("http://node-b.test", TOKEN_A)},
    )
    wrong_node = make_node(
        tmp_path, "node-c", "node-c-key", key_c,
        trusted={"node-a": TrustedPeer("node-a-key", key_a.public_key(), TOKEN_A)},
    )
    envelope = node_a.publish(observation("node-a", "node-a-key"))
    transport = httpx.ASGITransport(app=create_node_app(wrong_node))

    health = asyncio.run(node_a.check_peer("node-b", transport))

    assert health["status"] == "unavailable"
    assert health["remote_node_id"] is None
    with pytest.raises(HTTPException) as error:
        asyncio.run(node_a.sync_peer("node-b", envelope.record.record_id, transport))
    assert error.value.status_code == 502
    assert wrong_node.storage.list() == []


def test_reachable_peer_rejection_is_reported_as_degraded_not_unavailable(tmp_path):
    key_a = Ed25519PrivateKey.generate()
    peer_app = FastAPI()

    @peer_app.get("/health")
    async def peer_health():
        return {"status": "healthy", "node_id": "node-b"}

    @peer_app.post("/v1/intelligence/import")
    async def reject_import():
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=400, content={"detail": "invalid record"})

    node_a = make_node(
        tmp_path,
        "node-a",
        "node-a-key",
        key_a,
        trusted={"node-b": TrustedPeer("node-b-key", Ed25519PrivateKey.generate().public_key(), TOKEN_B)},
        peers={"node-b": PeerEndpoint("http://node-b.test", TOKEN_A)},
    )
    envelope = node_a.publish(observation("node-a", "node-a-key"))

    with pytest.raises(HTTPException) as error:
        asyncio.run(
            node_a.sync_peer(
                "node-b",
                envelope.record.record_id,
                httpx.ASGITransport(app=peer_app),
            )
        )

    assert error.value.status_code == 502
    assert "reachable" in error.value.detail
    assert node_a.peers()[0]["status"] == "degraded"


def test_publish_requires_node_admin_and_record_is_bounded(tmp_path):
    key_a = Ed25519PrivateKey.generate()
    node = make_node(tmp_path, "node-a", "node-a-key", key_a)
    client = TestClient(create_node_app(node))
    payload = observation("node-a", "node-a-key").model_dump(mode="json")
    assert client.post("/v1/intelligence/publish", json=payload).status_code == 401
    assert client.post(
        "/v1/intelligence/publish", json=payload,
        headers={"Authorization": f"Bearer {ADMIN_A}"},
    ).status_code == 201
    assert client.get("/v1/intelligence").status_code == 401
    listing = client.get("/v1/intelligence", headers={"Authorization": f"Bearer {ADMIN_A}"})
    assert listing.status_code == 200
    assert "actor_id" not in listing.text and "private_key" not in listing.text


def test_malformed_and_oversized_import_requests_are_rejected(tmp_path):
    key_a, key_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    node_b = make_node(
        tmp_path, "node-b", "node-b-key", key_b,
        trusted={"node-a": TrustedPeer("node-a-key", key_a.public_key(), TOKEN_A)},
    )
    client = TestClient(create_node_app(node_b))
    headers = {"Authorization": f"Bearer {TOKEN_A}"}
    assert client.post("/v1/intelligence/import", content="not-json", headers=headers).status_code == 422
    assert client.post("/v1/intelligence/import", content=b" " * (16 * 1024 + 1), headers=headers).status_code == 413


def test_environment_factory_loads_encrypted_test_key_and_isolated_store(tmp_path, monkeypatch):
    from app.network.replication import load_node_app_from_environment

    private = Ed25519PrivateKey.generate()
    passphrase = "test-only-key-passphrase"
    private_path = tmp_path / "node-private.pem"
    config_path = tmp_path / "node.json"
    private_path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode()),
    ))
    config_path.write_text(json.dumps({
        "node_id": "node-a",
        "key_id": "node-a-key",
        "private_key_file": str(private_path),
        "private_key_password_env": "TEST_NODE_KEY_PASSWORD",
        "database_path": str(tmp_path / "isolated.sqlite3"),
        "admin_token_env": "TEST_NODE_ADMIN",
        "trusted_publishers": {},
        "peers": {},
    }), encoding="utf-8")
    monkeypatch.setenv("HONEYPOT_NODE_CONFIG", str(config_path))
    monkeypatch.setenv("TEST_NODE_KEY_PASSWORD", passphrase)
    monkeypatch.setenv("TEST_NODE_ADMIN", "test-node-admin-token-00000000000000000")

    app = load_node_app_from_environment()

    assert app.state.replication_node.config.node_id == "node-a"
    assert app.state.replication_node.storage.path == tmp_path / "isolated.sqlite3"
    assert app.state.replication_node.config.private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) == private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def test_event_collector_requires_configured_criteria_and_shares_only_aggregates(tmp_path):
    key = Ed25519PrivateKey.generate()
    policy = ThreatPublicationPolicy(
        enabled=True,
        minimum_severity="high",
        minimum_observations=2,
        allowed_sources=["suricata"],
        event_type_classifications={"suricata_alert": "exploit"},
    )
    node = make_node(tmp_path, "node-a", "node-a-key", key, publication_policy=policy)
    client = TestClient(create_node_app(node))
    auth = {"Authorization": f"Bearer {ADMIN_A}"}
    now = datetime.now(timezone.utc).isoformat()

    def submit(event_id, *, source="suricata", event_type="suricata_alert", severity="high", source_ip="1.1.1.1"):
        return client.post("/v1/intelligence/observe", headers=auth, json={
            "source_system": source,
            "sensor_id": "sensor-local-private",
            "external_event_id": event_id,
            "occurred_at": now,
            "event_type": event_type,
            "severity": severity,
            "source_ip": source_ip,
        })

    assert submit("low-1", severity="low").json()["reason"] == "severity_below_threshold"
    assert submit("private-1", source_ip="10.2.3.4").json()["reason"] == "non_public_indicator"
    assert submit("unknown-1", event_type="other_event").json()["reason"] == "event_type_not_mapped"
    assert submit("source-1", source="zeek").json()["reason"] == "source_not_allowed"
    assert node.storage.list() == []

    first = submit("event-1").json()
    repeated = submit("event-1").json()
    second = submit("event-2").json()
    assert first["status"] == "below_publication_threshold"
    assert repeated["status"] == "duplicate_event"
    assert repeated["observation_count"] == 1
    assert second["status"] == "published"
    assert second["observation_count"] == 2
    assert len(node.storage.list()) == 1
    signed = node.storage.get(second["record_id"])
    assert signed is not None
    assert signed.record.indicator == "1.1.1.1"
    assert signed.record.classification == "exploit"
    assert signed.record.source_system == "suricata"
    assert signed.record.observation_count == 2
    serialized = signed.model_dump_json()
    for private_value in ("sensor-local-private", "event-1", "event-2", "actor_id", "attributes"):
        assert private_value not in serialized

    assert submit("event-3").json()["status"] == "already_published"
    assert len(node.storage.list()) == 1


def test_event_collector_is_disabled_by_default_and_rejects_extra_sensitive_fields(tmp_path):
    node = make_node(tmp_path, "node-a", "node-a-key", Ed25519PrivateKey.generate())
    client = TestClient(create_node_app(node))
    payload = {
        "source_system": "suricata", "sensor_id": "sensor-a", "external_event_id": "event-a",
        "occurred_at": datetime.now(timezone.utc).isoformat(), "event_type": "suricata_alert",
        "severity": "critical", "source_ip": "1.1.1.1",
    }
    response = client.post(
        "/v1/intelligence/observe", json=payload,
        headers={"Authorization": f"Bearer {ADMIN_A}"},
    )
    assert response.status_code == 200
    assert response.json() == {"eligible": False, "reason": "publication_disabled"}
    response = client.post(
        "/v1/intelligence/observe", json={**payload, "attributes": {"password": "secret"}},
        headers={"Authorization": f"Bearer {ADMIN_A}"},
    )
    assert response.status_code == 422
    assert node.storage.list() == []


def test_two_live_uvicorn_processes_transfer_retry_fail_restart_and_resync():
    source_root = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join((str(source_root / "backend"), str(source_root)))
    completed = subprocess.run(
        [sys.executable, "-m", "app.network.live_demo"],
        cwd=source_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + "\n" + completed.stderr
    result = json.loads(completed.stdout)
    assert result["result"] == "passed"
    assert result["first_delivery"] == "stored"
    assert result["signature_valid_at_node_b"] is True
    assert result["node_b_record_state"] == "pending"
    assert result["duplicate_delivery"] == "duplicate"
    assert result["tampered_delivery_http_status"] == 400
    assert result["offline_peer_status"] == "unavailable"
    assert result["node_a_local_record_count_while_offline"] == 1
    assert result["node_b_state_after_restart"] == "pending"
    assert result["duplicate_after_restart"] == "duplicate"
    assert result["post_restart_new_delivery"] == "stored"


def test_live_demo_closes_parent_log_handle_after_start(tmp_path, monkeypatch):
    from app.network import live_demo

    captured = {}
    process = object()

    def fake_popen(*_args, **kwargs):
        captured["log"] = kwargs["stdout"]
        return process

    monkeypatch.setattr(live_demo.subprocess, "Popen", fake_popen)
    log_path = tmp_path / "node.log"

    assert live_demo._start_node(tmp_path / "node.json", 12345, {}, log_path) is process
    assert captured["log"].closed is True
    assert log_path.exists()


def test_publisher_key_rotation_requires_explicit_fingerprint_and_revocation(tmp_path):
    from hashlib import sha256

    key_old, key_new, key_receiver = (Ed25519PrivateKey.generate() for _ in range(3))
    publisher_old = make_node(tmp_path, "node-a", "node-a-key-v1", key_old)
    node_b = make_node(
        tmp_path, "node-b", "node-b-key", key_receiver,
        trusted={"node-a": TrustedPeer("node-a-key-v1", key_old.public_key(), TOKEN_A)},
    )
    old_envelope = publisher_old.publish(observation("node-a", "node-a-key-v1"))
    client_b = TestClient(create_node_app(node_b))
    auth = {"Authorization": f"Bearer {ADMIN_B}"}
    assert client_b.post(
        "/v1/intelligence/import", json=old_envelope.model_dump(mode="json"),
        headers={"Authorization": f"Bearer {TOKEN_A}"},
    ).status_code == 200

    raw_public = key_new.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    fingerprint = sha256(raw_public).hexdigest()
    pem = key_new.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    stage_body = {"key_id": "node-a-key-v2", "public_key_pem": pem, "expected_fingerprint": fingerprint}
    assert client_b.post(
        "/v1/publishers/node-a/keys", json={**stage_body, "expected_fingerprint": "0" * 64}, headers=auth
    ).status_code == 409
    staged = client_b.post("/v1/publishers/node-a/keys", json=stage_body, headers=auth)
    assert staged.status_code == 201
    assert staged.json()["status"] == "pending"

    publisher_new = make_node(tmp_path / "publisher-v2", "node-a", "node-a-key-v2", key_new)
    new_record = observation("node-a", "node-a-key-v2").model_copy(update={"record_id": "intel-node-a-v2-001"})
    new_envelope = publisher_new.publish(new_record)
    assert client_b.post(
        "/v1/intelligence/import", json=new_envelope.model_dump(mode="json"),
        headers={"Authorization": f"Bearer {TOKEN_A}"},
    ).status_code == 403
    activated = client_b.post(
        "/v1/publishers/node-a/keys/node-a-key-v2/activate",
        json={"expected_fingerprint": fingerprint}, headers=auth,
    )
    assert activated.status_code == 200 and activated.json()["status"] == "active"
    node_b = make_node(
        tmp_path, "node-b", "node-b-key", key_receiver,
        trusted={"node-a": TrustedPeer("node-a-key-v1", key_old.public_key(), TOKEN_A)},
    )
    client_b = TestClient(create_node_app(node_b))
    assert client_b.post(
        "/v1/intelligence/import", json=new_envelope.model_dump(mode="json"),
        headers={"Authorization": f"Bearer {TOKEN_A}"},
    ).status_code == 200

    revoked = client_b.post(
        "/v1/publishers/node-a/keys/node-a-key-v1/revoke",
        json={"expected_fingerprint": sha256(key_old.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )).hexdigest()}, headers=auth,
    )
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    assert client_b.post(
        "/v1/intelligence/import", json=old_envelope.model_dump(mode="json"),
        headers={"Authorization": f"Bearer {TOKEN_A}"},
    ).status_code == 403
    old_detail = client_b.get(f"/v1/intelligence/{old_envelope.record.record_id}", headers=auth)
    assert old_detail.status_code == 200
    assert old_detail.json()["signature_valid"] is True
    assert old_detail.json()["publisher_trust_status"] == "revoked"
    assert old_detail.json()["state"] == "revoked"
    assert any(item["action"] == "publisher_key_revoked" for item in old_detail.json()["audit"])


def test_peer_registry_controls_and_failure_history_survive_restart(tmp_path):
    key_a, key_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    node = make_node(
        tmp_path, "node-a", "node-a-key", key_a,
        trusted={"node-b": TrustedPeer("node-b-key", key_b.public_key(), TOKEN_B)},
        peers={"node-b": PeerEndpoint("http://127.0.0.1:1", TOKEN_A)},
    )
    client = TestClient(create_node_app(node))
    auth = {"Authorization": f"Bearer {ADMIN_A}"}
    assert client.get("/v1/peers", headers=auth).json()["peers"][0]["status"] == "unknown"
    assert client.post("/v1/peers/node-b/disable", headers=auth).json()["status"] == "disabled"
    assert asyncio.run(node.check_peer("node-b"))["status"] == "disabled"
    assert client.post("/v1/peers/node-b/enable", headers=auth).json()["enabled"] is True
    unavailable = asyncio.run(node.check_peer("node-b"))
    assert unavailable["status"] == "unavailable"
    assert unavailable["failure_count"] == 1
    local_record = node.publish(observation("node-a", "node-a-key"))
    with pytest.raises(HTTPException) as sync_error:
        asyncio.run(node.sync_peer("node-b", local_record.record.record_id))
    assert sync_error.value.status_code == 502

    restarted = make_node(
        tmp_path, "node-a", "node-a-key", key_a,
        trusted={"node-b": TrustedPeer("node-b-key", key_b.public_key(), TOKEN_B)},
        peers={"node-b": PeerEndpoint("http://127.0.0.1:1", TOKEN_A)},
    )
    state = restarted.peers()[0]
    assert state["enabled"] is True
    assert state["status"] == "unavailable"
    assert state["failure_count"] == 2
    assert restarted.dashboard_summary()["sync_failures"] == 1
    remote_node = make_node(
        tmp_path, "node-b", "node-b-key", key_b,
        trusted={"node-a": TrustedPeer("node-a-key", key_a.public_key(), TOKEN_A)},
    )
    recovered = asyncio.run(restarted.check_peer(
        "node-b", httpx.ASGITransport(app=create_node_app(remote_node))
    ))
    assert recovered["status"] == "healthy"
    assert recovered["last_seen"] is not None
    assert recovered["failure_count"] == 2


def test_intelligence_approval_rejection_expiration_conflicts_and_confidence(tmp_path):
    key_a, key_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    node_a = make_node(tmp_path, "node-a", "node-a-key", key_a)
    node_b = make_node(
        tmp_path, "node-b", "node-b-key", key_b,
        trusted={"node-a": TrustedPeer("node-a-key", key_a.public_key(), TOKEN_A)},
    )
    client = TestClient(create_node_app(node_b))
    peer_auth = {"Authorization": f"Bearer {TOKEN_A}"}
    admin_auth = {"Authorization": f"Bearer {ADMIN_B}"}
    first_record = observation("node-a", "node-a-key")
    first = node_a.publish(first_record)
    assert client.post("/v1/intelligence/import", json=first.model_dump(mode="json"), headers=peer_auth).json()["state"] == "pending"

    duplicate_indicator_record = first_record.model_copy(update={"record_id": "intel-node-a-duplicate"})
    duplicate = node_a.publish(duplicate_indicator_record)
    assert client.post("/v1/intelligence/import", json=duplicate.model_dump(mode="json"), headers=peer_auth).status_code == 200
    duplicate_detail = client.get(f"/v1/intelligence/{duplicate.record.record_id}", headers=admin_auth).json()
    assert duplicate_detail["relations"][0]["relation"] == "duplicate_indicator"

    conflicting_record = first_record.model_copy(update={"record_id": "intel-node-a-conflict", "classification": "exploit"})
    conflict = node_a.publish(conflicting_record)
    assert client.post("/v1/intelligence/import", json=conflict.model_dump(mode="json"), headers=peer_auth).status_code == 200
    detail = client.get(f"/v1/intelligence/{conflict.record.record_id}", headers=admin_auth).json()
    assert detail["relations"][0]["relation"] == "classification_conflict"
    assert detail["confidence_score"] > 0
    assert "not a probability" in detail["confidence_basis"]

    approval = client.post(
        f"/v1/intelligence/{first.record.record_id}/approve", headers=admin_auth,
        json={"reason": "Reviewed against local telemetry"},
    )
    assert approval.status_code == 200 and approval.json()["state"] == "approved"
    duplicate_approved = client.post(
        "/v1/intelligence/import", json=first.model_dump(mode="json"), headers=peer_auth
    )
    assert duplicate_approved.json()["status"] == "duplicate"
    assert duplicate_approved.json()["state"] == "approved"
    rejected_after = client.post(
        f"/v1/intelligence/{first.record.record_id}/reject", headers=admin_auth,
        json={"reason": "Changed decision"},
    )
    assert rejected_after.status_code == 409
    audit = client.get(f"/v1/intelligence/{first.record.record_id}/audit", headers=admin_auth).json()["audit"]
    assert [item["action"] for item in audit] == ["imported", "approved"]

    reject_response = client.post(
        f"/v1/intelligence/{conflict.record.record_id}/reject", headers=admin_auth,
        json={"reason": "Conflicts with another classification"},
    )
    assert reject_response.status_code == 200 and reject_response.json()["state"] == "rejected"
    assert client.get(f"/v1/intelligence/{conflict.record.record_id}/audit", headers=admin_auth).json()["audit"][-1]["action"] == "rejected"

    expired_record = observation("node-a", "node-a-key").model_copy(update={
        "record_id": "intel-expired-001",
        "created_at": datetime.now(timezone.utc) - timedelta(days=31),
    })
    expired = node_a.publish(expired_record)
    node_b.storage.put(expired, "pending")
    assert node_b.storage.get_entry(expired_record.record_id)[1] == "expired"
    assert node_b.storage.audit_for_record(expired_record.record_id)[-1]["action"] == "expired"
    assert client.post(
        f"/v1/intelligence/{expired_record.record_id}/approve", headers=admin_auth,
        json={"reason": "Must be rejected after expiration"},
    ).status_code == 409


def test_publisher_policy_and_read_only_dashboard_authentication(tmp_path):
    key_a, key_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    from app.network.replication import NodeConfig

    node = ReplicationNode(NodeConfig(
        node_id="node-b", key_id="node-b-key", private_key=key_b,
        database_path=tmp_path / "policy.sqlite3", admin_token=ADMIN_B,
        trusted_publishers={"node-a": TrustedPeer(
            "node-a-key", key_a.public_key(), TOKEN_A,
            allowed_sources=frozenset({"cowrie"}), minimum_observations=5,
        )},
        peers={}, dashboard_token="dashboard-read-token-00000000000000000",
    ))
    client = TestClient(create_node_app(node))
    publisher = make_node(tmp_path, "node-a", "node-a-key", key_a)
    envelope = publisher.publish(observation("node-a", "node-a-key"))
    assert client.post(
        "/v1/intelligence/import", json=envelope.model_dump(mode="json"),
        headers={"Authorization": f"Bearer {TOKEN_A}"},
    ).status_code == 403
    assert client.get("/v1/dashboard/summary", headers={"Authorization": f"Bearer {ADMIN_B}"}).status_code == 401
    response = client.get(
        "/v1/dashboard/summary",
        headers={"Authorization": "Bearer dashboard-read-token-00000000000000000"},
    )
    assert response.status_code == 200
    assert response.json()["node"]["node_id"] == "node-b"


@pytest.mark.parametrize(
    ("policy_overrides", "expected_detail"),
    [
        ({"allowed_classifications": frozenset({"scanning"})}, "classification"),
        ({"minimum_observations": 5}, "more observations"),
    ],
)
def test_publisher_classification_and_observation_policies_fail_closed(tmp_path, policy_overrides, expected_detail):
    key_a, key_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    trusted_peer = TrustedPeer("node-a-key", key_a.public_key(), TOKEN_A, **policy_overrides)
    node_b = make_node(tmp_path, "node-b", "node-b-key", key_b, trusted={"node-a": trusted_peer})
    node_a = make_node(tmp_path, "node-a", "node-a-key", key_a)
    envelope = node_a.publish(observation("node-a", "node-a-key"))

    with pytest.raises(HTTPException, match=expected_detail):
        node_b.import_record(envelope, f"Bearer {TOKEN_A}")
    assert node_b.storage.list() == []


def test_local_signing_key_rotation_keeps_prior_records_verifiable(tmp_path):
    old_key, new_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    database_path = tmp_path / "rotating-node.sqlite3"
    old_node = ReplicationNode(NodeConfig(
        node_id="node-a", key_id="node-a-key-v1", private_key=old_key,
        database_path=database_path, admin_token=ADMIN_A,
        trusted_publishers={}, peers={},
    ))
    old_envelope = old_node.publish(observation("node-a", "node-a-key-v1"))
    new_node = ReplicationNode(NodeConfig(
        node_id="node-a", key_id="node-a-key-v2", private_key=new_key,
        database_path=database_path, admin_token=ADMIN_A,
        trusted_publishers={}, peers={},
    ))
    new_envelope = new_node.publish(observation("node-a", "node-a-key-v2").model_copy(
        update={"record_id": "intel-node-a-after-rotation"}
    ))
    client = TestClient(create_node_app(new_node))
    old_detail = client.get(
        f"/v1/intelligence/{old_envelope.record.record_id}",
        headers={"Authorization": f"Bearer {ADMIN_A}"},
    )
    assert old_detail.status_code == 200
    assert old_detail.json()["signature_valid"] is True
    assert old_detail.json()["publisher_trust_status"] == "active"
    assert new_envelope.record.key_id == "node-a-key-v2"


def test_node_database_cannot_be_reused_under_a_different_identity(tmp_path):
    shared_path = tmp_path / "node-a.sqlite3"
    node_a = ReplicationNode(NodeConfig(
        node_id="node-a", key_id="node-a-key", private_key=Ed25519PrivateKey.generate(),
        database_path=shared_path, admin_token=ADMIN_A,
        trusted_publishers={}, peers={},
    ))
    assert node_a.dashboard_summary()["node"]["node_id"] == "node-a"
    with pytest.raises(ValueError, match="identity bound"):
        ReplicationNode(NodeConfig(
            node_id="node-b", key_id="node-b-key", private_key=Ed25519PrivateKey.generate(),
            database_path=shared_path, admin_token=ADMIN_B,
            trusted_publishers={}, peers={},
        ))
