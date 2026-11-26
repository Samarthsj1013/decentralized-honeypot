"""Run a self-contained two-Uvicorn-process localhost exchange demonstration."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _keypair(directory: Path, node: str, password: str) -> tuple[Path, Path]:
    private_key = Ed25519PrivateKey.generate()
    private_path = directory / f"{node}-private.pem"
    public_path = directory / f"{node}-public.pem"
    private_path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode("utf-8")),
    ))
    public_path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return private_path, public_path


def _write_configs(directory: Path, port_a: int, port_b: int, env: dict[str, str]) -> tuple[Path, Path]:
    a_private, a_public = _keypair(directory, "node-a", env["DEMO_A_KEY_PASSWORD"])
    b_private, b_public = _keypair(directory, "node-b", env["DEMO_B_KEY_PASSWORD"])
    config_a = {
        "node_id": "demo-node-a", "key_id": "demo-node-a-key-v1",
        "private_key_file": str(a_private), "private_key_password_env": "DEMO_A_KEY_PASSWORD",
        "database_path": str(directory / "node-a.sqlite3"), "admin_token_env": "DEMO_A_ADMIN_TOKEN",
        "trusted_publishers": {"demo-node-b": {
            "key_id": "demo-node-b-key-v1", "public_key_file": str(b_public),
            "incoming_token_env": "DEMO_B_TO_A_TOKEN",
        }},
        "peers": {"demo-node-b": {
            "base_url": f"http://127.0.0.1:{port_b}", "outgoing_token_env": "DEMO_A_TO_B_TOKEN",
        }},
    }
    config_b = {
        "node_id": "demo-node-b", "key_id": "demo-node-b-key-v1",
        "private_key_file": str(b_private), "private_key_password_env": "DEMO_B_KEY_PASSWORD",
        "database_path": str(directory / "node-b.sqlite3"), "admin_token_env": "DEMO_B_ADMIN_TOKEN",
        "trusted_publishers": {"demo-node-a": {
            "key_id": "demo-node-a-key-v1", "public_key_file": str(a_public),
            "incoming_token_env": "DEMO_A_TO_B_TOKEN",
        }},
        "peers": {"demo-node-a": {
            "base_url": f"http://127.0.0.1:{port_a}", "outgoing_token_env": "DEMO_B_TO_A_TOKEN",
        }},
    }
    path_a, path_b = directory / "node-a.json", directory / "node-b.json"
    path_a.write_text(json.dumps(config_a, indent=2), encoding="utf-8")
    path_b.write_text(json.dumps(config_b, indent=2), encoding="utf-8")
    return path_a, path_b


def _start_node(config_path: Path, port: int, env: dict[str, str], log_path: Path) -> subprocess.Popen:
    node_env = dict(env)
    node_env["HONEYPOT_NODE_CONFIG"] = str(config_path)
    with log_path.open("ab") as log:
        return subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.network.replication:load_node_app_from_environment",
             "--factory", "--host", "127.0.0.1", "--port", str(port)],
            cwd=Path(__file__).resolve().parents[2],
            env=node_env,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )


def _stop(process: subprocess.Popen | None) -> None:
    if process is None:
        return
    if os.name == "nt":
        # The Windows venv launcher can leave the actual Python child alive
        # after its wrapper exits. Stop the process tree so descendants also
        # release the inherited log handle before TemporaryDirectory cleanup.
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    if process.poll() is not None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _wait_ready(process: subprocess.Popen, url: str, token: str, log_path: Path) -> None:
    deadline = time.monotonic() + 20
    last_error = "no response"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            last_error = f"process exited with code {process.returncode}"
            break
        try:
            response = httpx.get(url + "/health", headers={"Authorization": f"Bearer {token}"}, timeout=0.5)
            if response.status_code == 200:
                return
            last_error = f"health returned HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            last_error = type(exc).__name__
        time.sleep(0.1)
    log_text = log_path.read_text(encoding="utf-8", errors="replace")[-4000:] if log_path.exists() else ""
    raise RuntimeError(f"Node did not become ready ({last_error}). See {log_path}\n{log_text}")


def _record(record_id: str, node_id: str, key_id: str, indicator: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "record_id": record_id, "publisher_id": node_id, "key_id": key_id,
        "created_at": now, "indicator_type": "ipv4", "indicator": indicator,
        "classification": "scanning", "severity": "high", "source_system": "zeek",
        "first_seen": now, "last_seen": now, "observation_count": 1,
    }


def run_demo(data_parent: Path | None = None) -> dict:
    temp_context = None
    if data_parent is None:
        temp_context = tempfile.TemporaryDirectory(prefix="honeypot-live-node-demo-")
        data_dir = Path(temp_context.name)
    else:
        data_parent.mkdir(parents=True, exist_ok=True)
        data_dir = data_parent / f"demo-{secrets.token_hex(6)}"
        data_dir.mkdir()

    port_a, port_b = _free_port(), _free_port()
    while port_a == port_b:
        port_b = _free_port()
    env = dict(os.environ)
    for name in (
        "DEMO_A_KEY_PASSWORD", "DEMO_B_KEY_PASSWORD", "DEMO_A_ADMIN_TOKEN",
        "DEMO_B_ADMIN_TOKEN", "DEMO_A_TO_B_TOKEN", "DEMO_B_TO_A_TOKEN",
    ):
        env[name] = secrets.token_urlsafe(36)
    config_a, config_b = _write_configs(data_dir, port_a, port_b, env)
    url_a, url_b = f"http://127.0.0.1:{port_a}", f"http://127.0.0.1:{port_b}"
    process_a = process_b = None
    log_a, log_b = data_dir / "node-a.log", data_dir / "node-b.log"
    summary = {"node_a_port": port_a, "node_b_port": port_b}
    try:
        process_b = _start_node(config_b, port_b, env, log_b)
        _wait_ready(process_b, url_b, env["DEMO_A_TO_B_TOKEN"], log_b)
        process_a = _start_node(config_a, port_a, env, log_a)
        _wait_ready(process_a, url_a, env["DEMO_B_TO_A_TOKEN"], log_a)
        auth_a = {"Authorization": f"Bearer {env['DEMO_A_ADMIN_TOKEN']}"}
        auth_b = {"Authorization": f"Bearer {env['DEMO_B_ADMIN_TOKEN']}"}
        # Peer health checks inside Node A have a five-second failure timeout;
        # keep this caller's deadline longer so an expected offline peer is
        # returned as a health result instead of aborting the demonstration.
        with httpx.Client(timeout=8.0) as client:
            published = client.post(
                url_a + "/v1/intelligence/publish",
                headers=auth_a,
                json=_record("live-demo-record-001", "demo-node-a", "demo-node-a-key-v1", "198.51.100.47"),
            )
            published.raise_for_status()
            envelope = published.json()
            record_id = envelope["record"]["record_id"]
            first = client.post(url_a + f"/v1/peers/demo-node-b/sync/{record_id}", headers=auth_a)
            first.raise_for_status()
            first_result = first.json()
            detail = client.get(url_b + f"/v1/intelligence/{record_id}", headers=auth_b)
            detail.raise_for_status()
            imported = detail.json()
            duplicate = client.post(url_a + f"/v1/peers/demo-node-b/sync/{record_id}", headers=auth_a)
            duplicate.raise_for_status()
            tampered = dict(envelope)
            tampered["record"] = dict(envelope["record"], indicator="203.0.113.90")
            tamper_response = client.post(
                url_b + "/v1/intelligence/import",
                headers={"Authorization": f"Bearer {env['DEMO_A_TO_B_TOKEN']}"},
                json=tampered,
            )
            summary.update({
                "first_delivery": first_result["status"],
                "signature_valid_at_node_b": imported["signature_valid"],
                "node_b_record_state": imported["state"],
                "duplicate_delivery": duplicate.json()["status"],
                "tampered_delivery_http_status": tamper_response.status_code,
            })

            _stop(process_b)
            process_b = None
            offline = client.get(url_a + "/v1/peers/demo-node-b/health", headers=auth_a)
            offline.raise_for_status()
            node_a_records = client.get(url_a + "/v1/intelligence", headers=auth_a)
            node_a_records.raise_for_status()
            summary["offline_peer_status"] = offline.json()["status"]
            summary["node_a_local_record_count_while_offline"] = len(node_a_records.json()["records"])

            process_b = _start_node(config_b, port_b, env, log_b)
            _wait_ready(process_b, url_b, env["DEMO_A_TO_B_TOKEN"], log_b)
            restarted = client.get(url_b + f"/v1/intelligence/{record_id}", headers=auth_b)
            restarted.raise_for_status()
            duplicate_after_restart = client.post(url_a + f"/v1/peers/demo-node-b/sync/{record_id}", headers=auth_a)
            duplicate_after_restart.raise_for_status()

            second_publish = client.post(
                url_a + "/v1/intelligence/publish", headers=auth_a,
                json=_record("live-demo-record-002", "demo-node-a", "demo-node-a-key-v1", "1.1.1.1"),
            )
            second_publish.raise_for_status()
            second_id = second_publish.json()["record"]["record_id"]
            post_restart_sync = client.post(url_a + f"/v1/peers/demo-node-b/sync/{second_id}", headers=auth_a)
            post_restart_sync.raise_for_status()
            summary.update({
                "node_b_state_after_restart": restarted.json()["state"],
                "duplicate_after_restart": duplicate_after_restart.json()["status"],
                "post_restart_new_delivery": post_restart_sync.json()["status"],
                "node_b_local_record_count": len(client.get(url_b + "/v1/intelligence", headers=auth_b).json()["records"]),
            })
        summary["result"] = "passed"
        if data_parent is not None:
            summary["data_directory"] = str(data_dir)
        return summary
    finally:
        _stop(process_a)
        _stop(process_b)
        if temp_context is not None:
            temp_context.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, help="Keep demo-only keys, configs, logs, and node databases under a new unique subdirectory")
    args = parser.parse_args()
    try:
        result = run_demo(args.data_dir)
    except Exception as exc:
        print(json.dumps({"result": "failed", "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
