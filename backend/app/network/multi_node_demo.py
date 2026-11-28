"""Run a local multi-process replication experiment with isolated node stores.

The prototype uses direct HTTP fan-out from one publisher. It has no relay,
quorum, consensus, or Byzantine fault-tolerance protocol.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.network import live_demo


def _unused_port(used: set[int]) -> int:
    while True:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = int(listener.getsockname()[1])
        if port not in used:
            used.add(port)
            return port


def _node_ids(count: int) -> list[str]:
    return [f"dahin-node-{chr(ord('a') + index)}" for index in range(count)]


def _make_node_files(directory: Path, count: int, ports: list[int], env: dict[str, str]) -> tuple[list[Path], list[Path], list[Path]]:
    node_ids = _node_ids(count)
    private_paths: list[Path] = []
    public_paths: list[Path] = []
    for index, node_id in enumerate(node_ids):
        private_path, public_path = live_demo._keypair(directory, node_id, env[f"DAHIN_{index}_KEY_PASSWORD"])
        private_paths.append(private_path)
        public_paths.append(public_path)

    configs: list[Path] = []
    for index, node_id in enumerate(node_ids):
        trusted: dict[str, dict[str, str]] = {}
        peers: dict[str, dict[str, str]] = {}
        if index == 0:
            # Publisher A explicitly trusts and directly fans out to B and C.
            for receiver_index in range(1, min(count, 3)):
                receiver_id = node_ids[receiver_index]
                trusted[receiver_id] = {
                    "key_id": f"{receiver_id}-key-v1",
                    "public_key_file": str(public_paths[receiver_index]),
                    "incoming_token_env": f"DAHIN_{receiver_index}_TO_A_TOKEN",
                }
                peers[receiver_id] = {
                    "base_url": f"http://127.0.0.1:{ports[receiver_index]}",
                    "outgoing_token_env": f"DAHIN_A_TO_{receiver_index}_TOKEN",
                }
        elif index in (1, 2):
            trusted[node_ids[0]] = {
                "key_id": f"{node_ids[0]}-key-v1",
                "public_key_file": str(public_paths[0]),
                "incoming_token_env": f"DAHIN_A_TO_{index}_TOKEN",
            }

        config = {
            "node_id": node_id,
            "key_id": f"{node_id}-key-v1",
            "private_key_file": str(private_paths[index]),
            "private_key_password_env": f"DAHIN_{index}_KEY_PASSWORD",
            "database_path": str(directory / f"{node_id}.sqlite3"),
            "admin_token_env": f"DAHIN_{index}_ADMIN_TOKEN",
            "trusted_publishers": trusted,
            "peers": peers,
        }
        config_path = directory / f"{node_id}-config.json"
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        configs.append(config_path)
    return configs, private_paths, public_paths


def _wait_for_untrusted_listener(process: subprocess.Popen, url: str, log_path: Path) -> None:
    """A 401 from the protected health route proves the untrusted node is up."""
    deadline = time.monotonic() + 20
    last_status: int | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            response = httpx.get(url + "/health", timeout=0.5)
            last_status = response.status_code
            if response.status_code == 401:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    details = log_path.read_text(encoding="utf-8", errors="replace")[-2000:] if log_path.exists() else ""
    raise RuntimeError(f"Untrusted node listener did not become ready (last HTTP status {last_status}). {details}")


def run_demo(node_count: int = 4, data_parent: Path | None = None) -> dict:
    if type(node_count) is not int or not 3 <= node_count <= 5:
        raise ValueError("node count must be between 3 and 5")
    context = None
    if data_parent is None:
        context = tempfile.TemporaryDirectory(prefix="dahin-multi-node-demo-")
        directory = Path(context.name)
    else:
        data_parent.mkdir(parents=True, exist_ok=True)
        directory = data_parent / f"run-{secrets.token_hex(6)}"
        directory.mkdir()

    node_ids = _node_ids(node_count)
    ports: list[int] = []
    used_ports: set[int] = set()
    for _ in node_ids:
        ports.append(_unused_port(used_ports))
    env = dict(os.environ)
    for index in range(node_count):
        env[f"DAHIN_{index}_KEY_PASSWORD"] = secrets.token_urlsafe(36)
        env[f"DAHIN_{index}_ADMIN_TOKEN"] = secrets.token_urlsafe(36)
    for receiver_index in (1, 2):
        if receiver_index < node_count:
            env[f"DAHIN_A_TO_{receiver_index}_TOKEN"] = secrets.token_urlsafe(36)
            env[f"DAHIN_{receiver_index}_TO_A_TOKEN"] = secrets.token_urlsafe(36)

    configs, private_paths, _public_paths = _make_node_files(directory, node_count, ports, env)
    urls = [f"http://127.0.0.1:{port}" for port in ports]
    processes: dict[int, subprocess.Popen] = {}
    logs = {index: directory / f"{node_ids[index]}.log" for index in range(node_count)}
    summary: dict = {
        "result": "failed",
        "node_count": node_count,
        "publisher": node_ids[0],
        "trusted_receivers": node_ids[1:min(node_count, 3)],
        "untrusted_receivers": node_ids[3:],
    }
    try:
        for index in range(1, node_count):
            node_env = dict(env)
            node_env["HONEYPOT_NODE_CONFIG"] = str(configs[index])
            process = live_demo._start_node(configs[index], ports[index], node_env, logs[index])
            processes[index] = process
            if index < 3:
                token = env[f"DAHIN_A_TO_{index}_TOKEN"]
                live_demo._wait_ready(process, urls[index], token, logs[index])
            else:
                _wait_for_untrusted_listener(process, urls[index], logs[index])

        node_a_env = dict(env)
        node_a_env["HONEYPOT_NODE_CONFIG"] = str(configs[0])
        processes[0] = live_demo._start_node(configs[0], ports[0], node_a_env, logs[0])
        live_demo._wait_ready(processes[0], urls[0], env["DAHIN_1_TO_A_TOKEN"], logs[0])

        headers = {
            index: {"Authorization": f"Bearer {env[f'DAHIN_{index}_ADMIN_TOKEN']}"}
            for index in range(node_count)
        }
        with httpx.Client(timeout=9.0) as client:
            created = client.post(
                urls[0] + "/v1/intelligence/publish",
                headers=headers[0],
                json=live_demo._record("dahin-multi-node-record-001", node_ids[0], f"{node_ids[0]}-key-v1", "198.51.100.47"),
            )
            created.raise_for_status()
            envelope = created.json()
            record_id = envelope["record"]["record_id"]
            sync_latencies: dict[str, float] = {}
            first_results: dict[str, str] = {}
            for receiver_index in range(1, min(node_count, 3)):
                started = time.perf_counter()
                response = client.post(
                    urls[0] + f"/v1/peers/{node_ids[receiver_index]}/sync/{record_id}",
                    headers=headers[0],
                )
                response.raise_for_status()
                sync_latencies[node_ids[receiver_index]] = round((time.perf_counter() - started) * 1000, 3)
                first_results[node_ids[receiver_index]] = response.json()["status"]

            imports: dict[str, dict] = {}
            for receiver_index in range(1, min(node_count, 3)):
                detail = client.get(urls[receiver_index] + f"/v1/intelligence/{record_id}", headers=headers[receiver_index])
                detail.raise_for_status()
                imports[node_ids[receiver_index]] = detail.json()

            duplicate_results: dict[str, str] = {}
            for receiver_index in range(1, min(node_count, 3)):
                duplicate = client.post(
                    urls[0] + f"/v1/peers/{node_ids[receiver_index]}/sync/{record_id}",
                    headers=headers[0],
                )
                duplicate.raise_for_status()
                duplicate_results[node_ids[receiver_index]] = duplicate.json()["status"]

            tampered = dict(envelope)
            tampered["record"] = dict(envelope["record"], indicator="203.0.113.77")
            tamper = client.post(
                urls[1] + "/v1/intelligence/import",
                headers={"Authorization": f"Bearer {env['DAHIN_A_TO_1_TOKEN']}"},
                json=tampered,
            )
            if node_count > 3:
                untrusted = client.post(
                    urls[3] + "/v1/intelligence/import",
                    headers={"Authorization": "Bearer untrusted-publisher-test"},
                    json=envelope,
                )
                untrusted_status = untrusted.status_code
            else:
                untrusted_status = None

            recovery_node = 2 if node_count > 2 else 1
            live_demo._stop(processes[recovery_node])
            processes.pop(recovery_node, None)
            offline = client.get(
                urls[0] + f"/v1/peers/{node_ids[recovery_node]}/health",
                headers=headers[0],
            )
            offline.raise_for_status()
            local = client.get(urls[0] + "/v1/intelligence", headers=headers[0])
            local.raise_for_status()
            offline_state = offline.json()["status"]
            local_records_while_offline = len(local.json()["records"])

            node_env = dict(env)
            node_env["HONEYPOT_NODE_CONFIG"] = str(configs[recovery_node])
            processes[recovery_node] = live_demo._start_node(
                configs[recovery_node], ports[recovery_node], node_env, logs[recovery_node]
            )
            live_demo._wait_ready(
                processes[recovery_node], urls[recovery_node],
                env[f"DAHIN_A_TO_{recovery_node}_TOKEN"], logs[recovery_node],
            )
            second = client.post(
                urls[0] + "/v1/intelligence/publish",
                headers=headers[0],
                json=live_demo._record("dahin-multi-node-record-002", node_ids[0], f"{node_ids[0]}-key-v1", "203.0.113.21"),
            )
            second.raise_for_status()
            second_id = second.json()["record"]["record_id"]
            recovered = client.post(
                urls[0] + f"/v1/peers/{node_ids[recovery_node]}/sync/{second_id}",
                headers=headers[0],
            )
            recovered.raise_for_status()
            recovered_detail = client.get(
                urls[recovery_node] + f"/v1/intelligence/{second_id}",
                headers=headers[recovery_node],
            )
            recovered_detail.raise_for_status()

        key_digests = {hashlib.sha256(path.read_bytes()).hexdigest() for path in private_paths}
        database_paths = [directory / f"{node_id}.sqlite3" for node_id in node_ids]
        database_identities: dict[str, str | None] = {}
        for node_id, database_path in zip(node_ids, database_paths, strict=True):
            with closing(sqlite3.connect(database_path)) as database:
                row = database.execute("SELECT node_id FROM network_node_identity WHERE slot=1").fetchone()
            database_identities[node_id] = row[0] if row else None
        databases_isolated = (
            all(path.is_file() for path in database_paths)
            and len({path.resolve() for path in database_paths}) == node_count
            and database_identities == {node_id: node_id for node_id in node_ids}
        )
        summary.update({
            "first_delivery": first_results,
            "imports_signature_valid": {node_id: detail["signature_valid"] for node_id, detail in imports.items()},
            "imports_pending": {node_id: detail["state"] == "pending" for node_id, detail in imports.items()},
            "duplicate_delivery": duplicate_results,
            "tampered_delivery_http_status": tamper.status_code,
            "untrusted_publisher_http_status": untrusted_status,
            "offline_peer_status": offline_state,
            "publisher_local_record_count_while_peer_offline": local_records_while_offline,
            "post_restart_delivery": recovered.json()["status"],
            "post_restart_import_state": recovered_detail.json()["state"],
            "publisher_key_materials_unique": len(key_digests) == node_count,
            "node_database_identities": database_identities,
            "node_databases_isolated": databases_isolated,
            "transfer_latency_ms_by_receiver": sync_latencies,
        })
        required_success = (
            all(value == "stored" for value in first_results.values())
            and all(value == "duplicate" for value in duplicate_results.values())
            and all(detail["signature_valid"] and detail["state"] == "pending" for detail in imports.values())
            and tamper.status_code == 400
            and (untrusted_status is None or untrusted_status == 403)
            and offline_state == "unavailable"
            and local_records_while_offline == 1
            and recovered.json()["status"] == "stored"
            and recovered_detail.json()["state"] == "pending"
            and len(key_digests) == node_count
            and databases_isolated
        )
        summary["result"] = "passed" if required_success else "failed"
        summary["transport"] = "direct localhost HTTP; no relay or consensus"
        return summary
    finally:
        for process in processes.values():
            live_demo._stop(process)
        if context is not None:
            context.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", type=int, default=4, choices=range(3, 6))
    parser.add_argument("--data-dir", type=Path, help="Keep generated keys, databases, configs, and logs in a new unique subdirectory")
    args = parser.parse_args(argv)
    try:
        result = run_demo(args.nodes, args.data_dir)
    except Exception as exc:
        result = {"result": "failed", "error_type": type(exc).__name__}
        print(json.dumps(result, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
