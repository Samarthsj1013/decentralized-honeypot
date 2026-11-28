from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("node_count", [3, 4, 5])
def test_live_multi_node_fanout_reject_invalid_and_recover(node_count):
    source_root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join((str(source_root / "backend"), str(source_root)))
    completed = subprocess.run(
        [sys.executable, "-m", "app.network.multi_node_demo", "--nodes", str(node_count)],
        cwd=source_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + "\n" + completed.stderr
    result = json.loads(completed.stdout)
    assert result["result"] == "passed"
    assert result["node_count"] == node_count
    assert len(result["first_delivery"]) == max(1, min(node_count, 3) - 1)
    assert set(result["first_delivery"].values()) == {"stored"}
    assert all(result["imports_signature_valid"].values())
    assert all(result["imports_pending"].values())
    assert set(result["duplicate_delivery"].values()) == {"duplicate"}
    assert result["tampered_delivery_http_status"] == 400
    assert result["untrusted_publisher_http_status"] == (403 if node_count > 3 else None)
    assert result["offline_peer_status"] == "unavailable"
    assert result["publisher_local_record_count_while_peer_offline"] == 1
    assert result["post_restart_delivery"] == "stored"
    assert result["post_restart_import_state"] == "pending"
    assert result["publisher_key_materials_unique"] is True
    assert result["node_databases_isolated"] is True
    assert len(result["node_database_identities"]) == node_count
    assert set(result["node_database_identities"].values()) == {
        f"dahin-node-{chr(ord('a') + index)}" for index in range(node_count)
    }
    assert all(value > 0 for value in result["transfer_latency_ms_by_receiver"].values())
