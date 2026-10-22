from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.routes import attack_simulation_service
from app.main import app


client = TestClient(app)


@pytest.mark.parametrize(
    ("scenario", "repeat_count", "expected_actions"),
    [
        ("reconnaissance", 2, ["read"]),
        ("credential_probing", 2, ["attempt_login"]),
        ("database_probing", 2, ["query"]),
        (
            "multi_stage",
            2,
            ["read", "attempt_login", "query"],
        ),
        ("repeated_access", 3, ["read", "read", "read"]),
    ],
)
def test_scenarios_record_expected_actions(
    scenario,
    repeat_count,
    expected_actions,
):
    payload = {
        "scenario": scenario,
        "simulation_id": f"sim-{uuid4().hex}",
        "actor_id": f"actor-{uuid4().hex}",
    }
    if scenario == "repeated_access":
        payload["repeat_count"] = repeat_count

    response = client.post("/api/v1/simulation/runs", json=payload)

    assert response.status_code == 201
    summary = response.json()
    assert summary["interactions_attempted"] == len(expected_actions)
    assert summary["interactions_recorded"] == len(expected_actions)
    assert summary["observed_actions"] == expected_actions
    assert len(summary["event_ids"]) == len(expected_actions)
    assert len(set(summary["event_ids"])) == len(expected_actions)
    assert summary["errors"] == []
    assert summary["duplicate_decoys_avoided"] is None


def test_scenarios_endpoint_lists_supported_scenarios():
    response = client.get("/api/v1/simulation/scenarios")

    assert response.status_code == 200
    assert {scenario["name"] for scenario in response.json()} == {
        "reconnaissance",
        "credential_probing",
        "database_probing",
        "multi_stage",
        "repeated_access",
    }


def test_multi_stage_changes_strategy_and_persists_generated_decoys():
    actor_id = f"actor-{uuid4().hex}"
    response = client.post(
        "/api/v1/simulation/runs",
        json={
            "scenario": "multi_stage",
            "simulation_id": f"sim-{uuid4().hex}",
            "actor_id": actor_id,
        },
    )

    assert response.status_code == 201
    summary = response.json()
    assert summary["initial_adaptation_strategy"] == "neutral_response"
    assert summary["final_adaptation_strategy"] == "expanded_decoy_path"
    assert summary["observed_strategies"] == [
        "file_decoy",
        "credential_decoy",
        "expanded_decoy_path",
    ]
    assert summary["strategy_change_count"] == 3
    assert summary["decoys_generated"] == 6
    assert len(summary["generated_decoy_ids"]) == 6
    assert summary["generated_decoy_categories"] == {
        "credential": 2,
        "database_record": 1,
        "file": 3,
    }
    assert len(summary["bundle_ids"]) == 3
    assert all(result["valid"] for result in summary["bundle_validation_results"])
    listed = client.get("/api/v1/decoys")
    assert listed.status_code == 200
    listed_ids = {decoy["decoy_id"] for decoy in listed.json()}
    assert len(summary["observed_decoys"]) == 3
    assert len(set(summary["event_ids"])) == 3
    assert set(summary["generated_decoy_ids"]).issubset(listed_ids)


def test_policy_lanes_compare_neutral_baseline_with_behavior_conditioning():
    baseline = client.post(
        "/api/v1/simulation/runs",
        json={
            "scenario": "credential_probing",
            "simulation_id": f"sim-{uuid4().hex}",
            "actor_id": f"actor-{uuid4().hex}",
            "policy_mode": "baseline",
        },
    )
    conditioned = client.post(
        "/api/v1/simulation/runs",
        json={
            "scenario": "credential_probing",
            "simulation_id": f"sim-{uuid4().hex}",
            "actor_id": f"actor-{uuid4().hex}",
            "policy_mode": "behavior_conditioned",
        },
    )

    assert baseline.status_code == conditioned.status_code == 201
    baseline_summary = baseline.json()
    conditioned_summary = conditioned.json()
    assert baseline_summary["final_adaptation_strategy"] == "neutral_response"
    assert baseline_summary["strategy_change_count"] == 0
    assert baseline_summary["decoys_generated"] == 0
    assert conditioned_summary["final_adaptation_strategy"] == "credential_decoy"
    assert conditioned_summary["strategy_change_count"] == 1
    assert conditioned_summary["decoys_generated"] == 1


def test_repeated_access_records_each_event_without_extra_decoys():
    response = client.post(
        "/api/v1/simulation/runs",
        json={
            "scenario": "repeated_access",
            "simulation_id": f"sim-{uuid4().hex}",
            "actor_id": f"actor-{uuid4().hex}",
            "repeat_count": 4,
        },
    )

    assert response.status_code == 201
    summary = response.json()
    assert summary["interactions_recorded"] == 4
    assert summary["observed_decoys"] == [
        "decoy-finance-001",
        "decoy-finance-001",
        "decoy-finance-001",
        "decoy-finance-001",
    ]
    assert summary["decoys_generated"] == 1
    assert len(summary["generated_decoy_ids"]) == 1
    assert len(set(summary["event_ids"])) == 4


def test_actor_history_does_not_contaminate_another_simulation():
    actor_one = f"actor-{uuid4().hex}"
    actor_two = f"actor-{uuid4().hex}"

    first = client.post(
        "/api/v1/simulation/runs",
        json={
            "scenario": "credential_probing",
            "simulation_id": f"sim-{uuid4().hex}",
            "actor_id": actor_one,
        },
    )
    second = client.post(
        "/api/v1/simulation/runs",
        json={
            "scenario": "database_probing",
            "simulation_id": f"sim-{uuid4().hex}",
            "actor_id": actor_two,
        },
    )

    assert first.status_code == second.status_code == 201
    assert first.json()["observed_actions"] == ["attempt_login"]
    assert second.json()["observed_actions"] == ["query"]
    assert first.json()["actor_id"] != second.json()["actor_id"]
    assert first.json()["event_ids"] != second.json()["event_ids"]


def test_failed_interaction_is_reported_honestly(monkeypatch):
    def fail_interaction(*args, **kwargs):
        raise RuntimeError("simulated interaction failure")

    monkeypatch.setattr(
        attack_simulation_service._workflow,
        "record_interaction",
        fail_interaction,
    )
    simulation_id = f"sim-{uuid4().hex}"
    response = client.post(
        "/api/v1/simulation/runs",
        json={
            "scenario": "reconnaissance",
            "simulation_id": simulation_id,
            "actor_id": f"actor-{uuid4().hex}",
        },
    )

    assert response.status_code == 201
    summary = response.json()
    assert summary["interactions_attempted"] == 1
    assert summary["interactions_recorded"] == 0
    assert summary["event_ids"] == []
    assert summary["errors"][0]["message"] == "simulated interaction failure"
    assert summary["decoys_generated"] == 0

    retrieved = client.get(f"/api/v1/simulation/runs/{simulation_id}")
    assert retrieved.status_code == 200
    assert retrieved.json() == summary


def test_generation_failure_is_not_counted_as_success(monkeypatch):
    def fail_generation(*args, **kwargs):
        raise RuntimeError("synthetic generation failure")

    monkeypatch.setattr(
        attack_simulation_service._workflow._bundle_generator,
        "generate_bundle",
        fail_generation,
    )
    response = client.post(
        "/api/v1/simulation/runs",
        json={
            "scenario": "credential_probing",
            "simulation_id": f"sim-{uuid4().hex}",
            "actor_id": f"actor-{uuid4().hex}",
        },
    )

    assert response.status_code == 201
    summary = response.json()
    assert summary["interactions_recorded"] == 1
    assert summary["decoys_generated"] == 0
    assert summary["generated_decoy_ids"] == []
    assert "Interaction was recorded" in summary["errors"][0]["message"]
    assert "synthetic generation failure" in summary["errors"][0]["message"]
    assert summary["final_adaptation_strategy"] == "neutral_response"


@pytest.mark.parametrize(
    "payload",
    [
        {"scenario": "unknown"},
        {"scenario": "repeated_access", "repeat_count": 1},
        {"scenario": "repeated_access", "repeat_count": 6},
        {"scenario": "multi_stage", "repeat_count": 3},
        {"scenario": "reconnaissance", "actor_id": "not allowed"},
    ],
)
def test_invalid_scenario_inputs_are_rejected(payload):
    response = client.post("/api/v1/simulation/runs", json=payload)

    assert response.status_code == 422


def test_actor_or_simulation_id_cannot_be_reused():
    actor_id = f"actor-{uuid4().hex}"
    simulation_id = f"sim-{uuid4().hex}"
    payload = {
        "scenario": "reconnaissance",
        "simulation_id": simulation_id,
        "actor_id": actor_id,
    }

    assert client.post("/api/v1/simulation/runs", json=payload).status_code == 201
    assert client.post("/api/v1/simulation/runs", json=payload).status_code == 409
    assert client.post(
        "/api/v1/simulation/runs",
        json={
            "scenario": "credential_probing",
            "simulation_id": f"sim-{uuid4().hex}",
            "actor_id": actor_id,
        },
    ).status_code == 409


def test_unknown_simulation_run_returns_404():
    response = client.get(f"/api/v1/simulation/runs/missing-{uuid4().hex}")

    assert response.status_code == 404
