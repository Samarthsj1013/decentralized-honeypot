from datetime import datetime, timezone
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.experiments.models import ExperimentRequest
import app.experiments.service as experiment_service
from app.experiments.service import ExperimentService
from app.experiments.storage import ExperimentStorage
from app.experiments.closed_loop import (
    ContextualStrategyPolicy,
    simulate_reaction,
    strategy_reward,
)
from app.simulation.adversary import SCENARIOS, SyntheticEvent, generate_scenario


def test_all_scenario_events_are_normalized_and_seed_reproducible():
    for scenario in SCENARIOS:
        first = generate_scenario(scenario, 1234)
        again = generate_scenario(scenario, 1234)
        assert first == again
        assert first
        assert all(item.event_id.startswith("syn-") and item.source_ip == "198.51.100.10" for item in first)
        assert all(item.occurred_at.tzinfo == timezone.utc for item in first)


def test_experiment_storage_releases_sqlite_file_after_run(tmp_path):
    database = tmp_path / "closeable-experiments.sqlite3"
    service = ExperimentService(ExperimentStorage(database))
    result = service.run(ExperimentRequest(
        experiment_id="closeable-experiment", scenarios=["reconnaissance"],
        repetitions=1, seed=31, modes=["baseline"],
    ))

    assert database.exists()
    assert service.storage.get(result.experiment_id) == result
    database.unlink()
    assert not database.exists()


def test_experiment_pairs_identical_scenario_seeds_and_persists_reports(tmp_path):
    storage = ExperimentStorage(tmp_path / "experiments.sqlite3")
    service = ExperimentService(storage)
    request = ExperimentRequest(experiment_id="paired", scenarios=["multi_sensor_correlated_activity", "mixed_benign_suspicious_traffic"], repetitions=1, seed=21)
    result = service.run(request)
    grouped = {}
    for row in result.scenario_results:
        grouped.setdefault((row.scenario, row.repetition), []).append(row)
    assert all({row.seed for row in rows}.__len__() == 1 for rows in grouped.values())
    assert all({row.events_generated for row in rows}.__len__() == 1 for rows in grouped.values())
    for rows in grouped.values():
        baseline = next(row for row in rows if row.mode == "baseline")
        adaptive = next(row for row in rows if row.mode == "adaptive")
        assert baseline.adaptation_reason is None
        assert adaptive.adaptation_reason
    assert result.comparison.available
    adaptive_metrics = next(mode for mode in result.mode_metrics if mode.mode == "adaptive")
    baseline_metrics = next(mode for mode in result.mode_metrics if mode.mode == "baseline")
    assert adaptive_metrics.adaptation_effectiveness == pytest.approx(adaptive_metrics.detection_coverage - baseline_metrics.detection_coverage)
    assert adaptive_metrics.simulated_engagement_rate is not None
    assert baseline_metrics.simulated_engagement_rate is not None
    assert adaptive_metrics.mean_synthetic_interaction_depth is not None
    assert baseline_metrics.median_synthetic_session_duration_seconds is not None
    assert adaptive_metrics.unique_decoys_accessed is None
    assert any(metric.metric == "simulated_engagement_rate" for metric in result.comparison.metrics)
    repeat = ExperimentService(ExperimentStorage(tmp_path / "paired-repeat.sqlite3")).run(
        request.model_copy(update={"experiment_id": "paired-repeat"})
    )
    assert [
        (row.mode, row.attacker_reactions, row.simulated_attacker_engaged,
         row.simulated_interaction_depth, row.simulated_session_duration_seconds)
        for row in result.scenario_results
    ] == [
        (row.mode, row.attacker_reactions, row.simulated_attacker_engaged,
         row.simulated_interaction_depth, row.simulated_session_duration_seconds)
        for row in repeat.scenario_results
    ]
    assert storage.get("paired") == result
    assert storage.list(10, 0)[1] == 1
    assert "# Experiment paired" in service.report("paired", "markdown")[0]
    assert "scenario" in service.report("paired", "csv")[0]
    assert service.report("paired", "json")[1] == "application/json"
    with pytest.raises(HTTPException, match="already been used"):
        service.run(request)


def test_closed_loop_is_seeded_records_reactions_rewards_and_persists_locally(tmp_path):
    service = ExperimentService(ExperimentStorage(tmp_path / "closed-loop.sqlite3"))
    request = ExperimentRequest(
        experiment_id="closed-loop-a", scenarios=["reconnaissance", "mixed_benign_suspicious_traffic"],
        repetitions=2, seed=837, modes=["baseline", "adaptive", "closed_loop"],
    )
    first = service.run(request)
    second = ExperimentService(ExperimentStorage(tmp_path / "second.sqlite3")).run(
        request.model_copy(update={"experiment_id": "closed-loop-b"})
    )
    first_rows = [row for row in first.scenario_results if row.mode == "closed_loop"]
    second_rows = [row for row in second.scenario_results if row.mode == "closed_loop"]
    assert len(first_rows) == 4
    assert [(row.selected_strategy, row.attacker_reactions, row.strategy_reward) for row in first_rows] == [
        (row.selected_strategy, row.attacker_reactions, row.strategy_reward) for row in second_rows
    ]
    assert all(row.policy_version == "contextual-epsilon-greedy-v1" for row in first_rows)
    assert all(row.strategy_reward is not None and -1 <= row.strategy_reward <= 1 for row in first_rows)
    assert service.storage.get("closed-loop-a") == first
    assert "policy_version" in service.report("closed-loop-a", "csv")[0]
    assert "closed loop" in service.report("closed-loop-a", "markdown")[0].lower()
    closed_metrics = next(row for row in first.mode_metrics if row.mode == "closed_loop")
    assert sum(closed_metrics.strategy_selection_counts.values()) == 4
    assert closed_metrics.mean_strategy_reward == pytest.approx(
        sum(row.strategy_reward for row in first_rows) / len(first_rows)
    )
    assert first.comparison.available
    assert all(metric.closed_loop is not None or metric.metric in {"adaptation_effectiveness", "unique_decoys_accessed"} for metric in first.comparison.metrics)
    assert next(metric for metric in first.comparison.metrics if metric.metric == "unique_decoys_accessed").closed_loop is None


def test_closed_loop_reaction_engine_includes_deterministic_ineffective_case():
    events = generate_scenario("repeated_session_behavior", 77)
    first = simulate_reaction(events, "repeated_connection", "file_decoy", 0)
    second = simulate_reaction(events, "repeated_connection", "file_decoy", 0)
    assert first == second
    assert first[1] == ["abandon"]
    assert first[0] == []


def test_closed_loop_policy_has_bounded_updates_and_exploration():
    policy = ContextualStrategyPolicy(9)
    decisions = [policy.select("authentication_probing") for _ in range(12)]
    assert all(decision.policy_version == "contextual-epsilon-greedy-v1" for decision in decisions)
    assert all(decision.strategy in {"static_baseline", "expanded_decoy_path", "credential_decoy", "file_decoy", "neutral_response"} for decision in decisions)
    policy.update(decisions[0].strategy, 1.0)
    with pytest.raises(ValueError):
        policy.update(decisions[0].strategy, 1.01)


def test_closed_loop_reward_is_bounded_and_penalizes_false_positives_and_cost():
    base = strategy_reward(
        true_positives=2, suspicious_events=2, false_positives=0,
        benign_events=2, incident_detected=True, reactions=["continue_session"],
        reaction_events=1, original_events=2, strategy="static_baseline",
    )
    penalized = strategy_reward(
        true_positives=2, suspicious_events=2, false_positives=2,
        benign_events=2, incident_detected=True, reactions=["continue_session"],
        reaction_events=1, original_events=2, strategy="file_decoy",
    )
    assert -1 <= penalized < base <= 1


def test_metric_rates_are_calculated_from_ground_truth_and_predictions(tmp_path):
    service = ExperimentService(ExperimentStorage(tmp_path / "metrics.sqlite3"))
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    # At baseline threshold, only the third failed login onward is detected.
    records = [SyntheticEvent(event_id=f"e{i}", occurred_at=now.replace(second=i), event_type="cowrie_login_failed", source_system="cowrie", sensor_id="sensor-a", destination_port=22, protocol="ssh", suspicious=True, attributes={"authentication_outcome": "failed"}) for i in range(3)]
    scenario, _ = service._evaluate_scenario("repeated_failed_authentication", 1, 8, records, "baseline", "static_baseline", None, None, {"auth": 3, "ports": 5, "commands": 3, "protocols": 3, "sensors": 2})
    assert scenario.true_positives == 1
    assert scenario.false_negatives == 2
    assert scenario.false_positives == 0
    aggregate = service._aggregate("baseline", [scenario], 1)
    assert aggregate.detection_coverage == pytest.approx(1 / 3)
    assert aggregate.false_negative_rate == pytest.approx(2 / 3)
    assert aggregate.event_capture_rate == 1
    assert aggregate.peak_memory_bytes is None


def test_false_positive_rate_uses_benign_ground_truth(tmp_path):
    service = ExperimentService(ExperimentStorage(tmp_path / "false-positive.sqlite3"))
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = [SyntheticEvent(event_id=f"b{i}", occurred_at=now.replace(second=i), event_type="zeek_connection", source_system="zeek", sensor_id="sensor-a", destination_port=port, protocol="tcp", suspicious=False, attributes={}) for i, port in enumerate((21, 22, 23, 80, 443))]
    result, _ = service._evaluate_scenario("mixed_benign_suspicious_traffic", 1, 5, rows, "baseline", "static_baseline", None, None, {"auth": 3, "ports": 5, "commands": 3, "protocols": 3, "sensors": 2})
    assert result.false_positives == 1
    assert result.false_negatives == 0
    metrics = service._aggregate("baseline", [result], 1)
    assert metrics.false_positive_rate == pytest.approx(0.2)
    assert metrics.false_negative_rate is None


def test_scenario_processing_timer_covers_only_event_processing_loop(monkeypatch):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = [SyntheticEvent(
        event_id="timed-event", occurred_at=now, event_type="zeek_connection",
        source_system="zeek", sensor_id="sensor-a", destination_port=22,
        protocol="tcp", suspicious=False, attributes={},
    )]
    ticks = iter((10.0, 10.125))
    monkeypatch.setattr(experiment_service, "perf_counter", lambda: next(ticks))

    result, elapsed_ms = ExperimentService._evaluate_scenario(
        "reconnaissance", 1, 17, rows, "baseline", "static_baseline", None,
        None, {"auth": 3, "ports": 5, "commands": 3, "protocols": 3, "sensors": 2},
    )

    assert result.completed is True
    assert result.processing_time_ms == pytest.approx(125.0)
    assert elapsed_ms == pytest.approx(125.0)


def test_bounds_duplicate_modes_and_unknown_scenarios_rejected():
    with pytest.raises(ValueError):
        ExperimentRequest(scenarios=["reconnaissance", "reconnaissance"])
    with pytest.raises(ValueError):
        ExperimentRequest(modes=["baseline", "baseline"])
    with pytest.raises(ValueError):
        ExperimentRequest(scenarios=["not-a-scenario"])
    with pytest.raises(ValueError):
        ExperimentRequest(scenarios=["reconnaissance"], repetitions=11, modes=["baseline", "adaptive"])


def test_unpaired_mode_has_no_comparison_and_not_found_is_reported(tmp_path):
    service = ExperimentService(ExperimentStorage(tmp_path / "unpaired.sqlite3"))
    result = service.run(ExperimentRequest(experiment_id="one-mode", scenarios=["reconnaissance"], modes=["baseline"], seed=2))
    assert not result.comparison.available
    assert result.comparison.metrics == []
    with pytest.raises(HTTPException) as error:
        service.get("missing")
    assert error.value.status_code == 404


def test_experiment_storage_failure_returns_error_without_overwrite(tmp_path, monkeypatch):
    storage = ExperimentStorage(tmp_path / "failure.sqlite3")
    service = ExperimentService(storage)
    monkeypatch.setattr(storage, "save", lambda _result: (_ for _ in ()).throw(RuntimeError("disk unavailable")))
    with pytest.raises(HTTPException) as error:
        service.run(ExperimentRequest(experiment_id="disk-error", scenarios=["reconnaissance"], modes=["baseline"]))
    assert error.value.status_code == 503
    assert storage.get("disk-error") is None


def test_scenario_failure_is_persisted_with_unavailable_metrics(tmp_path, monkeypatch):
    def fail(*_args, **_kwargs):
        raise RuntimeError("injected failure detail must not leak")
    monkeypatch.setattr(ExperimentService, "_evaluate_scenario", staticmethod(fail))
    result = ExperimentService(ExperimentStorage(tmp_path / "run-failure.sqlite3")).run(
        ExperimentRequest(experiment_id="run-failure", scenarios=["reconnaissance"], seed=4)
    )
    assert all(not row.completed for row in result.scenario_results)
    assert all("injected failure detail" not in row.errors[0] for row in result.scenario_results)
    for metrics in result.mode_metrics:
        assert metrics.scenarios_completed == 0
        assert metrics.scenario_completion_rate == 0
        assert metrics.event_capture_rate is None
        assert metrics.detection_coverage is None
        assert metrics.incident_detection_rate is None
        assert metrics.detector_false_negatives is None
        assert metrics.execution_time_seconds is None


def test_experiment_api_routes_are_registered():
    from app.api.routes import router
    paths = {route.path for route in router.routes}
    assert {"/api/v1/experiments/run", "/api/v1/experiments", "/api/v1/experiments/{experiment_id}", "/api/v1/experiments/{experiment_id}/results", "/api/v1/experiments/{experiment_id}/comparison", "/api/v1/experiments/{experiment_id}/report"} <= paths


def test_experiment_api_executes_and_exports_stored_results(tmp_path, monkeypatch):
    from app.api import routes
    from app.main import app

    monkeypatch.setattr(routes, "experiment_service", ExperimentService(ExperimentStorage(tmp_path / "api-experiments.sqlite3")))
    client = TestClient(app)
    response = client.post("/api/v1/experiments/run", json={"experiment_id": "api-demo", "scenarios": ["reconnaissance"], "repetitions": 1, "seed": 11, "modes": ["baseline", "adaptive"]})
    assert response.status_code == 201
    assert response.json()["experiment_id"] == "api-demo"
    assert client.get("/api/v1/experiments").json()["items"][0]["experiment_id"] == "api-demo"
    assert len(client.get("/api/v1/experiments/api-demo/results").json()) == 2
    assert client.get("/api/v1/experiments/api-demo/comparison").json()["available"] is True
    assert client.get("/api/v1/experiments/api-demo/report?format=json").json()["experiment_id"] == "api-demo"
    assert "row_type" in client.get("/api/v1/experiments/api-demo/report?format=csv").text
    assert client.get("/api/v1/experiments/api-demo/report?format=markdown").text.startswith("# Experiment api-demo")
    assert client.post("/api/v1/experiments/run", json={"experiment_id": "api-demo", "scenarios": ["reconnaissance"]}).status_code == 409


def test_experiment_api_accepts_closed_loop_mode_and_returns_feedback(tmp_path, monkeypatch):
    from app.api import routes
    from app.main import app

    monkeypatch.delenv("HONEYPOT_API_READ_TOKEN", raising=False)
    monkeypatch.delenv("HONEYPOT_API_ADMIN_TOKEN", raising=False)
    monkeypatch.setattr(routes, "experiment_service", ExperimentService(ExperimentStorage(tmp_path / "closed-loop-api.sqlite3")))
    client = TestClient(app)
    response = client.post(
        "/api/v1/experiments/run",
        json={
            "experiment_id": "closed-loop-api", "scenarios": ["reconnaissance"],
            "seed": 606, "modes": ["baseline", "adaptive", "closed_loop"],
        },
    )
    assert response.status_code == 201
    payload = response.json()
    closed = next(row for row in payload["scenario_results"] if row["mode"] == "closed_loop")
    assert closed["policy_version"] == "contextual-epsilon-greedy-v1"
    assert closed["attacker_reactions"]
    assert -1 <= closed["strategy_reward"] <= 1
