from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.evaluation.models import EvaluationRequest, EvaluationRunResult
from app.evaluation.service import EvaluationService
from app.evaluation.storage import SQLiteEvaluationStorage
from app.main import app
from app.simulation.models import (
    ScenarioName,
    SimulationError,
    SimulationRunRequest,
    SimulationRunSummary,
)
from app.simulation.service import AttackSimulationService, SCENARIOS


client = TestClient(app)


def make_summary(
    request: SimulationRunRequest,
    *,
    attempted: int,
    recorded: int,
    elapsed: float,
    strategy_changes: int | None = 0,
    decoys_generated: int = 0,
    error_count: int = 0,
) -> SimulationRunSummary:
    now = datetime.now(timezone.utc)
    return SimulationRunSummary(
        simulation_id=request.simulation_id,
        actor_id=request.actor_id,
        scenario=request.scenario,
        interactions_attempted=attempted,
        interactions_recorded=recorded,
        event_ids=[f"{request.simulation_id}-{i}" for i in range(recorded)],
        observed_actions=["read"] * recorded,
        observed_decoys=["decoy-finance-001"] * recorded,
        initial_adaptation_strategy=None,
        final_adaptation_strategy="neutral_response" if recorded else None,
        observed_strategies=["neutral_response"] * recorded,
        strategy_change_count=strategy_changes,
        decoys_generated=decoys_generated,
        generated_decoy_ids=[f"generated-{i}" for i in range(decoys_generated)],
        errors=[
            SimulationError(
                step=index + 1,
                decoy_id="decoy-finance-001",
                action="read",
                message="synthetic test failure",
            )
            for index in range(error_count)
        ],
        started_at=now,
        ended_at=now,
        elapsed_seconds=elapsed,
    )


class ControlledSimulationService:
    def expected_actions(
        self,
        scenario: ScenarioName,
        repeat_count: int = 2,
    ) -> list[str]:
        return AttackSimulationService.expected_actions(scenario, repeat_count)

    def run(self, request: SimulationRunRequest) -> SimulationRunSummary:
        if request.scenario == "credential_probing":
            raise HTTPException(status_code=503, detail="synthetic run failure")
        if request.scenario == "database_probing":
            return make_summary(
                request,
                attempted=1,
                recorded=0,
                elapsed=0.03,
                strategy_changes=0,
                error_count=1,
            )
        if request.scenario == "multi_stage":
            return make_summary(
                request,
                attempted=3,
                recorded=3,
                elapsed=0.08,
                strategy_changes=2,
                decoys_generated=4,
            )
        if request.scenario == "repeated_access":
            return make_summary(
                request,
                attempted=request.repeat_count,
                recorded=request.repeat_count,
                elapsed=0.02,
            )
        return make_summary(
            request,
            attempted=1,
            recorded=1,
            elapsed=0.01,
        )


def test_evaluation_aggregates_completed_incomplete_and_failed_runs(tmp_path):
    storage = SQLiteEvaluationStorage(tmp_path / "evaluations.sqlite3")
    evaluation = EvaluationService(ControlledSimulationService(), storage)

    summary = evaluation.run(
        EvaluationRequest(evaluation_id="aggregate-test", repetitions=2)
    )

    assert summary.status == "partial"
    assert summary.overall.runs_requested == 10
    assert summary.overall.runs_with_summary == 8
    assert summary.overall.completed_runs == 6
    assert summary.overall.incomplete_runs == 2
    assert summary.overall.failed_runs == 2
    assert summary.overall.completion_rate == 0.6
    assert summary.overall.interactions_attempted == 14
    assert summary.overall.interactions_recorded == 12
    assert summary.overall.event_recording_rate == 12 / 14
    assert summary.overall.strategy_measurement_runs == 8
    assert summary.overall.strategy_changed_runs == 2
    assert summary.overall.strategy_change_rate == 0.25
    assert summary.overall.decoy_generation_runs == 2
    assert summary.overall.decoy_generation_rate == 0.25
    assert summary.overall.decoys_generated == 8
    assert summary.overall.errors == 4
    assert summary.overall.latency_sample_count == 8
    assert summary.overall.median_latency_ms == 25.0
    assert summary.overall.p95_latency_ms is None
    assert all(
        run.expected_action_sequence_match is None
        for run in summary.runs
        if run.status != "completed"
    )


def test_latency_aggregation_uses_median_and_requires_20_for_p95():
    assert EvaluationService._p95([float(value) for value in range(1, 20)]) is None
    assert EvaluationService._p95([float(value) for value in range(1, 21)]) == 19.0


def test_old_run_without_strategy_measurement_is_excluded(tmp_path):
    storage = SQLiteEvaluationStorage(tmp_path / "evaluations.sqlite3")
    evaluation = EvaluationService(ControlledSimulationService(), storage)
    runs = []
    for repetition in (1, 2):
        request = SimulationRunRequest(
            scenario="reconnaissance",
            simulation_id=f"old-{repetition}",
            actor_id=f"old-actor-{repetition}",
        )
        run_summary = make_summary(
            request,
            attempted=1,
            recorded=1,
            elapsed=0.02,
            strategy_changes=None if repetition == 1 else 1,
        )
        runs.append(
            EvaluationRunResult(
                scenario="reconnaissance",
                repetition=repetition,
                simulation_id=request.simulation_id,
                actor_id=request.actor_id,
                status="completed",
                scenario_expected_actions=["read"],
                expected_action_sequence_match=True,
                simulation_summary=run_summary,
            )
        )

    metrics = evaluation._aggregate("reconnaissance", 2, runs)
    assert metrics.strategy_measurement_runs == 1
    assert metrics.strategy_changed_runs == 1
    assert metrics.strategy_change_rate == 1.0


def test_evaluation_results_persist_and_use_fresh_run_ids(tmp_path):
    storage = SQLiteEvaluationStorage(tmp_path / "evaluations.sqlite3")
    evaluation = EvaluationService(ControlledSimulationService(), storage)
    first = evaluation.run(
        EvaluationRequest(evaluation_id="persist-one", repetitions=1)
    )
    second = evaluation.run(
        EvaluationRequest(evaluation_id="persist-two", repetitions=1)
    )

    first_ids = {run.simulation_id for run in first.runs}
    second_ids = {run.simulation_id for run in second.runs}
    first_actors = {run.actor_id for run in first.runs}
    second_actors = {run.actor_id for run in second.runs}
    assert first_ids.isdisjoint(second_ids)
    assert first_actors.isdisjoint(second_actors)
    assert storage.get(first.evaluation_id) == first
    assert storage.get(second.evaluation_id) == second


def test_evaluation_api_runs_and_retrieves_persisted_summary():
    evaluation_id = f"api-{uuid4().hex[:8]}"
    response = client.post(
        "/api/v1/evaluations",
        json={"evaluation_id": evaluation_id, "repetitions": 1},
    )

    assert response.status_code == 201
    body = response.json()
    assert len(body["scenarios"]) == len(SCENARIOS)
    assert len(body["runs"]) == len(SCENARIOS)
    assert len({run["simulation_id"] for run in body["runs"]}) == len(SCENARIOS)
    assert len({run["actor_id"] for run in body["runs"]}) == len(SCENARIOS)
    multi_stage_run = next(
        run for run in body["runs"] if run["scenario"] == "multi_stage"
    )
    assert multi_stage_run["scenario_expected_actions"] == [
        "read",
        "attempt_login",
        "query",
    ]
    assert multi_stage_run["expected_action_sequence_match"] is True

    retrieved = client.get(f"/api/v1/evaluations/{evaluation_id}")
    assert retrieved.status_code == 200
    assert retrieved.json() == body
    assert client.post(
        "/api/v1/evaluations",
        json={"evaluation_id": evaluation_id, "repetitions": 1},
    ).status_code == 409


def test_evaluation_limits_and_identifiers_are_validated():
    for payload in (
        {"repetitions": 0},
        {"repetitions": 21},
        {"repeated_access_count": 1},
        {"repeated_access_count": 6},
        {"evaluation_id": "invalid id"},
    ):
        response = client.post("/api/v1/evaluations", json=payload)
        assert response.status_code == 422
