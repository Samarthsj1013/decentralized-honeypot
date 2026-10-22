from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.simulation.models import (
    ScenarioName,
    SimulationRunSummary,
)


class EvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evaluation_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=16,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    repetitions: int = Field(default=3, ge=1, le=20)
    repeated_access_count: int = Field(default=2, ge=2, le=5)


class EvaluationRunResult(BaseModel):
    scenario: ScenarioName
    repetition: int
    simulation_id: str
    actor_id: str
    status: Literal["completed", "incomplete", "failed"]
    scenario_expected_actions: list[str]
    expected_action_sequence_match: bool | None
    simulation_summary: SimulationRunSummary | None
    execution_error: str | None = None


class EvaluationMetrics(BaseModel):
    runs_requested: int
    runs_with_summary: int
    completed_runs: int
    incomplete_runs: int
    failed_runs: int
    completion_rate: float
    interactions_attempted: int
    interactions_recorded: int
    event_recording_rate: float | None
    strategy_measurement_runs: int
    strategy_changed_runs: int
    strategy_change_rate: float | None
    decoy_generation_measurement_runs: int
    decoy_generation_runs: int
    decoy_generation_rate: float | None
    decoys_generated: int
    errors: int
    latency_sample_count: int
    median_latency_ms: float | None
    p95_latency_ms: float | None
    p95_minimum_sample_size: int


class ScenarioEvaluation(EvaluationMetrics):
    scenario: ScenarioName


class EvaluationSummary(BaseModel):
    evaluation_id: str
    status: Literal["completed", "partial"]
    repetitions_per_scenario: int
    repeated_access_count: int
    scenarios: list[ScenarioEvaluation]
    overall: EvaluationMetrics
    runs: list[EvaluationRunResult]
    started_at: datetime
    ended_at: datetime
    elapsed_seconds: float
    unavailable_measurements: list[str] = Field(default_factory=list)
