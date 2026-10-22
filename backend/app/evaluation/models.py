from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.simulation.models import (
    ScenarioName,
    SimulationRunSummary,
)
from app.simulation.models import PolicyMode


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
    policy_modes: list[PolicyMode] = Field(
        default_factory=lambda: ["baseline", "behavior_conditioned"],
        min_length=1,
        max_length=2,
    )

    @field_validator("policy_modes")
    @classmethod
    def unique_policy_modes(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("policy_modes must not contain duplicates")
        return value


class EvaluationRunResult(BaseModel):
    scenario: ScenarioName
    policy_mode: PolicyMode
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
    generated_decoy_categories: dict[str, int]
    strategy_selection_counts: dict[str, int]
    errors: int
    latency_sample_count: int
    median_latency_ms: float | None
    p95_latency_ms: float | None
    p95_minimum_sample_size: int
    bundles_generated: int = 0
    validated_bundles: int = 0
    bundle_validation_failures: int = 0
    bundle_asset_categories: dict[str, int] = Field(default_factory=dict)


class ScenarioEvaluation(EvaluationMetrics):
    scenario: ScenarioName


class PolicyModeEvaluation(EvaluationMetrics):
    policy_mode: PolicyMode


class EvaluationSummary(BaseModel):
    evaluation_id: str
    status: Literal["completed", "partial"]
    repetitions_per_scenario: int
    repeated_access_count: int
    policy_mode_metrics: list[PolicyModeEvaluation] = Field(default_factory=list)
    scenarios: list[ScenarioEvaluation]
    overall: EvaluationMetrics
    runs: list[EvaluationRunResult]
    started_at: datetime
    ended_at: datetime
    elapsed_seconds: float
    unavailable_measurements: list[str] = Field(default_factory=list)
