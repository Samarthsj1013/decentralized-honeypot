"""Bounded experiment request and persisted result schemas."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.simulation.adversary import SCENARIOS, Scenario

Mode = Literal["baseline", "adaptive", "closed_loop"]


class ExperimentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    experiment_id: str | None = Field(default=None, min_length=1, max_length=48, pattern=r"^[A-Za-z0-9_-]+$")
    scenarios: list[Scenario] = Field(default_factory=lambda: list(SCENARIOS), min_length=1, max_length=10)
    repetitions: int = Field(default=1, ge=1, le=10)
    seed: int = Field(default=2026, ge=0, le=4294967295)
    modes: list[Mode] = Field(default_factory=lambda: ["baseline", "adaptive"], min_length=1, max_length=3)

    @model_validator(mode="after")
    def unique_values_and_bounds(self):
        if len(set(self.scenarios)) != len(self.scenarios):
            raise ValueError("scenarios must not contain duplicates")
        if len(set(self.modes)) != len(self.modes):
            raise ValueError("modes must not contain duplicates")
        if len(self.scenarios) * self.repetitions * len(self.modes) > 200:
            raise ValueError("experiment exceeds the 200-run limit")
        return self


class ModeMetrics(BaseModel):
    mode: Mode
    scenarios_requested: int
    scenarios_completed: int
    scenario_completion_rate: float | None
    events_generated: int
    events_captured: int | None
    event_capture_rate: float | None
    ground_truth_suspicious_events: int
    detector_true_positives: int | None
    detector_false_positives: int | None
    detector_false_negatives: int | None
    detection_coverage: float | None
    incident_detection_rate: float | None
    detection_latency_median_seconds: float | None
    false_positive_rate: float | None
    false_negative_rate: float | None
    adaptation_frequency: float | None
    adaptations_applied: int
    strategy_selection_counts: dict[str, int] = Field(default_factory=dict)
    attacker_reaction_counts: dict[str, int] = Field(default_factory=dict)
    mean_strategy_reward: float | None = None
    adaptation_effectiveness: float | None
    average_event_processing_ms: float | None
    execution_time_seconds: float | None
    peak_memory_bytes: int | None = None
    simulated_engagement_rate: float | None = None
    mean_synthetic_interaction_depth: float | None = None
    median_synthetic_session_duration_seconds: float | None = None
    unique_decoys_accessed: int | None = None


class ScenarioResult(BaseModel):
    scenario: Scenario
    repetition: int
    seed: int
    ground_truth: Literal["suspicious", "mixed"]
    mode: Mode
    profile_category: str | None = None
    selected_strategy: str
    adaptation_reason: str | None = None
    policy_version: str | None = None
    attacker_reactions: list[str] = Field(default_factory=list, max_length=8)
    strategy_reward: float | None = Field(default=None, ge=-1, le=1)
    events_generated: int
    events_captured: int | None
    suspicious_events: int
    true_positives: int | None
    false_positives: int | None
    false_negatives: int | None
    incident_detected: bool | None
    detection_latency_seconds: float | None
    processing_time_ms: float | None
    completed: bool
    errors: list[str] = Field(default_factory=list, max_length=4)
    simulated_attacker_engaged: bool | None = None
    simulated_interaction_depth: int | None = None
    simulated_session_duration_seconds: float | None = None
    unique_decoys_accessed: int | None = None


class MetricDifference(BaseModel):
    metric: str
    baseline: float | None
    adaptive: float | None
    absolute_difference: float | None
    percentage_difference: float | None
    closed_loop: float | None = None


class ExperimentComparison(BaseModel):
    available: bool
    metrics: list[MetricDifference]
    note: str


class ExperimentResult(BaseModel):
    experiment_id: str
    created_at: datetime
    seed: int
    scenarios: list[Scenario]
    repetitions: int
    modes: list[Mode]
    mode_definitions: dict[str, str]
    mode_metrics: list[ModeMetrics]
    scenario_results: list[ScenarioResult]
    comparison: ExperimentComparison
    metric_definitions: dict[str, str]
    limitations: list[str]
    execution_time_seconds: float
