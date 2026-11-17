"""API and persistence models for telemetry behavior profiling."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


BehaviorCategory = Literal[
    "reconnaissance", "authentication_probing", "repeated_connection",
    "suspicious_session", "multi_protocol", "unknown",
]
RecommendationState = Literal["pending", "evaluated", "evaluation_failed", "approved"]


class ProfileHistoryItem(BaseModel):
    recorded_at: datetime
    category: BehaviorCategory
    anomaly_index: float | None = Field(default=None, ge=0, le=1)
    cluster: int | None = Field(default=None, ge=0)
    observation_count: int = Field(ge=0)
    changes: list[str] = Field(default_factory=list, max_length=8)


class AttackerBehaviorProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_id: str
    source_ref: str
    first_observed: datetime
    last_observed: datetime
    observation_count: int = Field(ge=1)
    observation_window_seconds: int = Field(ge=60, le=86400)
    feature_schema_name: Literal["decentralized_honeypot.attacker_behavior_features"]
    feature_schema_version: Literal[1]
    features: dict[str, int | float]
    classification: BehaviorCategory
    model_vote_fraction: float = Field(ge=0, le=1)
    anomaly_index: float = Field(ge=0, le=1)
    anomaly_index_method: Literal["synthetic_baseline_percentile"]
    cluster: int = Field(ge=0)
    evidence_indicators: list[str] = Field(max_length=16)
    influential_features: dict[str, float] = Field(max_length=8)
    model_version: str = Field(min_length=1, max_length=64)
    history: list[ProfileHistoryItem] = Field(default_factory=list, max_length=20)
    limitations: list[str] = Field(default_factory=list, max_length=8)


class ProfileList(BaseModel):
    items: list[AttackerBehaviorProfile]
    total: int


class ProfileStats(BaseModel):
    total_profiles: int
    category_counts: dict[str, int]
    cluster_counts: dict[str, int]
    mean_anomaly_index: float | None = None
    model_version: str | None = None


class ProfileRecomputeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_seconds: int = Field(default=3600, ge=60, le=86400)


class ProfileRecomputeResponse(BaseModel):
    profiles_updated: int
    recommendations_created: int
    observation_window_seconds: int
    model_version: str
    profiles: list[AttackerBehaviorProfile] = Field(max_length=200)


class StatusAuditEntry(BaseModel):
    state: RecommendationState
    changed_at: datetime
    action: Literal["created", "evaluated", "evaluation_failed", "approved"]


class SafetyChecks(BaseModel):
    synthetic_assets_only: bool
    no_command_execution: bool
    no_public_deployment: bool
    no_automatic_blocking: bool
    bundle_validation_passed: bool
    simulation_runs_complete: bool
    event_recording_complete: bool
    evidence_sufficient: bool
    expected_scenario_covered: bool


class RecommendationEvaluation(BaseModel):
    outcome: Literal["passed", "failed"]
    evaluated_at: datetime
    evaluation_kind: Literal["isolated_synthetic_workflow_validation"]
    measured_scenarios: list[str]
    expected_scenario: str | None
    expected_scenario_covered: bool
    runs_requested: int | None
    completed_runs: int | None
    failed_runs: int | None
    incomplete_runs: int | None
    interactions_attempted: int | None
    interactions_recorded: int | None
    event_recording_rate: float | None
    generated_decoys: int | None
    bundle_validation_failures: int | None
    elapsed_seconds: float | None
    synthetic_interaction_opportunities: int | None
    telemetry_coverage: str
    false_positive_risk: str
    safety_checks: SafetyChecks
    limitations: list[str] = Field(max_length=8)


class DeceptionRecommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendation_id: str
    profile_id: str
    profile_category: BehaviorCategory
    proposed_strategy: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=120)
    rationale: str = Field(min_length=1, max_length=500)
    supporting_features: dict[str, int | float] = Field(max_length=8)
    expected_scenario: str | None = None
    model_version: str
    status: RecommendationState
    evaluation: RecommendationEvaluation | None = None
    status_history: list[StatusAuditEntry] = Field(max_length=20)
    risk_constraints: list[str] = Field(max_length=12)
    limitations: list[str] = Field(max_length=8)


class RecommendationList(BaseModel):
    items: list[DeceptionRecommendation]
    total: int


class ProfileHistoryResponse(BaseModel):
    profile: AttackerBehaviorProfile
    history: list[ProfileHistoryItem]
