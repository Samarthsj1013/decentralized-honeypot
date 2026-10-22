from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from app.honeypot.bundles import BundleValidationResult


ScenarioName = Literal[
    "reconnaissance",
    "credential_probing",
    "database_probing",
    "multi_stage",
    "repeated_access",
]
PolicyMode = Literal["baseline", "behavior_conditioned"]


class SimulationRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: ScenarioName
    simulation_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=48,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    actor_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    repeat_count: int = Field(default=2, ge=2, le=5)
    policy_mode: PolicyMode = "behavior_conditioned"

    @model_validator(mode="after")
    def validate_repeat_count(self):
        if self.scenario != "repeated_access" and self.repeat_count != 2:
            raise ValueError(
                "repeat_count can only be changed for repeated_access"
            )
        return self


class SimulationScenario(BaseModel):
    name: ScenarioName
    description: str
    maximum_interactions: int


class SimulationError(BaseModel):
    step: int
    decoy_id: str
    action: str
    message: str


class SimulationRunSummary(BaseModel):
    simulation_id: str
    actor_id: str
    scenario: ScenarioName
    policy_mode: PolicyMode = "behavior_conditioned"
    interactions_attempted: int
    interactions_recorded: int
    event_ids: list[str]
    observed_actions: list[str]
    observed_decoys: list[str]
    initial_adaptation_strategy: str | None
    final_adaptation_strategy: str | None
    observed_strategies: list[str] | None = None
    strategy_change_count: int | None = None
    decoys_generated: int
    generated_decoy_ids: list[str]
    generated_decoy_categories: dict[str, int] = Field(default_factory=dict)
    bundle_ids: list[str] = Field(default_factory=list)
    bundle_asset_categories: dict[str, int] = Field(default_factory=dict)
    bundle_validation_results: list[BundleValidationResult] = Field(default_factory=list)
    duplicate_decoys_avoided: int | None = None
    unavailable_measurements: list[str] = Field(default_factory=list)
    errors: list[SimulationError] = Field(default_factory=list)
    started_at: datetime
    ended_at: datetime
    elapsed_seconds: float


class SimulationScenarioList(BaseModel):
    scenarios: list[SimulationScenario]
