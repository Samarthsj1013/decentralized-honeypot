from datetime import datetime, timezone
from time import perf_counter
from uuid import uuid4

from fastapi import HTTPException

from app.adaptation.service import AdaptiveHoneypotService
from app.events.models import InteractionRequest
from app.events.store import EventStore
from app.honeypot.interaction import InteractionWorkflow
from app.honeypot.registry import GeneratedDecoyRegistry
from app.honeypot.service import HoneypotService
from app.intelligence.service import BehavioralIntelligenceService
from app.simulation.models import (
    ScenarioName,
    SimulationError,
    SimulationRunRequest,
    SimulationRunSummary,
    SimulationScenario,
)
from app.simulation.storage import SQLiteSimulationStorage


SCENARIOS = [
    SimulationScenario(
        name="reconnaissance",
        description="Inspect the synthetic decoy catalog and read the built-in file decoy.",
        maximum_interactions=1,
    ),
    SimulationScenario(
        name="credential_probing",
        description="Submit one simulated login attempt to the built-in credential decoy.",
        maximum_interactions=1,
    ),
    SimulationScenario(
        name="database_probing",
        description="Run one simulated query against the built-in database decoy.",
        maximum_interactions=1,
    ),
    SimulationScenario(
        name="multi_stage",
        description="Read a file, attempt a synthetic credential login, then query a synthetic database decoy.",
        maximum_interactions=3,
    ),
    SimulationScenario(
        name="repeated_access",
        description="Read the same built-in file decoy repeatedly to exercise event recording.",
        maximum_interactions=5,
    ),
]


class AttackSimulationService:
    """Execute bounded scenarios through the application's real workflow."""

    def __init__(
        self,
        workflow: InteractionWorkflow,
        honeypot: HoneypotService,
        event_store: EventStore,
        intelligence: BehavioralIntelligenceService,
        adaptation: AdaptiveHoneypotService,
        registry: GeneratedDecoyRegistry,
        storage: SQLiteSimulationStorage,
    ) -> None:
        self._workflow = workflow
        self._honeypot = honeypot
        self._event_store = event_store
        self._intelligence = intelligence
        self._adaptation = adaptation
        self._registry = registry
        self._storage = storage

    @staticmethod
    def list_scenarios() -> list[SimulationScenario]:
        return list(SCENARIOS)

    def get_run(self, simulation_id: str) -> SimulationRunSummary:
        summary = self._storage.get(simulation_id)
        if summary is None:
            raise HTTPException(status_code=404, detail="Simulation run not found")
        return summary

    def run(self, request: SimulationRunRequest) -> SimulationRunSummary:
        simulation_id = request.simulation_id or uuid4().hex
        actor_id = request.actor_id or f"sim-{simulation_id}"

        if self._storage.get(simulation_id) is not None:
            raise HTTPException(
                status_code=409,
                detail="Simulation ID has already been used",
            )

        if any(
            event.actor_id == actor_id
            for event in self._event_store.list_events()
        ):
            raise HTTPException(
                status_code=409,
                detail="Actor ID already has interaction history",
            )
        if self._adaptation._history_storage.get_observed_strategy(actor_id):
            raise HTTPException(
                status_code=409,
                detail="Actor ID already has adaptation history",
            )
        if any(
            decoy.actor_id == actor_id
            for decoy in self._registry.list_all()
        ):
            raise HTTPException(
                status_code=409,
                detail="Actor ID already has generated decoys",
            )
        if self._storage.actor_has_run(actor_id):
            raise HTTPException(
                status_code=409,
                detail="Actor ID has already been used by a simulation",
            )

        plan = self._build_plan(request.scenario, request.repeat_count)
        if len(plan) > 10:
            raise HTTPException(status_code=422, detail="Scenario exceeds interaction limit")

        if self._adaptation._history_storage.get_observed_strategy(actor_id) is None:
            # Simulations have an explicit neutral starting policy so the
            # first observed behavior can produce a measured transition.
            self._adaptation._history_storage.set_observed_strategy(
                actor_id, "neutral_response"
            )

        started_at = datetime.now(timezone.utc)
        started_clock = perf_counter()
        initial_strategy = self._adaptation._history_storage.get_observed_strategy(
            actor_id
        )
        existing_actor_decoys = {
            decoy.decoy_id
            for decoy in self._registry.list_all()
            if decoy.actor_id == actor_id
        }
        existing_bundle_ids = {
            bundle.bundle_id for bundle in self._registry.list_bundles(actor_id)
        }
        event_ids: list[str] = []
        observed_actions: list[str] = []
        observed_decoys: list[str] = []
        observed_strategies: list[str] = []
        strategy_change_count = 0
        prior_strategy = initial_strategy
        errors: list[SimulationError] = []

        # Reconnaissance includes catalog inspection, recorded as available
        # decoys in the summary; only explicit interactions create events.
        if request.scenario == "reconnaissance":
            self._honeypot.list_decoys()

        for step_number, (decoy_id, action) in enumerate(plan, start=1):
            prior_event_ids = {
                event.event_id
                for event in self._event_store.list_events()
                if event.actor_id == actor_id
            }
            try:
                self._workflow.record_interaction(
                    decoy_id,
                    InteractionRequest(actor_id=actor_id, action=action),
                    policy_mode=request.policy_mode,
                    scenario_id=simulation_id,
                )
            except Exception as exc:
                detail = getattr(exc, "detail", None)
                errors.append(
                    SimulationError(
                        step=step_number,
                        decoy_id=decoy_id,
                        action=action,
                        message=str(detail if detail is not None else exc),
                    )
                )

            # Count what the event store actually contains, including the
            # case where later ledger/adaptation work failed after insertion.
            recorded_events = [
                event
                for event in self._event_store.list_events()
                if event.actor_id == actor_id
                and event.event_id not in prior_event_ids
                and event.event_id not in event_ids
            ]
            for event in recorded_events:
                event_ids.append(event.event_id)
                observed_actions.append(event.action)
                observed_decoys.append(event.decoy_id)

            current_strategy = self._adaptation._history_storage.get_observed_strategy(
                actor_id
            )
            if current_strategy is not None:
                observed_strategies.append(current_strategy)
                if (
                    prior_strategy is not None
                    and current_strategy != prior_strategy
                ):
                    strategy_change_count += 1
                prior_strategy = current_strategy

        final_strategy = self._adaptation._history_storage.get_observed_strategy(
            actor_id
        )
        final_actor_decoys = {
            decoy.decoy_id
            for decoy in self._registry.list_all()
            if decoy.actor_id == actor_id
        }
        generated_decoy_categories: dict[str, int] = {}
        for decoy in self._registry.list_all():
            if decoy.decoy_id in final_actor_decoys - existing_actor_decoys:
                generated_decoy_categories[decoy.decoy_type] = (
                    generated_decoy_categories.get(decoy.decoy_type, 0) + 1
                )
        actor_bundles = self._registry.list_bundles(actor_id)
        new_bundles = [
            bundle for bundle in actor_bundles
            if bundle.bundle_id not in existing_bundle_ids
        ]
        from app.honeypot.bundles import BundleConsistencyValidator
        validator = BundleConsistencyValidator()
        bundle_asset_categories = {
            "identities": sum(len(bundle.identities) for bundle in new_bundles),
            "database_records": sum(len(bundle.database_records) for bundle in new_bundles),
            "files": sum(len(bundle.files) for bundle in new_bundles),
            "api_resources": sum(len(bundle.api_resources) for bundle in new_bundles),
        }
        ended_at = datetime.now(timezone.utc)

        summary = SimulationRunSummary(
            simulation_id=simulation_id,
            actor_id=actor_id,
            scenario=request.scenario,
            policy_mode=request.policy_mode,
            interactions_attempted=len(plan),
            interactions_recorded=len(event_ids),
            event_ids=event_ids,
            observed_actions=observed_actions,
            observed_decoys=observed_decoys,
            initial_adaptation_strategy=initial_strategy,
            final_adaptation_strategy=final_strategy,
            observed_strategies=observed_strategies,
            strategy_change_count=strategy_change_count,
            decoys_generated=len(final_actor_decoys - existing_actor_decoys),
            generated_decoy_ids=sorted(
                final_actor_decoys - existing_actor_decoys
            ),
            generated_decoy_categories=dict(sorted(generated_decoy_categories.items())),
            bundle_ids=[bundle.bundle_id for bundle in new_bundles],
            bundle_asset_categories=bundle_asset_categories,
            bundle_validation_results=[validator.validate(bundle) for bundle in new_bundles],
            duplicate_decoys_avoided=None,
            unavailable_measurements=[
                "duplicate_decoys_avoided: the registry does not expose insert-conflict counts"
            ],
            errors=errors,
            started_at=started_at,
            ended_at=ended_at,
            elapsed_seconds=round(perf_counter() - started_clock, 6),
        )
        self._storage.save(summary)
        return summary

    @classmethod
    def expected_actions(
        cls,
        scenario: ScenarioName,
        repeat_count: int = 2,
    ) -> list[str]:
        return [
            action
            for _decoy_id, action in cls._build_plan(
                scenario,
                repeat_count,
            )
        ]

    @staticmethod
    def _build_plan(
        scenario: ScenarioName,
        repeat_count: int,
    ) -> list[tuple[str, str]]:
        if scenario == "reconnaissance":
            return [("decoy-finance-001", "read")]
        if scenario == "credential_probing":
            return [("decoy-credential-001", "attempt_login")]
        if scenario == "database_probing":
            return [("decoy-database-001", "query")]
        if scenario == "multi_stage":
            return [
                ("decoy-finance-001", "read"),
                ("decoy-credential-001", "attempt_login"),
                ("decoy-database-001", "query"),
            ]
        if scenario == "repeated_access":
            return [
                ("decoy-finance-001", "read")
                for _ in range(repeat_count)
            ]
        raise ValueError(f"Unsupported simulation scenario: {scenario}")
