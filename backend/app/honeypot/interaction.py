from fastapi import HTTPException

from app.adaptation.service import AdaptiveHoneypotService
from app.events.models import HoneypotEvent, InteractionRequest
from app.honeypot.generator import BehaviorConditionedDecoyGenerator
from app.honeypot.registry import GeneratedDecoyRegistry
from app.honeypot.service import HoneypotService
from app.honeypot.bundle_generator import BehaviorConditionedBundleGenerator
from app.honeypot.bundles import BundleConsistencyValidator
from app.intelligence.service import (
    BehavioralIntelligenceService,
)


class InteractionWorkflow:
    """Run the application's real event, fingerprint, and adaptation path."""

    def __init__(
        self,
        honeypot: HoneypotService,
        intelligence: BehavioralIntelligenceService,
        adaptation: AdaptiveHoneypotService,
        generator: BehaviorConditionedDecoyGenerator,
        registry: GeneratedDecoyRegistry,
        bundle_generator: BehaviorConditionedBundleGenerator | None = None,
        bundle_validator: BundleConsistencyValidator | None = None,
    ) -> None:
        self._honeypot = honeypot
        self._intelligence = intelligence
        self._adaptation = adaptation
        self._generator = generator
        self._registry = registry
        self._bundle_generator = bundle_generator or BehaviorConditionedBundleGenerator()
        self._bundle_validator = bundle_validator or BundleConsistencyValidator()

    def record_interaction(
        self,
        decoy_id: str,
        request: InteractionRequest,
        policy_mode: str = "behavior_conditioned",
        scenario_id: str | None = None,
    ) -> HoneypotEvent:
        event = self._honeypot.record_interaction(decoy_id, request)
        fingerprint = self._intelligence.analyze_actor(request.actor_id)

        if fingerprint is None:
            return event

        decision = self._adaptation.record_decision(fingerprint)
        current_strategy = (
            decision.selected_strategy
            if policy_mode == "behavior_conditioned"
            else "neutral_response"
        )
        history_storage = self._adaptation._history_storage
        previous_strategy = history_storage.get_observed_strategy(
            request.actor_id
        )

        if previous_strategy is None:
            previous_strategy = "neutral_response"
            history_storage.set_observed_strategy(
                request.actor_id, previous_strategy
            )

        if (
            policy_mode == "behavior_conditioned"
            and current_strategy != previous_strategy
        ):
            # Persist the new observation only after generation and registry
            # persistence succeed, so a failure can be retried next request.
            try:
                bundle = self._bundle_generator.generate_bundle(
                    fingerprint=fingerprint,
                    selected_strategy=current_strategy,
                    strategy_reason=decision.reason,
                    scenario_id=scenario_id,
                )
                validation = self._bundle_validator.validate(bundle)
                if not validation.valid:
                    raise ValueError(
                        "Generated bundle failed consistency validation: "
                        + ", ".join(issue.code for issue in validation.issues)
                    )
                generated = self._bundle_generator.to_generated_decoys(bundle)
                self._registry.save_bundle(bundle, generated)
                # Re-register persisted projections as recovery if a prior
                # process ended after the DB commit but before memory update.
                self._honeypot.register_generated_decoys(generated)
            except Exception as exc:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Interaction was recorded, but adaptive decoy "
                        f"generation or persistence failed: {exc}"
                    ),
                ) from exc
            history_storage.set_observed_strategy(
                request.actor_id,
                current_strategy,
            )

        return event
