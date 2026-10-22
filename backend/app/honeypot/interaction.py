from app.adaptation.service import AdaptiveHoneypotService
from app.events.models import HoneypotEvent, InteractionRequest
from app.honeypot.generator import BehaviorConditionedDecoyGenerator
from app.honeypot.registry import GeneratedDecoyRegistry
from app.honeypot.service import HoneypotService
from app.intelligence.service import (
    BehavioralFingerprint,
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
    ) -> None:
        self._honeypot = honeypot
        self._intelligence = intelligence
        self._adaptation = adaptation
        self._generator = generator
        self._registry = registry

    def record_interaction(
        self,
        decoy_id: str,
        request: InteractionRequest,
    ) -> HoneypotEvent:
        event = self._honeypot.record_interaction(decoy_id, request)
        fingerprint = self._intelligence.analyze_actor(request.actor_id)

        if fingerprint is None:
            return event

        current_strategy = self._select_strategy(fingerprint)
        history_storage = self._adaptation._history_storage
        previous_strategy = history_storage.get_observed_strategy(
            request.actor_id
        )

        if previous_strategy is None:
            history_storage.set_observed_strategy(
                request.actor_id,
                current_strategy,
            )
        elif current_strategy != previous_strategy:
            # Persist the new observation only after generation and registry
            # persistence succeed, so a failure can be retried next request.
            generated = self._generator.generate(
                fingerprint=fingerprint,
                limit=2,
            )
            saved = self._registry.save_many(generated)
            self._honeypot.register_generated_decoys(saved)
            history_storage.set_observed_strategy(
                request.actor_id,
                current_strategy,
            )

        return event

    @staticmethod
    def _select_strategy(fingerprint: BehavioralFingerprint) -> str:
        actions = set(fingerprint.action_sequence)

        if (
            "attempt_login" in actions
            and "query" in actions
            and fingerprint.unique_decoys_accessed >= 2
        ):
            return "expanded_decoy_path"

        if "attempt_login" in actions:
            return "credential_decoy"

        if "query" in actions:
            return "database_decoy"

        return "neutral_response"
