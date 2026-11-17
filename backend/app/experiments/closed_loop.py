"""Deterministic simulation-local deception policy and attacker reactions.

The probabilities below are explicit synthetic assumptions for controlled
experiments. They are not learned from operational telemetry and do not imply
real attacker behavior or deception effectiveness.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import timedelta

from app.profiling.service import RECOMMENDATION_POLICY
from app.simulation.adversary import SyntheticEvent

POLICY_VERSION = "contextual-epsilon-greedy-v1"
STRATEGY_LIBRARY = {
    "static_baseline": {"resource_cost": 0.0},
    "expanded_decoy_path": {"resource_cost": 0.15},
    "credential_decoy": {"resource_cost": 0.10},
    "file_decoy": {"resource_cost": 0.20},
    "neutral_response": {"resource_cost": 0.0},
}
EPSILON = 0.15


@dataclass(frozen=True)
class StrategyDecision:
    strategy: str
    reason: str
    policy_version: str = POLICY_VERSION


class ContextualStrategyPolicy:
    """Small bounded epsilon-greedy policy, scoped to one experiment run."""

    def __init__(self, seed: int):
        self._rng = random.Random(seed)
        self._totals = {strategy: 0.0 for strategy in STRATEGY_LIBRARY}
        self._counts = {strategy: 0 for strategy in STRATEGY_LIBRARY}

    def select(self, profile_category: str) -> StrategyDecision:
        recommended = RECOMMENDATION_POLICY.get(
            profile_category, RECOMMENDATION_POLICY["unknown"]
        )["strategy"]
        if recommended not in STRATEGY_LIBRARY:
            recommended = "neutral_response"
        if self._rng.random() < EPSILON:
            choices = sorted(STRATEGY_LIBRARY)
            selected = self._rng.choice(choices)
            reason = f"Exploration ({EPSILON:.2f} probability) among bounded synthetic strategies."
        else:
            def score(strategy: str) -> tuple[float, int, str]:
                mean_reward = self._totals[strategy] / self._counts[strategy] if self._counts[strategy] else 0.0
                context_bonus = 0.25 if strategy == recommended else 0.0
                return (mean_reward + context_bonus, -self._counts[strategy], strategy)

            selected = max(STRATEGY_LIBRARY, key=score)
            reason = (
                f"Exploitation: bounded historical mean reward plus 0.25 context bonus; "
                f"profile recommendation was {recommended}."
            )
        return StrategyDecision(selected, reason)

    def update(self, strategy: str, reward: float) -> None:
        if strategy not in self._totals or not -1.0 <= reward <= 1.0:
            raise ValueError("strategy or reward is outside policy bounds")
        self._totals[strategy] += reward
        self._counts[strategy] += 1


def simulate_reaction(
    events: list[SyntheticEvent],
    profile_category: str,
    strategy: str,
    seed: int,
) -> tuple[list[SyntheticEvent], list[str]]:
    """Return inert follow-up events and a recorded reaction for one synthetic session."""
    recommended = RECOMMENDATION_POLICY.get(
        profile_category, RECOMMENDATION_POLICY["unknown"]
    )["strategy"]
    # Intentionally includes low-response and harmful cases; these are scenario
    # assumptions, not claims about real attackers.
    engagement_probability = 0.62 if strategy == recommended else 0.28
    if profile_category == "unknown" and strategy == "neutral_response":
        engagement_probability = 0.20
    if profile_category == "repeated_connection" and strategy == "file_decoy":
        engagement_probability = 0.10
    rng = random.Random(seed)
    if not events:
        return [], ["no_interaction"]
    engaged = rng.random() < engagement_probability
    if not engaged:
        return [], ["abandon"]
    if profile_category in {"reconnaissance", "multi_protocol"}:
        reaction, count = "explore_synthetic_resource", 2
    elif profile_category == "repeated_connection":
        reaction, count = "continue_slowly", 1
    else:
        reaction, count = "continue_session", 1
    last = events[-1]
    followups = [
        last.model_copy(update={
            "event_id": f"{last.event_id}-reaction-{index + 1}",
            "occurred_at": last.occurred_at + timedelta(seconds=(index + 1) * 2),
            "event_type": "synthetic_deception_engagement",
            "suspicious": True,
            "attributes": {"strategy_id": strategy, "reaction": reaction},
        })
        for index in range(count)
    ]
    return followups, [reaction]


def strategy_reward(
    *, true_positives: int, suspicious_events: int, false_positives: int,
    benign_events: int, incident_detected: bool, reactions: list[str],
    reaction_events: int, original_events: int, strategy: str,
) -> float:
    """Transparent bounded utility proxy; inputs are measured synthetic outcomes."""
    detection_coverage = true_positives / suspicious_events if suspicious_events else 0.0
    false_positive_rate = false_positives / benign_events if benign_events else 0.0
    engagement = min(1.0, reaction_events / max(1, original_events))
    overhead = min(1.0, reaction_events / max(1, original_events))
    engagement_bonus = 0.20 if reactions and reactions[0] != "abandon" else 0.0
    raw = (
        0.40 * detection_coverage
        + 0.15 * engagement
        + engagement_bonus
        + (0.20 if incident_detected else 0.0)
        - 0.25 * false_positive_rate
        - 0.10 * overhead
        - STRATEGY_LIBRARY.get(strategy, {}).get("resource_cost", 0.0)
    )
    return round(max(-1.0, min(1.0, raw)), 6)
