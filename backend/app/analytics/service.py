
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app.adaptation.storage import SQLiteAdaptationStorage
from app.events.store import EventStore


class AnalyticsService:
    """Build analytics summaries from honeypot events and decisions."""

    def __init__(
        self,
        store: EventStore,
        history_storage: SQLiteAdaptationStorage,
    ) -> None:
        self.store = store
        self.history_storage = history_storage

    def get_summary(self, recent_limit: int = 10) -> dict[str, Any]:
        if recent_limit < 1:
            raise ValueError("recent_limit must be at least 1")

        events = self.store.list_events()

        action_counts = Counter(event.action for event in events)
        actor_ids = {event.actor_id for event in events}
        decoy_counts = Counter(event.decoy_id for event in events)

        ordered_events = sorted(
            events,
            key=lambda event: event.timestamp,
            reverse=True,
        )

        recent_activity = [
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "actor_id": event.actor_id,
                "decoy_id": event.decoy_id,
                "action": event.action,
                "severity": event.severity,
            }
            for event in ordered_events[:recent_limit]
        ]

        # Read persistent strategy-selection counts directly from SQLite.
        with self.history_storage._lock:
            with self.history_storage._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT selected_strategy, COUNT(*) AS decision_count
                    FROM adaptation_decisions
                    GROUP BY selected_strategy
                    ORDER BY selected_strategy
                    """
                ).fetchall()

        strategy_counts = {
            row["selected_strategy"]: row["decision_count"]
            for row in rows
        }

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_interactions": len(events),
            "unique_actors": len(actor_ids),
            "action_counts": dict(sorted(action_counts.items())),
            "decoy_interaction_counts": dict(
                sorted(decoy_counts.items())
            ),
            "strategy_selection_counts": strategy_counts,
            "recent_activity": recent_activity,
            "simulation_only": True,
        }
