from datetime import datetime, timedelta, timezone

from app.events.models import HoneypotEvent
from app.events.store import EventStore
from app.intelligence.service import BehavioralIntelligenceService


def make_event(event_id, actor_id, decoy_id, action, timestamp):
    return HoneypotEvent(
        event_id=event_id,
        actor_id=actor_id,
        decoy_id=decoy_id,
        action=action,
        timestamp=timestamp,
    )


def test_fingerprint_has_stable_versioned_counts_patterns_and_timing():
    actor = "fingerprint-example"
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = EventStore()
    store.add(make_event("e1", actor, "decoy-finance-001", "read", start))
    store.add(
        make_event(
            "e2",
            actor,
            "decoy-credential-001",
            "attempt_login",
            start + timedelta(seconds=30),
        )
    )
    store.add(
        make_event(
            "e3",
            actor,
            "decoy-credential-001",
            "attempt_login",
            start + timedelta(seconds=60),
        )
    )

    fingerprint = BehavioralIntelligenceService(store).analyze_actor(actor)
    assert fingerprint is not None
    assert fingerprint.fingerprint_version == 1
    assert fingerprint.action_frequencies == {"attempt_login": 2, "read": 1}
    assert fingerprint.decoy_type_frequencies == {"credential": 2, "file": 1}
    assert fingerprint.action_sequence == ["read", "attempt_login", "attempt_login"]
    assert fingerprint.credential_probing is True
    assert fingerprint.file_probing is True
    assert fingerprint.repeated_access is True
    assert fingerprint.elapsed_seconds == 60
    assert fingerprint.interactions_per_minute == 3
    assert fingerprint.timing_reliable is True


def test_mixed_timezone_timestamps_preserve_order_but_mark_timing_unavailable():
    actor = "fingerprint-mixed-time"
    store = EventStore()
    store.add(
        make_event(
            "e1",
            actor,
            "decoy-finance-001",
            "read",
            datetime(2026, 1, 1),
        )
    )
    store.add(
        make_event(
            "e2",
            actor,
            "decoy-credential-001",
            "attempt_login",
            datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    )

    fingerprint = BehavioralIntelligenceService(store).analyze_actor(actor)
    assert fingerprint is not None
    assert fingerprint.action_sequence == ["read", "attempt_login"]
    assert fingerprint.timing_reliable is False
    assert fingerprint.elapsed_seconds is None
    assert fingerprint.interactions_per_minute is None
