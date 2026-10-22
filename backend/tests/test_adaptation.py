
import pytest
from fastapi import HTTPException

from app.adaptation.service import AdaptiveHoneypotService
from app.events.models import HoneypotEvent
from app.events.store import EventStore


@pytest.fixture
def store():
    return EventStore()


@pytest.fixture
def adaptation_service(store):
    return AdaptiveHoneypotService(store)


def add_event(store, actor_id, decoy_id, action, event_id):
    event = HoneypotEvent(
        event_id=event_id,
        decoy_id=decoy_id,
        actor_id=actor_id,
        action=action,
    )
    store.add(event)
    return event


def test_unknown_actor_has_no_adaptation_decision(adaptation_service):
    with pytest.raises(HTTPException) as exc:
        adaptation_service.analyze_actor("unknown-actor")

    assert exc.value.status_code == 404


def test_read_only_activity_selects_neutral_strategy(
    store,
    adaptation_service,
):
    add_event(
        store,
        "actor-read",
        "decoy-finance-001",
        "read",
        "event-read-001",
    )

    decision = adaptation_service.analyze_actor("actor-read")

    assert decision.risk_level == "low"
    assert decision.selected_strategy == "neutral_response"
    assert decision.event_count == 1
    assert decision.simulation_only is True


def test_login_attempt_selects_credential_strategy(
    store,
    adaptation_service,
):
    add_event(
        store,
        "actor-login",
        "decoy-credential-001",
        "attempt_login",
        "event-login-001",
    )

    decision = adaptation_service.analyze_actor("actor-login")

    assert decision.risk_level == "medium"
    assert decision.selected_strategy == "credential_decoy"


def test_database_query_selects_database_strategy(
    store,
    adaptation_service,
):
    add_event(
        store,
        "actor-query",
        "decoy-database-001",
        "query",
        "event-query-001",
    )

    decision = adaptation_service.analyze_actor("actor-query")

    assert decision.risk_level == "medium"
    assert decision.selected_strategy == "database_decoy"


def test_combined_behavior_selects_expanded_decoy_path(
    store,
    adaptation_service,
):
    actor_id = "actor-combined"

    add_event(
        store,
        actor_id,
        "decoy-finance-001",
        "read",
        "event-combined-001",
    )
    add_event(
        store,
        actor_id,
        "decoy-credential-001",
        "attempt_login",
        "event-combined-002",
    )
    add_event(
        store,
        actor_id,
        "decoy-database-001",
        "query",
        "event-combined-003",
    )

    decision = adaptation_service.analyze_actor(actor_id)

    assert decision.risk_level == "high"
    assert decision.selected_strategy == "expanded_decoy_path"
    assert decision.event_count == 3
    assert len(decision.observed_decoys) == 3
    assert decision.simulation_only is True


def test_new_behavior_changes_the_selected_strategy(
    store,
    adaptation_service,
):
    actor_id = "actor-evolving"

    add_event(
        store,
        actor_id,
        "decoy-finance-001",
        "read",
        "event-evolving-001",
    )

    first_decision = adaptation_service.analyze_actor(actor_id)

    add_event(
        store,
        actor_id,
        "decoy-credential-001",
        "attempt_login",
        "event-evolving-002",
    )

    second_decision = adaptation_service.analyze_actor(actor_id)

    assert first_decision.selected_strategy == "neutral_response"
    assert second_decision.selected_strategy == "credential_decoy"
    assert second_decision.event_count == 2
    assert "attempt_login" in second_decision.observed_actions
