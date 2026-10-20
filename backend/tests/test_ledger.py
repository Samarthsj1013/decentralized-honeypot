
from datetime import datetime, timezone

from backend.app.events.models import HoneypotEvent
from backend.app.ledger.service import EventLedger, GENESIS_HASH


def make_event(event_id: str, actor_id: str = "simulator-ledger"):
    return HoneypotEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        decoy_id="decoy-finance-001",
        actor_id=actor_id,
        action="read",
    )


def test_first_entry_uses_genesis_hash():
    ledger = EventLedger()

    entry = ledger.append(make_event("event-001"))

    assert entry.sequence == 1
    assert entry.previous_hash == GENESIS_HASH
    assert len(entry.entry_hash) == 64


def test_appending_events_creates_hash_chain():
    ledger = EventLedger()

    first = ledger.append(make_event("event-001"))
    second = ledger.append(make_event("event-002"))

    assert first.sequence == 1
    assert second.sequence == 2
    assert second.previous_hash == first.entry_hash


def test_valid_ledger_passes_verification():
    ledger = EventLedger()

    ledger.append(make_event("event-001"))
    ledger.append(make_event("event-002"))
    ledger.append(make_event("event-003"))

    result = ledger.verify_chain()

    assert result.valid is True
    assert result.entries_checked == 3
    assert result.first_invalid_sequence is None


def test_empty_ledger_is_valid():
    ledger = EventLedger()

    result = ledger.verify_chain()

    assert result.valid is True
    assert result.entries_checked == 0


def test_modified_entry_data_is_detected():
    ledger = EventLedger()
    ledger.append(make_event("event-001"))

    # Simulate tampering with stored ledger data.
    ledger._entries[0].event_data["action"] = "query"

    result = ledger.verify_chain()

    assert result.valid is False
    assert result.first_invalid_sequence == 1
    assert "hash" in result.message.lower()


def test_modified_previous_hash_is_detected():
    ledger = EventLedger()
    ledger.append(make_event("event-001"))
    ledger.append(make_event("event-002"))

    ledger._entries[1].previous_hash = "f" * 64

    result = ledger.verify_chain()

    assert result.valid is False
    assert result.first_invalid_sequence == 2
    assert "link" in result.message.lower()


def test_list_entries_returns_independent_copies():
    ledger = EventLedger()
    ledger.append(make_event("event-001"))

    returned_entries = ledger.list_entries()
    returned_entries[0].event_data["action"] = "query"

    result = ledger.verify_chain()

    assert result.valid is True


def test_clear_resets_ledger():
    ledger = EventLedger()
    ledger.append(make_event("event-001"))

    ledger.clear()

    assert ledger.list_entries() == []
    assert ledger.verify_chain().valid is True
