
from datetime import datetime, timezone

from backend.app.events.models import HoneypotEvent
from backend.app.ledger.service import EventLedger
from backend.app.ledger.storage import SQLiteLedgerStorage


def create_event(event_id: str) -> HoneypotEvent:
    return HoneypotEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        decoy_id="decoy-finance-001",
        actor_id="persistence-test",
        action="read",
    )


def create_ledger(database_path):
    storage = SQLiteLedgerStorage(database_path)
    return EventLedger(storage=storage)


def test_entries_survive_ledger_recreation(tmp_path):
    database_path = tmp_path / "persistent_ledger.sqlite3"

    first_ledger = create_ledger(database_path)
    first_ledger.append(create_event("persistent-event-001"))
    first_ledger.append(create_event("persistent-event-002"))

    second_ledger = create_ledger(database_path)

    entries = second_ledger.list_entries()

    assert len(entries) == 2
    assert entries[0].event_id == "persistent-event-001"
    assert entries[1].event_id == "persistent-event-002"
    assert second_ledger.verify_chain().valid is True


def test_modified_database_event_data_is_detected(tmp_path):
    database_path = tmp_path / "tampered_ledger.sqlite3"

    ledger = create_ledger(database_path)
    ledger.append(create_event("tamper-event-001"))

    storage = SQLiteLedgerStorage(database_path)

    with storage._connect() as connection:
        connection.execute(
            """
            UPDATE ledger_entries
            SET event_data = ?
            WHERE sequence = 1
            """,
            (
                '{"action":"query","actor_id":"attacker"}',
            ),
        )

    reopened_ledger = create_ledger(database_path)
    result = reopened_ledger.verify_chain()

    assert result.valid is False
    assert result.first_invalid_sequence == 1


def test_modified_database_hash_is_detected(tmp_path):
    database_path = tmp_path / "tampered_hash_ledger.sqlite3"

    ledger = create_ledger(database_path)
    ledger.append(create_event("tamper-hash-event-001"))

    storage = SQLiteLedgerStorage(database_path)

    with storage._connect() as connection:
        connection.execute(
            """
            UPDATE ledger_entries
            SET entry_hash = ?
            WHERE sequence = 1
            """,
            ("f" * 64,),
        )

    reopened_ledger = create_ledger(database_path)
    result = reopened_ledger.verify_chain()

    assert result.valid is False
    assert result.first_invalid_sequence == 1


def test_startup_verification_detects_tampered_database(tmp_path):
    database_path = tmp_path / "startup_tampered_ledger.sqlite3"

    ledger = create_ledger(database_path)
    ledger.append(create_event("startup-tamper-event-001"))

    storage = SQLiteLedgerStorage(database_path)

    with storage._connect() as connection:
        connection.execute(
            """
            UPDATE ledger_entries
            SET event_data = ?
            WHERE sequence = 1
            """,
            ('{"action":"query","actor_id":"modified"}',),
        )

    reopened_ledger = create_ledger(database_path)

    result = reopened_ledger.startup_verification

    assert result.valid is False
    assert result.first_invalid_sequence == 1


def test_invalid_persisted_ledger_rejects_new_events(tmp_path):
    database_path = tmp_path / "invalid_ledger.sqlite3"

    ledger = create_ledger(database_path)
    ledger.append(create_event("invalid-ledger-event-001"))

    storage = SQLiteLedgerStorage(database_path)

    with storage._connect() as connection:
        connection.execute(
            """
            UPDATE ledger_entries
            SET entry_hash = ?
            WHERE sequence = 1
            """,
            ("f" * 64,),
        )

    reopened_ledger = create_ledger(database_path)

    import pytest

    with pytest.raises(RuntimeError, match="invalid ledger"):
        reopened_ledger.append(
            create_event("should-not-be-appended")
        )
