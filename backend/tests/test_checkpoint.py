
import json
import sqlite3
from datetime import datetime, timezone

from app.events.models import HoneypotEvent
from app.ledger.checkpoint import LedgerCheckpointService
from app.ledger.service import EventLedger
from app.ledger.storage import SQLiteLedgerStorage


def create_test_service(tmp_path):
    storage = SQLiteLedgerStorage(tmp_path / "test_ledger.sqlite3")
    ledger = EventLedger(storage=storage)

    service = LedgerCheckpointService(
        ledger=ledger,
        private_key_path=tmp_path / "test_private.pem",
        public_key_path=tmp_path / "test_public.pem",
    )

    return ledger, service


def create_event(event_id: str) -> HoneypotEvent:
    return HoneypotEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        decoy_id="decoy-finance-001",
        actor_id="checkpoint-test",
        action="read",
    )


def test_checkpoint_verifies_for_non_empty_ledger(tmp_path):
    ledger, service = create_test_service(tmp_path)
    ledger.append(create_event("checkpoint-event-001"))

    checkpoint = service.create_checkpoint()
    result = service.verify_checkpoint(checkpoint)

    assert checkpoint.sequence == 1
    assert checkpoint.head_hash != "0" * 64
    assert result.valid is True
    assert result.signature_valid is True
    assert result.ledger_matches is True


def test_modified_checkpoint_signature_is_rejected(tmp_path):
    ledger, service = create_test_service(tmp_path)
    ledger.append(create_event("checkpoint-event-002"))

    checkpoint = service.create_checkpoint()
    modified = checkpoint.model_copy(
        update={"signature": "invalid-signature"}
    )

    result = service.verify_checkpoint(modified)

    assert result.valid is False
    assert result.signature_valid is False


def test_checkpoint_rejects_tampered_persisted_ledger_payload(tmp_path):
    database_path = tmp_path / "test_ledger.sqlite3"
    storage = SQLiteLedgerStorage(database_path)
    ledger = EventLedger(storage=storage)
    service = LedgerCheckpointService(
        ledger=ledger,
        private_key_path=tmp_path / "test_private.pem",
        public_key_path=tmp_path / "test_public.pem",
    )
    ledger.append(create_event("tampered-checkpoint-event-001"))

    checkpoint = service.create_checkpoint()
    before = service.verify_checkpoint(checkpoint)
    assert before.valid is True
    assert before.signature_valid is True
    assert before.ledger_matches is True
    assert before.ledger_integrity_valid is True

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT event_data FROM ledger_entries WHERE sequence = 1"
        ).fetchone()
        event_data = json.loads(row[0])
        event_data["actor_id"] = "tampered-actor"
        connection.execute(
            "UPDATE ledger_entries SET event_data = ? WHERE sequence = 1",
            (
                json.dumps(
                    event_data,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ),
            ),
        )

    after = service.verify_checkpoint(checkpoint)

    assert after.valid is False
    assert after.signature_valid is True
    assert after.ledger_matches is True
    assert after.ledger_integrity_valid is False
    assert after.first_invalid_sequence == 1
    assert "Ledger integrity verification failed at sequence 1" in after.message


def test_old_checkpoint_does_not_match_new_ledger_head(tmp_path):
    ledger, service = create_test_service(tmp_path)
    ledger.append(create_event("checkpoint-event-003"))

    checkpoint = service.create_checkpoint()

    ledger.append(create_event("checkpoint-event-004"))
    result = service.verify_checkpoint(checkpoint)

    assert result.valid is False
    assert result.signature_valid is True
    assert result.ledger_matches is False


def test_ledger_remains_valid_after_checkpoint_creation(tmp_path):
    ledger, service = create_test_service(tmp_path)
    ledger.append(create_event("checkpoint-event-005"))
    ledger.append(create_event("checkpoint-event-006"))

    service.create_checkpoint()
    result = ledger.verify_chain()

    assert result.valid is True
    assert result.entries_checked == 2
