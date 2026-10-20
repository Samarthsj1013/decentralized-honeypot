
from datetime import datetime, timezone

from backend.app.events.models import HoneypotEvent
from backend.app.ledger.checkpoint import LedgerCheckpointService
from backend.app.ledger.service import EventLedger
from backend.app.ledger.storage import SQLiteLedgerStorage


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
