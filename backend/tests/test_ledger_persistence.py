
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from app.events.models import HoneypotEvent


def create_event(event_id: str) -> HoneypotEvent:
    return HoneypotEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        decoy_id="decoy-finance-001",
        actor_id="persistence-test",
        action="read",
    )


def create_ledger(database_path):
    from app.ledger.service import EventLedger

    return EventLedger(storage=create_storage(database_path))


def create_storage(database_path):
    from app.ledger.storage import SQLiteLedgerStorage

    return SQLiteLedgerStorage(database_path)


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

    storage = create_storage(database_path)

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


def test_tampering_with_copied_database_payload_is_detected(tmp_path):
    project_root = Path(__file__).resolve().parents[2]
    app_source = project_root / "backend" / "app"
    isolated_backend = tmp_path / "isolated_project" / "backend"

    for relative_path in (
        "__init__.py",
        "events/__init__.py",
        "events/models.py",
        "ledger/__init__.py",
        "ledger/service.py",
        "ledger/storage.py",
    ):
        destination = isolated_backend / "app" / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(app_source / relative_path, destination)

    runner = r'''
import json
import shutil
import sqlite3
import sys
from pathlib import Path

from app.events.models import HoneypotEvent
from app.ledger.service import EventLedger
from app.ledger.storage import SQLiteLedgerStorage

isolated_root = Path(sys.argv[1])
database_path = isolated_root / "backend" / "data" / "event_ledger.sqlite3"
copied_path = isolated_root / "copied_ledger.sqlite3"
backup_path = isolated_root / "copied_ledger.before_tamper.sqlite3"

source = EventLedger(SQLiteLedgerStorage(database_path))
source.append(HoneypotEvent(
    event_id="copied-tamper-event-001",
    timestamp="2026-01-01T00:00:00+00:00",
    decoy_id="decoy-finance-001",
    actor_id="safe-test-actor",
    action="read",
))
shutil.copy2(database_path, copied_path)
shutil.copy2(copied_path, backup_path)

before = EventLedger(SQLiteLedgerStorage(copied_path)).verify_chain()
with sqlite3.connect(copied_path) as connection:
    row = connection.execute(
        "SELECT event_data FROM ledger_entries WHERE sequence = 1"
    ).fetchone()
    event_data = json.loads(row[0])
    event_data["actor_id"] = "tampered-actor"
    connection.execute(
        "UPDATE ledger_entries SET event_data = ? WHERE sequence = 1",
        (json.dumps(event_data, sort_keys=True, separators=(",", ":")),),
    )

after = EventLedger(SQLiteLedgerStorage(copied_path)).verify_chain()
source_after = EventLedger(SQLiteLedgerStorage(database_path)).verify_chain()
backup_after = EventLedger(SQLiteLedgerStorage(backup_path)).verify_chain()
print(json.dumps({
    "before": before.model_dump(),
    "after": after.model_dump(),
    "source_after": source_after.model_dump(),
    "backup_after": backup_after.model_dump(),
}))
'''
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(isolated_backend)
    completed = subprocess.run(
        [sys.executable, "-c", runner, str(tmp_path / "isolated_project")],
        check=True,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=environment,
    )
    results = json.loads(completed.stdout)

    assert results["before"]["valid"] is True
    assert results["before"]["entries_checked"] == 1
    assert results["after"]["valid"] is False
    assert results["after"]["first_invalid_sequence"] == 1
    assert results["after"]["message"] == (
        "Entry hash does not match its contents."
    )
    assert results["source_after"]["valid"] is True
    assert results["backup_after"]["valid"] is True


def test_modified_database_hash_is_detected(tmp_path):
    database_path = tmp_path / "tampered_hash_ledger.sqlite3"

    ledger = create_ledger(database_path)
    ledger.append(create_event("tamper-hash-event-001"))

    storage = create_storage(database_path)

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

    storage = create_storage(database_path)

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

    storage = create_storage(database_path)

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
