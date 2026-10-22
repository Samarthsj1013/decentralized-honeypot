
import hashlib
import json
from pathlib import Path
from threading import RLock
from typing import Any

from pydantic import BaseModel

from app.events.models import HoneypotEvent
from app.ledger.storage import SQLiteLedgerStorage


GENESIS_HASH = "0" * 64
LEDGER_VERSION = "1.0"


class LedgerEntry(BaseModel):
    sequence: int
    event_id: str
    event_data: dict[str, Any]
    previous_hash: str
    entry_hash: str
    ledger_version: str = LEDGER_VERSION


class LedgerVerification(BaseModel):
    valid: bool
    entries_checked: int
    first_invalid_sequence: int | None = None
    message: str


class EventLedger:
    """Append-only hash chain with persistent storage and integrity checks."""

    def __init__(
        self,
        storage: SQLiteLedgerStorage | None = None,
    ) -> None:
        self._entries: list[LedgerEntry] = []
        self._storage = storage
        self._lock = RLock()

        if self._storage is not None:
            persisted_entries = self._storage.load_entries()
            self._entries = [
                LedgerEntry.model_validate(entry)
                for entry in persisted_entries
            ]

        # Check persisted entries immediately when the ledger is created.
        # Keep the application available if the ledger is invalid so that
        # the problem can be inspected and reported instead of hidden.
        self._startup_verification = self.verify_chain()

    @staticmethod
    def _canonical_json(data: dict[str, Any]) -> str:
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @classmethod
    def _calculate_hash(
        cls,
        sequence: int,
        event_id: str,
        event_data: dict[str, Any],
        previous_hash: str,
    ) -> str:
        payload = {
            "sequence": sequence,
            "event_id": event_id,
            "event_data": event_data,
            "previous_hash": previous_hash,
            "ledger_version": LEDGER_VERSION,
        }

        serialized = cls._canonical_json(payload).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    @property
    def startup_verification(self) -> LedgerVerification:
        """Return the integrity result captured when this ledger was opened."""
        return self._startup_verification.model_copy(deep=True)

    def append(self, event: HoneypotEvent) -> LedgerEntry:
        event_data = event.model_dump(mode="json")

        with self._lock:
            # Do not extend a chain that is already invalid.
            current_verification = self.verify_chain()

            if not current_verification.valid:
                raise RuntimeError(
                    "Cannot append to an invalid ledger. "
                    "Inspect the ledger integrity failure first."
                )

            sequence = len(self._entries) + 1
            previous_hash = (
                self._entries[-1].entry_hash
                if self._entries
                else GENESIS_HASH
            )

            entry_hash = self._calculate_hash(
                sequence,
                event.event_id,
                event_data,
                previous_hash,
            )

            entry = LedgerEntry(
                sequence=sequence,
                event_id=event.event_id,
                event_data=event_data,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                ledger_version=LEDGER_VERSION,
            )

            # Persist before changing in-memory state.
            if self._storage is not None:
                self._storage.append_entry(
                    entry.model_dump(mode="json")
                )

            self._entries.append(entry)

            return entry.model_copy(deep=True)

    def list_entries(self) -> list[LedgerEntry]:
        with self._lock:
            return [
                entry.model_copy(deep=True)
                for entry in self._entries
            ]

    def verify_chain(self) -> LedgerVerification:
        with self._lock:
            return self._verify_entries(self._entries)

    def verify_persisted_chain(self) -> LedgerVerification:
        """Reload and verify persisted rows, including external DB changes."""
        with self._lock:
            if self._storage is None:
                return self._verify_entries(self._entries)

            try:
                entries = [
                    LedgerEntry.model_validate(entry)
                    for entry in self._storage.load_entries()
                ]
            except Exception:
                return LedgerVerification(
                    valid=False,
                    entries_checked=0,
                    message="Persisted ledger entries could not be loaded.",
                )

            self._entries = entries
            return self._verify_entries(self._entries)

    @classmethod
    def _verify_entries(
        cls,
        entries: list[LedgerEntry],
    ) -> LedgerVerification:
        previous_hash = GENESIS_HASH

        for index, entry in enumerate(entries, start=1):
            if entry.sequence != index:
                return LedgerVerification(
                    valid=False,
                    entries_checked=index - 1,
                    first_invalid_sequence=index,
                    message="Ledger sequence is invalid.",
                )

            if entry.ledger_version != LEDGER_VERSION:
                return LedgerVerification(
                    valid=False,
                    entries_checked=index - 1,
                    first_invalid_sequence=index,
                    message="Ledger version is invalid or unsupported.",
                )

            if entry.previous_hash != previous_hash:
                return LedgerVerification(
                    valid=False,
                    entries_checked=index - 1,
                    first_invalid_sequence=index,
                    message="Previous-hash link is invalid.",
                )

            expected_hash = cls._calculate_hash(
                entry.sequence,
                entry.event_id,
                entry.event_data,
                entry.previous_hash,
            )

            if entry.entry_hash != expected_hash:
                return LedgerVerification(
                    valid=False,
                    entries_checked=index - 1,
                    first_invalid_sequence=index,
                    message="Entry hash does not match its contents.",
                )

            previous_hash = entry.entry_hash

        return LedgerVerification(
            valid=True,
            entries_checked=len(entries),
            message="All ledger entries and hash links are valid.",
        )

    def clear(self) -> None:
        with self._lock:
            if self._storage is not None:
                self._storage.clear()

            self._entries.clear()
            self._startup_verification = self.verify_chain()


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATABASE_PATH = (
    PROJECT_ROOT / "backend" / "data" / "event_ledger.sqlite3"
)

persistent_storage = SQLiteLedgerStorage(DATABASE_PATH)
event_ledger = EventLedger(storage=persistent_storage)
