import hashlib
from datetime import timezone
from threading import RLock

from fastapi import HTTPException

from app.events.models import HoneypotEvent, TelemetryIngestRequest
from app.events.store import EventStore
from app.ledger.service import EventLedger


MAX_TELEMETRY_BODY_BYTES = 32 * 1024


class TelemetryIngestionService:
    """Map normalized telemetry into inert events and append them once."""

    def __init__(self, store: EventStore, ledger: EventLedger) -> None:
        self._store = store
        self._ledger = ledger
        self._lock = RLock()

    @staticmethod
    def _event_id(payload: TelemetryIngestRequest) -> str:
        identity = f"{payload.source_system}\0{payload.sensor_id}\0{payload.external_event_id}"
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        return f"external-{digest}"

    def ingest(self, payload: TelemetryIngestRequest) -> tuple[HoneypotEvent, bool]:
        event_id = self._event_id(payload)
        sensor_digest = hashlib.sha256(payload.sensor_id.encode("utf-8")).hexdigest()[:20]
        event = HoneypotEvent(
            event_id=event_id,
            timestamp=payload.occurred_at.astimezone(timezone.utc),
            decoy_id="external-telemetry",
            actor_id=f"external-sensor-{sensor_digest}",
            action=payload.event_type,
            event_type="external_telemetry",
            severity=payload.severity,
            source="external",
            source_system=payload.source_system,
            sensor_id=payload.sensor_id,
            source_event_id=payload.external_event_id,
            telemetry_event_type=payload.event_type,
            source_ip=str(payload.source_ip) if payload.source_ip is not None else None,
            destination_ip=(
                str(payload.destination_ip)
                if payload.destination_ip is not None
                else None
            ),
            source_port=payload.source_port,
            destination_port=payload.destination_port,
            protocol=payload.protocol,
            attributes=payload.attributes,
        )

        with self._lock:
            existing = self._store.get_event(event_id)
            if existing is not None:
                if existing.model_dump(mode="json") != event.model_dump(mode="json"):
                    raise HTTPException(
                        status_code=409,
                        detail="External event ID was already used with different contents",
                    )
                return existing, False

            # The ledger is durable and the in-memory store is restored from it
            # at startup. Persist first so a crash cannot leave an unledgered event.
            try:
                self._ledger.append(event)
            except Exception:
                raise HTTPException(
                    status_code=503,
                    detail="Telemetry could not be recorded in the event ledger",
                ) from None
            return self._store.add_event(event), True
