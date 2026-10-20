
from threading import Lock

from backend.app.events.models import HoneypotEvent


class EventStore:
    """Thread-safe in-memory store for honeypot events."""

    def __init__(self) -> None:
        self._events: list[HoneypotEvent] = []
        self._lock = Lock()

    def add_event(self, event: HoneypotEvent) -> HoneypotEvent:
        with self._lock:
            self._events.append(event)
        return event
    def add(self, event: HoneypotEvent) -> HoneypotEvent:
        return self.add_event(event)

    def list_events(self) -> list[HoneypotEvent]:
        with self._lock:
            return list(self._events)

    def get_event(self, event_id: str) -> HoneypotEvent | None:
        with self._lock:
            for event in self._events:
                if event.event_id == event_id:
                    return event
        return None

    def count_events(self) -> int:
        with self._lock:
            return len(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


event_store = EventStore()
