import asyncio
import json
from threading import Lock
from typing import Any

from app.events.models import HoneypotEvent
from app.telemetry.models import TelemetryAlert, cowrie_summary, live_summary


class LiveUpdateHub:
    """Bounded in-process fanout for server-sent event dashboard updates."""

    def __init__(self, queue_size: int = 100) -> None:
        self._queue_size = queue_size
        self._subscribers: dict[int, tuple[asyncio.Queue, asyncio.AbstractEventLoop]] = {}
        self._lock = Lock()

    def subscribe(self) -> tuple[int, asyncio.Queue]:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._queue_size)
        subscriber_id = id(queue)
        with self._lock:
            self._subscribers[subscriber_id] = (queue, loop)
        return subscriber_id, queue

    def unsubscribe(self, subscriber_id: int) -> None:
        with self._lock:
            self._subscribers.pop(subscriber_id, None)

    def publish_event(self, event: HoneypotEvent) -> None:
        self._publish({"kind": "event", "id": event.event_id, "data": live_summary(event).model_dump(mode="json")})
        summary = cowrie_summary(event)
        if summary is not None:
            self._publish({"kind": "cowrie", "id": event.event_id, "data": summary.model_dump(mode="json")})

    def publish_alert(self, alert: TelemetryAlert) -> None:
        self._publish({"kind": "alert", "id": alert.alert_id, "data": alert.model_dump(mode="json")})

    def publish_incident(self, incident_id: str) -> None:
        # Send only a refresh hint; detailed evidence is fetched via the API.
        self._publish({"kind": "incident", "id": f"incident-{incident_id}", "data": {"incident_id": incident_id}})

    def _publish(self, message: dict[str, Any]) -> None:
        with self._lock:
            subscribers = tuple(self._subscribers.values())
        for queue, loop in subscribers:
            if not loop.is_closed():
                loop.call_soon_threadsafe(self._enqueue, queue, message)

    @staticmethod
    def _enqueue(queue: asyncio.Queue, message: dict[str, Any]) -> None:
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            pass

    @staticmethod
    def encode(message: dict[str, Any]) -> str:
        return (
            f"id: {message['id']}\n"
            f"event: {message['kind']}\n"
            f"data: {json.dumps(message['data'], separators=(',', ':'), ensure_ascii=False)}\n\n"
        )
