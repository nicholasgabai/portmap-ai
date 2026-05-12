from __future__ import annotations

from dataclasses import dataclass
from itertools import count
from threading import Lock
from typing import Callable

from core_engine.events.models import EVENT_TYPES, EventValidationError, LocalEvent
from core_engine.events.queue import LocalEventQueue


EventHandler = Callable[[LocalEvent], None]


@dataclass(frozen=True)
class EventHandlerResult:
    subscription_id: str
    event_type: str | None
    ok: bool
    error: str | None = None


class LocalEventBus:
    """Local-only event bus with in-memory queue and handler isolation."""

    def __init__(self, *, queue: LocalEventQueue | None = None, history_limit: int = 1000) -> None:
        if history_limit < 0:
            raise ValueError("history_limit must be non-negative")
        self.queue = queue or LocalEventQueue()
        self.history_limit = history_limit
        self._history: list[LocalEvent] = []
        self._subscriptions: dict[str, tuple[str | None, EventHandler]] = {}
        self._ids = count(1)
        self._lock = Lock()

    def subscribe(self, handler: EventHandler, event_type: str | None = None) -> str:
        if not callable(handler):
            raise EventValidationError("event handler must be callable")
        if event_type is not None and event_type not in EVENT_TYPES:
            raise EventValidationError(f"unsupported event_type subscription: {event_type}")
        subscription_id = f"sub-{next(self._ids)}"
        with self._lock:
            self._subscriptions[subscription_id] = (event_type, handler)
        return subscription_id

    def unsubscribe(self, subscription_id: str) -> bool:
        with self._lock:
            return self._subscriptions.pop(subscription_id, None) is not None

    def publish(self, event: LocalEvent) -> list[EventHandlerResult]:
        if not isinstance(event, LocalEvent):
            raise EventValidationError("publish accepts LocalEvent objects only")
        self.queue.enqueue(event)
        with self._lock:
            if self.history_limit > 0:
                self._history.append(event)
                if len(self._history) > self.history_limit:
                    self._history = self._history[-self.history_limit :]
            subscriptions = list(self._subscriptions.items())
        return self._deliver(event, subscriptions)

    def consume(self, limit: int | None = None) -> list[LocalEvent]:
        return self.queue.drain(limit=limit)

    def replay(self, handler: EventHandler | None = None, *, event_type: str | None = None) -> list[EventHandlerResult]:
        if event_type is not None and event_type not in EVENT_TYPES:
            raise EventValidationError(f"unsupported event_type replay: {event_type}")
        if handler is not None and not callable(handler):
            raise EventValidationError("event handler must be callable")
        with self._lock:
            history = list(self._history)
            subscriptions = list(self._subscriptions.items())
        events = [event for event in history if event_type is None or event.event_type == event_type]
        results: list[EventHandlerResult] = []
        if handler is not None:
            for event in events:
                results.extend(self._deliver(event, [("replay", (event_type, handler))]))
            return results
        for event in events:
            results.extend(self._deliver(event, subscriptions))
        return results

    @property
    def history(self) -> list[LocalEvent]:
        with self._lock:
            return list(self._history)

    def _deliver(
        self,
        event: LocalEvent,
        subscriptions: list[tuple[str, tuple[str | None, EventHandler]]],
    ) -> list[EventHandlerResult]:
        results: list[EventHandlerResult] = []
        for subscription_id, (event_type, handler) in subscriptions:
            if event_type is not None and event_type != event.event_type:
                continue
            try:
                handler(event)
            except Exception as exc:  # Handler failures must not interrupt delivery.
                results.append(EventHandlerResult(subscription_id, event_type, False, str(exc)))
            else:
                results.append(EventHandlerResult(subscription_id, event_type, True))
        return results
