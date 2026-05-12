from __future__ import annotations

from collections import deque
from threading import Lock

from core_engine.events.models import EventValidationError, LocalEvent


class LocalEventQueue:
    """Small FIFO queue for local in-process event delivery."""

    def __init__(self, events: list[LocalEvent] | None = None) -> None:
        self._events: deque[LocalEvent] = deque()
        self._lock = Lock()
        for event in events or []:
            self.enqueue(event)

    def enqueue(self, event: LocalEvent) -> None:
        if not isinstance(event, LocalEvent):
            raise EventValidationError("queue accepts LocalEvent objects only")
        with self._lock:
            self._events.append(event)

    def consume(self) -> LocalEvent | None:
        with self._lock:
            if not self._events:
                return None
            return self._events.popleft()

    def drain(self, limit: int | None = None) -> list[LocalEvent]:
        consumed: list[LocalEvent] = []
        with self._lock:
            while self._events and (limit is None or len(consumed) < limit):
                consumed.append(self._events.popleft())
        return consumed

    def peek(self) -> list[LocalEvent]:
        with self._lock:
            return list(self._events)

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)
