"""Local event model and pipeline helpers for PortMap-AI."""

from core_engine.events.bus import EventHandlerResult, LocalEventBus
from core_engine.events.models import (
    EVENT_TYPES,
    SEVERITIES,
    EventValidationError,
    LocalEvent,
    create_event,
)
from core_engine.events.queue import LocalEventQueue
from core_engine.events.serializer import event_from_dict, event_from_json, event_to_dict, event_to_json

__all__ = [
    "EVENT_TYPES",
    "SEVERITIES",
    "EventHandlerResult",
    "EventValidationError",
    "LocalEvent",
    "LocalEventBus",
    "LocalEventQueue",
    "create_event",
    "event_from_dict",
    "event_from_json",
    "event_to_dict",
    "event_to_json",
]
