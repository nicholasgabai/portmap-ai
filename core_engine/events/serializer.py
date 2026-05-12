from __future__ import annotations

import json
from typing import Any

from core_engine.events.models import EventValidationError, LocalEvent


def event_to_dict(event: LocalEvent) -> dict[str, Any]:
    if not isinstance(event, LocalEvent):
        raise EventValidationError("expected LocalEvent")
    return event.to_dict()


def event_from_dict(payload: dict[str, Any]) -> LocalEvent:
    return LocalEvent.from_dict(payload)


def event_to_json(event: LocalEvent) -> str:
    try:
        return json.dumps(event_to_dict(event), sort_keys=True, separators=(",", ":"))
    except TypeError as exc:
        raise EventValidationError(f"event is not JSON serializable: {exc}") from exc


def event_from_json(payload: str) -> LocalEvent:
    if not isinstance(payload, str):
        raise EventValidationError("event JSON must be a string")
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise EventValidationError(f"invalid event JSON: {exc.msg}") from exc
    return event_from_dict(decoded)
