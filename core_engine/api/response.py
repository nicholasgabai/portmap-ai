from __future__ import annotations

from typing import Any
from core_engine.time_utils import observation_timestamps


def collection_response(app: Any, items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "status": "ok",
        "count": len(items),
        "items": [
            {**item, **observation_timestamps(item)} if "event_timestamp" in item or "ingested_at" in item else item
            for item in items
        ],
        "generated_at": app._generated_at(),
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }
