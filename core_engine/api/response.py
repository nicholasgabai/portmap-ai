from __future__ import annotations

from typing import Any


def collection_response(app: Any, items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "status": "ok",
        "count": len(items),
        "items": items,
        "generated_at": app._generated_at(),
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }
