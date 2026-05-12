from __future__ import annotations

from typing import Any


def health_response(app: Any) -> dict[str, Any]:
    return {
        "status": "ok",
        "generated_at": app._generated_at(),
        "bind_host": app.bind_host,
        "port": app.port,
        "local_only": app.local_only,
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }
