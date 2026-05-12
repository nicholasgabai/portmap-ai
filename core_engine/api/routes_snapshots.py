from __future__ import annotations

from typing import Any

from core_engine.api.response import collection_response


def snapshots_response(app: Any) -> dict[str, Any]:
    if app.repository is not None:
        items = app.repository.list_snapshots()
    else:
        items = list(app.snapshots)
    return collection_response(app, items)
