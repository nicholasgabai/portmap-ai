from __future__ import annotations

from typing import Any

from core_engine.api.response import collection_response


def events_response(app: Any) -> dict[str, Any]:
    if app.repository is not None:
        items = app.repository.list_events()
    else:
        items = list(app.events)
    return collection_response(app, items)
