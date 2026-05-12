from __future__ import annotations

from typing import Any

from core_engine.api.response import collection_response


def topology_response(app: Any) -> dict[str, Any]:
    if app.repository is not None:
        items = app.repository.list_topology_edges()
    else:
        items = list(app.topology_edges)
    return collection_response(app, items)
