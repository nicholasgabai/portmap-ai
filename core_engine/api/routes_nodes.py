from __future__ import annotations

from typing import Any

from core_engine.api.response import collection_response


def nodes_response(app: Any) -> dict[str, Any]:
    if app.node_registry is not None:
        summary = app.node_registry.summarize_nodes()
        items = summary.get("nodes", [])
    else:
        items = list(app.nodes)
    return collection_response(app, items)
