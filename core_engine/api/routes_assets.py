from __future__ import annotations

from typing import Any

from core_engine.api.response import collection_response


def assets_response(app: Any) -> dict[str, Any]:
    if app.repository is not None:
        items = app.repository.list_assets()
    else:
        items = list(app.assets)
    return collection_response(app, items)
