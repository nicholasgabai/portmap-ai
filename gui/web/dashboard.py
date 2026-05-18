from __future__ import annotations

from pathlib import Path
from typing import Any

from gui.web.render import render_dashboard_html


API_PATHS = {
    "health": "/health",
    "events": "/events",
    "assets": "/assets",
    "snapshots": "/snapshots",
    "nodes": "/nodes",
    "topology": "/topology",
    "operator_reviews": "/operator_reviews",
    "diagnostics": "/diagnostics",
}


def build_dashboard_model(source: dict[str, Any] | Any | None = None) -> dict[str, Any]:
    """Build an operator-friendly dashboard model from local API-shaped data."""
    data = _load_api_data(source)
    health = _payload(data.get("health"))
    events = _items(data.get("events"))
    assets = _items(data.get("assets"))
    snapshots = _items(data.get("snapshots"))
    nodes = _items(data.get("nodes"))
    topology_items = _items(data.get("topology"))
    topology_nodes, topology_edges = _topology_counts(topology_items)
    topology_payload = _payload(data.get("topology"))
    topology_nodes = int((topology_payload.get("summary") or {}).get("node_count") or topology_nodes)
    topology_edges = int((topology_payload.get("summary") or {}).get("edge_count") or topology_edges)
    operator_review_count = _operator_review_count(events, data)
    diagnostics = _items(data.get("diagnostics"))

    return {
        "title": "PortMap-AI Local Dashboard",
        "health_status": health.get("status", "unknown"),
        "generated_at": _generated_at(data),
        "metrics": {
            "asset_count": _count(data.get("assets"), assets),
            "event_count": _count(data.get("events"), events),
            "snapshot_count": _count(data.get("snapshots"), snapshots),
            "node_count": _count(data.get("nodes"), nodes),
            "topology_node_count": topology_nodes,
            "topology_edge_count": topology_edges,
            "operator_review_count": operator_review_count,
            "diagnostic_count": _count(data.get("diagnostics"), diagnostics),
        },
        "panels": {
            "health": health,
            "assets": assets,
            "events": events,
            "snapshots": snapshots,
            "nodes": nodes,
            "topology": topology_items,
            "operator_reviews": _items(data.get("operator_reviews")),
            "diagnostics": diagnostics,
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
        "read_only": True,
    }


def write_dashboard_html(path: str | Path, model: dict[str, Any]) -> Path:
    """Write a local static dashboard preview to an explicit path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_dashboard_html(model), encoding="utf-8")
    return target


def _load_api_data(source: dict[str, Any] | Any | None) -> dict[str, Any]:
    if source is None:
        return {}
    if isinstance(source, dict):
        return source
    if not hasattr(source, "get"):
        raise TypeError("dashboard source must be a dict or provider with get(path)")
    data: dict[str, Any] = {}
    for key, path in API_PATHS.items():
        response = source.get(path)
        data[key] = response[1] if isinstance(response, tuple) and len(response) == 2 else response
    return data


def _payload(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[dict[str, Any]]:
    rows = _payload(value).get("items") or []
    return [item for item in rows if isinstance(item, dict)]


def _count(value: Any, fallback_items: list[dict[str, Any]]) -> int:
    try:
        return int(_payload(value).get("count"))
    except (TypeError, ValueError):
        return len(fallback_items)


def _generated_at(data: dict[str, Any]) -> str:
    for key in ("health", "events", "assets", "snapshots", "nodes", "topology"):
        value = _payload(data.get(key)).get("generated_at")
        if isinstance(value, str) and value:
            return value
    return "not-generated"


def _topology_counts(items: list[dict[str, Any]]) -> tuple[int, int]:
    node_ids: set[str] = set()
    edge_count = 0
    for item in items:
        if isinstance(item.get("nodes"), list):
            node_ids.update(str(node.get("id") or node.get("node_id")) for node in item["nodes"] if isinstance(node, dict))
        src = item.get("src") or item.get("source") or item.get("from")
        dst = item.get("dst") or item.get("target") or item.get("to")
        if src:
            node_ids.add(str(src))
        if dst:
            node_ids.add(str(dst))
        if src or dst or item.get("edge_id"):
            edge_count += 1
    return len({node for node in node_ids if node and node != "None"}), edge_count


def _operator_review_count(events: list[dict[str, Any]], data: dict[str, Any]) -> int:
    explicit = data.get("operator_reviews")
    if isinstance(explicit, dict):
        try:
            return int(explicit.get("count"))
        except (TypeError, ValueError):
            pass
    return sum(
        1
        for event in events
        if event.get("event_type") in {"operator_review_created", "policy_review_required"}
        or event.get("approval_required") is True
    )
