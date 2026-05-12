from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable


def build_topology_graph(
    *,
    assets: Iterable[dict[str, Any]] | None = None,
    services: Iterable[dict[str, Any]] | None = None,
    topology_edges: Iterable[dict[str, Any]] | None = None,
    snapshots: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    api_data: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a normalized read-only topology graph from local evidence."""
    asset_rows = _rows(assets)
    service_rows = _rows(services)
    edge_rows = _rows(topology_edges)
    snapshot_rows = _snapshot_rows(snapshots)

    if api_data:
        asset_rows.extend(_api_items(api_data.get("assets")))
        service_rows.extend(_api_items(api_data.get("services")))
        snapshot_rows.extend(_api_items(api_data.get("snapshots")))
        edge_rows.extend(_api_items(api_data.get("topology")))

    for snapshot in snapshot_rows:
        asset_rows.extend(_rows(snapshot.get("assets")))
        service_rows.extend(_rows(snapshot.get("services")))
        topology = snapshot.get("topology") if isinstance(snapshot.get("topology"), dict) else {}
        edge_rows.extend(_rows(topology.get("edges")))

    nodes: dict[str, dict[str, Any]] = {}
    for asset in asset_rows:
        node_id = _asset_key(asset)
        node = nodes.setdefault(node_id, _new_node(node_id, asset))
        _merge_node(node, asset)

    for service in service_rows:
        node_id = _service_target(service)
        node = nodes.setdefault(node_id, _new_node(node_id, {"asset_id": node_id, "host": node_id, "target_source": "service"}))
        node["service_count"] += 1
        node["source_refs"].append(_source_ref("service", service, node_id))

    edges: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for edge in edge_rows:
        src = _first_str(edge, "source_asset", "src_asset", "src", "source", "from", "src_ip")
        dst = _first_str(edge, "target_asset", "dst_asset", "dst", "target", "to", "dst_ip")
        if not src or not dst:
            continue
        relationship_type = _first_str(edge, "relationship_type", "type") or "observed_relationship"
        label = _first_str(edge, "protocol", "service", "service_label") or ""
        key = (src, dst, relationship_type, label)
        item = edges.setdefault(key, _new_edge(src, dst, relationship_type, label, edge))
        item["observation_count"] += int(edge.get("observation_count") or edge.get("flow_count") or 1)
        item["confidence"] = max(item["confidence"], _confidence(edge))
        item["source_refs"].append(_source_ref("edge", edge, f"{src}->{dst}"))
        nodes.setdefault(src, _new_node(src, {"asset_id": src, "host": src, "target_source": "edge"}))
        nodes.setdefault(dst, _new_node(dst, {"asset_id": dst, "host": dst, "target_source": "edge"}))

    node_list = sorted((_final_node(node) for node in nodes.values()), key=lambda item: item["asset_id"])
    edge_list = sorted(edges.values(), key=lambda item: (item["source_asset"], item["target_asset"], item["relationship_type"]))
    service_count = len(service_rows)
    return {
        "status": "ok",
        "nodes": node_list,
        "edges": edge_list,
        "node_count": len(node_list),
        "edge_count": len(edge_list),
        "service_count": service_count,
        "relationship_count": sum(edge["observation_count"] for edge in edge_list),
        "generated_at": generated_at or _now(),
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
        "read_only": True,
    }


def summarize_topology(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = _rows(graph.get("nodes"))
    edges = _rows(graph.get("edges"))
    by_category: dict[str, int] = {}
    for node in nodes:
        category = str(node.get("category") or "unknown")
        by_category[category] = by_category.get(category, 0) + 1
    by_relationship: dict[str, int] = {}
    for edge in edges:
        relationship = str(edge.get("relationship_type") or "unknown")
        by_relationship[relationship] = by_relationship.get(relationship, 0) + 1
    return {
        "status": "ok",
        "node_count": len(nodes),
        "edge_count": len(edges),
        "service_count": int(graph.get("service_count") or 0),
        "relationship_count": int(graph.get("relationship_count") or 0),
        "by_category": dict(sorted(by_category.items())),
        "by_relationship": dict(sorted(by_relationship.items())),
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _snapshot_rows(value: Iterable[dict[str, Any]] | dict[str, Any] | None) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        if "assets" in value or "topology" in value:
            return [value]
        return _rows(value.get("items"))
    return _rows(value)


def _api_items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return _rows(value.get("items"))
    return _rows(value)


def _asset_key(asset: dict[str, Any]) -> str:
    return _first_str(asset, "asset_id", "host", "target", "node_id") or "asset-unknown"


def _service_target(service: dict[str, Any]) -> str:
    return _first_str(service, "asset_id", "target", "host") or "asset-unknown"


def _new_node(node_id: str, asset: dict[str, Any]) -> dict[str, Any]:
    label = _first_str(asset, "label", "host", "target", "node_id") or node_id
    category = _first_str(asset, "role", "category", "target_source") or "asset"
    confidence = _confidence(asset)
    identity = asset.get("identity") if isinstance(asset.get("identity"), dict) else {}
    return {
        "asset_id": node_id,
        "label": label,
        "category": category,
        "service_count": len(asset.get("service_ports") or []) + len(asset.get("services") or [] if isinstance(asset.get("services"), list) else []),
        "finding_count": len(asset.get("findings") or [] if isinstance(asset.get("findings"), list) else []),
        "confidence": max(confidence, float(identity.get("confidence") or 0.0)),
        "source_refs": [_source_ref("asset", asset, node_id)],
    }


def _merge_node(node: dict[str, Any], asset: dict[str, Any]) -> None:
    node["service_count"] = max(
        int(node.get("service_count") or 0),
        len(asset.get("service_ports") or []) + len(asset.get("services") or [] if isinstance(asset.get("services"), list) else []),
    )
    node["finding_count"] += len(asset.get("findings") or [] if isinstance(asset.get("findings"), list) else [])
    node["confidence"] = max(float(node.get("confidence") or 0.0), _confidence(asset))
    node["source_refs"].append(_source_ref("asset", asset, node["asset_id"]))


def _final_node(node: dict[str, Any]) -> dict[str, Any]:
    refs = sorted(set(str(ref) for ref in node.get("source_refs") or [] if ref))
    return {**node, "confidence": round(float(node.get("confidence") or 0.0), 2), "source_refs": refs}


def _new_edge(src: str, dst: str, relationship_type: str, label: str, edge: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_asset": src,
        "target_asset": dst,
        "relationship_type": relationship_type,
        "protocol_service_label": label or None,
        "observation_count": 0,
        "confidence": _confidence(edge),
        "source_refs": [],
    }


def _confidence(row: dict[str, Any]) -> float:
    try:
        value = float(row.get("confidence") or 0.0)
    except (TypeError, ValueError):
        value = 0.0
    return min(max(value, 0.0), 1.0)


def _first_str(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _source_ref(kind: str, row: dict[str, Any], fallback: str) -> str:
    for key in ("source_ref", "snapshot_id", "event_id", "edge_id", "service_id", "asset_id", "flow_id"):
        value = row.get(key)
        if value:
            return f"{kind}:{value}"
    return f"{kind}:{fallback}"


def _now() -> str:
    return datetime.now(UTC).isoformat()
