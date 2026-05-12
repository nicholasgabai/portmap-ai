from __future__ import annotations

import json
from hashlib import sha256
from typing import Any, Iterable


SNAPSHOT_SCHEMA_VERSION = 1


def build_visibility_snapshot(
    *,
    assets: Iterable[dict[str, Any]] | None = None,
    services: Iterable[dict[str, Any]] | None = None,
    flows: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    label: str = "",
    observed_at: str | float | int | None = None,
) -> dict[str, Any]:
    """Build a stable, JSON-serializable visibility snapshot from local evidence."""
    asset_rows = _rows(assets)
    service_rows = _rows(services)
    flow_rows = _flow_rows(flows)
    service_index = _services_by_host(service_rows)
    flow_index = _flows_by_host(flow_rows)

    snapshot_assets = [
        _snapshot_asset(row, service_index.get(str(row.get("host") or ""), []), flow_index.get(str(row.get("host") or ""), []))
        for row in asset_rows
    ]
    known_hosts = {asset["host"] for asset in snapshot_assets}
    for host in sorted((set(service_index) | set(flow_index)) - known_hosts):
        snapshot_assets.append(_snapshot_asset({"host": host, "status": "unknown"}, service_index.get(host, []), flow_index.get(host, [])))

    topology = _topology(flow_rows)
    payload = {
        "ok": True,
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "snapshot_id": "",
        "label": label,
        "observed_at": observed_at,
        "asset_count": len(snapshot_assets),
        "service_count": len(service_rows),
        "flow_count": len(flow_rows),
        "assets": sorted(snapshot_assets, key=lambda item: (item["host"], item["asset_id"])),
        "services": sorted((_snapshot_service(row) for row in service_rows), key=lambda item: (item["target"], item["port"])),
        "topology": topology,
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
    }
    payload["snapshot_id"] = sha256(
        json.dumps(
            {
                "label": payload["label"],
                "observed_at": payload["observed_at"],
                "assets": payload["assets"],
                "services": payload["services"],
                "topology": payload["topology"],
            },
            sort_keys=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()[:16]
    return payload


def compare_visibility_snapshots(
    baseline: dict[str, Any],
    current: dict[str, Any],
    *,
    require_approval: bool = True,
) -> dict[str, Any]:
    """Compare two snapshots and return safe operator-review deltas."""
    baseline_assets = {str(item.get("asset_id")): item for item in _rows(baseline.get("assets")) if item.get("asset_id")}
    current_assets = {str(item.get("asset_id")): item for item in _rows(current.get("assets")) if item.get("asset_id")}
    baseline_services = {_service_key(item): item for item in _rows(baseline.get("services"))}
    current_services = {_service_key(item): item for item in _rows(current.get("services"))}
    baseline_edges = {_edge_key(item): item for item in _rows((baseline.get("topology") or {}).get("edges"))}
    current_edges = {_edge_key(item): item for item in _rows((current.get("topology") or {}).get("edges"))}

    deltas: list[dict[str, Any]] = []
    for asset_id in sorted(set(current_assets) - set(baseline_assets)):
        deltas.append(_delta("asset_added", "medium", current_assets[asset_id].get("host", "unknown"), {"asset_id": asset_id}))
    for asset_id in sorted(set(baseline_assets) - set(current_assets)):
        deltas.append(_delta("asset_missing", "medium", baseline_assets[asset_id].get("host", "unknown"), {"asset_id": asset_id}))
    for asset_id in sorted(set(baseline_assets) & set(current_assets)):
        before = baseline_assets[asset_id]
        after = current_assets[asset_id]
        if before.get("status") != after.get("status"):
            deltas.append(_delta(
                "asset_status_changed",
                "low",
                after.get("host", "unknown"),
                {"asset_id": asset_id, "before": before.get("status"), "after": after.get("status")},
            ))

    for key in sorted(set(current_services) - set(baseline_services)):
        service = current_services[key]
        deltas.append(_delta("service_added", _service_delta_severity(service), service.get("target", "unknown"), _service_evidence(service)))
    for key in sorted(set(baseline_services) - set(current_services)):
        service = baseline_services[key]
        deltas.append(_delta("service_removed", "low", service.get("target", "unknown"), _service_evidence(service)))
    for key in sorted(set(baseline_services) & set(current_services)):
        before = baseline_services[key]
        after = current_services[key]
        if _service_signature(before) != _service_signature(after):
            deltas.append(_delta(
                "service_changed",
                "medium",
                after.get("target", "unknown"),
                {"before": _service_signature(before), "after": _service_signature(after), **_service_evidence(after)},
            ))

    for key in sorted(set(current_edges) - set(baseline_edges)):
        edge = current_edges[key]
        deltas.append(_delta("topology_relationship_added", "medium", key, _edge_evidence(edge)))
    for key in sorted(set(baseline_edges) - set(current_edges)):
        edge = baseline_edges[key]
        deltas.append(_delta("topology_relationship_removed", "low", key, _edge_evidence(edge)))

    findings = [_finding_from_delta(delta) for delta in deltas]
    workflows = [_workflow_from_finding(finding, require_approval=require_approval) for finding in findings if finding["severity"] in {"high", "critical"}]
    return {
        "ok": True,
        "baseline_snapshot_id": baseline.get("snapshot_id", ""),
        "current_snapshot_id": current.get("snapshot_id", ""),
        "delta_count": len(deltas),
        "deltas": deltas,
        "findings": findings,
        "response_workflows": workflows,
        "summary": _delta_summary(deltas, workflows),
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
    }


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _flow_rows(value: Iterable[dict[str, Any]] | dict[str, Any] | None) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return _rows(value.get("flows"))
    return _rows(value)


def _services_by_host(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        host = str(row.get("target") or "")
        if not host:
            continue
        grouped.setdefault(host, []).append(row)
    return grouped


def _flows_by_host(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        for endpoint in (row.get("initiator") or {}, row.get("responder") or {}):
            host = str(endpoint.get("ip") or "")
            if host:
                grouped.setdefault(host, []).append(row)
    return grouped


def _snapshot_asset(asset: dict[str, Any], services: list[dict[str, Any]], flows: list[dict[str, Any]]) -> dict[str, Any]:
    host = str(asset.get("host") or "unknown")
    service_ports = sorted({int(row.get("port") or 0) for row in services if row.get("port")})
    peers = sorted(_flow_peer(host, row) for row in flows if _flow_peer(host, row))
    identity = _identity_details(asset, services, flows)
    return {
        "asset_id": _asset_id(asset),
        "host": host,
        "status": str(asset.get("status") or "unknown"),
        "ip_version": int(asset.get("ip_version") or 0),
        "target_source": str(asset.get("target_source") or "unknown"),
        "identity": identity,
        "service_ports": service_ports,
        "services": sorted({str(row.get("service") or "unknown") for row in services}),
        "peers": peers,
        "relationship_count": len(peers),
    }


def _identity_details(asset: dict[str, Any], services: list[dict[str, Any]], flows: list[dict[str, Any]]) -> dict[str, Any]:
    confidence = 0.35
    sources = ["host"]
    if asset.get("status") == "reachable":
        confidence += 0.10
        sources.append("status")
    if _has_realish_value(asset.get("mac")):
        confidence += 0.20
        sources.append("hardware_address")
    if services:
        confidence += 0.15
        sources.append("service_set")
    if any(row.get("version") for row in services):
        confidence += 0.05
        sources.append("service_version")
    if flows:
        confidence += 0.15
        sources.append("flow_peers")
    confidence = min(confidence, 0.99)
    return {
        "confidence": round(confidence, 2),
        "confidence_label": "high" if confidence >= 0.75 else "medium" if confidence >= 0.5 else "low",
        "source_count": len(sources),
        "sources": sources,
        "raw_identifier_stored": False,
    }


def _asset_id(asset: dict[str, Any]) -> str:
    host = str(asset.get("host") or "unknown")
    ip_version = str(asset.get("ip_version") or "unknown")
    hardware = str(asset.get("mac") or "") if _has_realish_value(asset.get("mac")) else ""
    return "asset-" + sha256(f"{host}:{ip_version}:{hardware}".encode("utf-8")).hexdigest()[:16]


def _snapshot_service(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "target": str(row.get("target") or "unknown"),
        "port": int(row.get("port") or 0),
        "state": str(row.get("state") or "unknown"),
        "service": str(row.get("service") or "unknown"),
        "version": str(row.get("version") or ""),
        "confidence": float(row.get("confidence") or 0.0),
        "exposure": str(row.get("exposure") or "unknown"),
    }


def _topology(flows: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for row in flows:
        initiator = str((row.get("initiator") or {}).get("ip") or "")
        responder = str((row.get("responder") or {}).get("ip") or "")
        if not initiator or not responder:
            continue
        for host in (initiator, responder):
            node = nodes.setdefault(host, {"host": host, "flow_count": 0, "payload_bytes": 0})
            node["flow_count"] += 1
            node["payload_bytes"] += int(row.get("payload_bytes") or 0)
        key = (initiator, responder)
        edge = edges.setdefault(
            key,
            {"src": initiator, "dst": responder, "flow_count": 0, "payload_bytes": 0, "application_protocols": set()},
        )
        edge["flow_count"] += 1
        edge["payload_bytes"] += int(row.get("payload_bytes") or 0)
        edge["application_protocols"].update(str(item) for item in row.get("application_protocols") or [])
    return {
        "nodes": sorted(nodes.values(), key=lambda item: item["host"]),
        "edges": [
            {**edge, "application_protocols": sorted(edge["application_protocols"])}
            for edge in sorted(edges.values(), key=lambda item: (item["src"], item["dst"]))
        ],
    }


def _flow_peer(host: str, row: dict[str, Any]) -> str:
    initiator = str((row.get("initiator") or {}).get("ip") or "")
    responder = str((row.get("responder") or {}).get("ip") or "")
    if host == initiator:
        return responder
    if host == responder:
        return initiator
    return ""


def _has_realish_value(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and not text.startswith("<") and text.lower() not in {"unknown", "redacted"})


def _service_key(row: dict[str, Any]) -> str:
    return f"{row.get('target', 'unknown')}:{int(row.get('port') or 0)}"


def _service_signature(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "state": row.get("state", "unknown"),
        "service": row.get("service", "unknown"),
        "version": row.get("version", ""),
        "confidence": round(float(row.get("confidence") or 0), 2),
    }


def _service_delta_severity(service: dict[str, Any]) -> str:
    name = str(service.get("service") or "unknown").lower()
    port = int(service.get("port") or 0)
    if name in {"ssh", "rdp", "vnc", "winrm", "postgresql", "mysql", "redis", "mongodb", "mssql", "oracle", "elasticsearch"}:
        return "high"
    if port:
        return "medium"
    return "low"


def _service_evidence(service: dict[str, Any]) -> dict[str, Any]:
    return {
        "target": service.get("target", "unknown"),
        "port": int(service.get("port") or 0),
        "service": service.get("service", "unknown"),
        "state": service.get("state", "unknown"),
    }


def _edge_key(row: dict[str, Any]) -> str:
    return f"{row.get('src', 'unknown')}->{row.get('dst', 'unknown')}"


def _edge_evidence(edge: dict[str, Any]) -> dict[str, Any]:
    return {
        "src": edge.get("src", "unknown"),
        "dst": edge.get("dst", "unknown"),
        "application_protocols": list(edge.get("application_protocols") or []),
        "flow_count": int(edge.get("flow_count") or 0),
    }


def _delta(delta_type: str, severity: str, target: Any, evidence: dict[str, Any]) -> dict[str, Any]:
    delta_id = sha256(f"{delta_type}:{target}:{evidence}".encode("utf-8")).hexdigest()[:16]
    return {
        "delta_id": delta_id,
        "type": delta_type,
        "severity": severity,
        "target": str(target),
        "evidence": evidence,
        "recommended_action": _recommended_action(delta_type),
    }


def _recommended_action(delta_type: str) -> str:
    if delta_type.startswith("service_"):
        return "review_service_change"
    if delta_type.startswith("topology_"):
        return "review_topology_relationship"
    return "review_asset_baseline"


def _finding_from_delta(delta: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": "delta-" + delta["delta_id"],
        "category": "visibility_delta",
        "severity": delta["severity"],
        "type": delta["type"],
        "target": delta["target"],
        "message": f"Visibility baseline delta detected: {delta['type']}.",
        "evidence": delta["evidence"],
        "recommended_action": delta["recommended_action"],
    }


def _workflow_from_finding(finding: dict[str, Any], *, require_approval: bool) -> dict[str, Any]:
    return {
        "workflow_id": sha256(f"{finding['finding_id']}:{finding['recommended_action']}".encode("utf-8")).hexdigest()[:16],
        "source_finding_id": finding["finding_id"],
        "action": finding["recommended_action"],
        "target": finding["target"],
        "approval_required": bool(require_approval),
        "dry_run": True,
        "confirmed": False,
        "automatic_execution": False,
        "status": "pending_operator_review",
    }


def _delta_summary(deltas: list[dict[str, Any]], workflows: list[dict[str, Any]]) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for delta in deltas:
        by_type[delta["type"]] = by_type.get(delta["type"], 0) + 1
        by_severity[delta["severity"]] = by_severity.get(delta["severity"], 0) + 1
    return {
        "delta_count": len(deltas),
        "by_type": dict(sorted(by_type.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "response_workflow_count": len(workflows),
    }


__all__ = ["SNAPSHOT_SCHEMA_VERSION", "build_visibility_snapshot", "compare_visibility_snapshots"]
