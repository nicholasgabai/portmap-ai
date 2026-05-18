from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.topology.graph import build_topology_graph, summarize_topology


TOPOLOGY_SNAPSHOT_RECORD_VERSION = 1
SAFETY_FLAGS = {
    "local_only": True,
    "read_only": True,
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
}


def build_topology_snapshot(
    *,
    assets: Iterable[dict[str, Any]] | None = None,
    services: Iterable[dict[str, Any]] | None = None,
    topology_edges: Iterable[dict[str, Any]] | None = None,
    findings: Iterable[dict[str, Any]] | None = None,
    label: str = "topology-snapshot",
    observed_at: str | None = None,
    source_ref: str | None = None,
) -> dict[str, Any]:
    observed = observed_at or _now()
    graph = build_topology_graph(
        assets=assets,
        services=services,
        topology_edges=topology_edges,
        generated_at=observed,
    )
    finding_rows = [_normalize_finding(row) for row in _rows(findings)]
    summary = _snapshot_summary(graph, finding_rows)
    payload = {
        "ok": True,
        "record_version": TOPOLOGY_SNAPSHOT_RECORD_VERSION,
        "snapshot_type": "topology_state",
        "snapshot_id": "",
        "label": str(label or "topology-snapshot"),
        "observed_at": observed,
        "source_ref": source_ref or "topology:operator-provided",
        "topology": {
            "nodes": graph["nodes"],
            "edges": graph["edges"],
            "summary": summarize_topology(graph),
        },
        "findings": finding_rows,
        "summary": summary,
        "storage_ready": True,
        **SAFETY_FLAGS,
    }
    payload["snapshot_id"] = _stable_id(
        "topology-snapshot",
        {
            "label": payload["label"],
            "observed_at": payload["observed_at"],
            "topology": payload["topology"],
            "findings": payload["findings"],
        },
    )
    payload["summary"]["snapshot_id"] = payload["snapshot_id"]
    return payload


def summarize_topology_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    topology = snapshot.get("topology") if isinstance(snapshot.get("topology"), dict) else {}
    summary = topology.get("summary") if isinstance(topology.get("summary"), dict) else {}
    findings = _rows(snapshot.get("findings"))
    by_severity: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "info")
        by_severity[severity] = by_severity.get(severity, 0) + 1
    return {
        "snapshot_id": str(snapshot.get("snapshot_id") or ""),
        "label": str(snapshot.get("label") or ""),
        "observed_at": str(snapshot.get("observed_at") or ""),
        "node_count": int(summary.get("node_count") or 0),
        "edge_count": int(summary.get("edge_count") or 0),
        "service_count": int(summary.get("service_count") or 0),
        "relationship_count": int(summary.get("relationship_count") or 0),
        "finding_count": len(findings),
        "findings_by_severity": dict(sorted(by_severity.items())),
        **SAFETY_FLAGS,
    }


def topology_snapshot_to_storage_record(snapshot: dict[str, Any]) -> dict[str, Any]:
    summary = summarize_topology_snapshot(snapshot)
    return {
        "snapshot_id": summary["snapshot_id"] or _stable_id("topology-snapshot", snapshot),
        "label": summary["label"],
        "observed_at": summary["observed_at"],
        "snapshot_type": "topology_state",
        "summary": summary,
        "payload": snapshot,
        **SAFETY_FLAGS,
    }


def validate_topology_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(snapshot, dict):
        errors.append("snapshot must be an object")
    else:
        if snapshot.get("snapshot_type") != "topology_state":
            errors.append("snapshot_type must be topology_state")
        if not isinstance(snapshot.get("snapshot_id"), str) or not snapshot.get("snapshot_id"):
            errors.append("snapshot_id is required")
        topology = snapshot.get("topology")
        if not isinstance(topology, dict):
            errors.append("topology must be an object")
        else:
            if not isinstance(topology.get("nodes"), list):
                errors.append("topology.nodes must be a list")
            if not isinstance(topology.get("edges"), list):
                errors.append("topology.edges must be a list")
    return {
        "ok": not errors,
        "status": "valid" if not errors else "invalid",
        "errors": errors,
        **SAFETY_FLAGS,
    }


def _snapshot_summary(graph: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    summary = summarize_topology(graph)
    return {
        "snapshot_id": "",
        "node_count": summary["node_count"],
        "edge_count": summary["edge_count"],
        "service_count": summary["service_count"],
        "relationship_count": summary["relationship_count"],
        "finding_count": len(findings),
        "recommended_review": any(str(item.get("severity") or "info") in {"medium", "high", "critical"} for item in findings),
        **SAFETY_FLAGS,
    }


def _normalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    finding_type = str(finding.get("finding_type") or finding.get("type") or "topology_finding")
    finding_id = str(finding.get("finding_id") or _stable_id("finding", finding_type, finding))
    return {
        "finding_id": finding_id,
        "finding_type": finding_type,
        "severity": str(finding.get("severity") or "info"),
        "summary": str(finding.get("summary") or finding_type.replace("_", " ")),
        "source_refs": sorted(str(ref) for ref in finding.get("source_refs") or []),
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
