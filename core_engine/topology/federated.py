from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.topology.graph import build_topology_graph, summarize_topology
from core_engine.topology.node_merge import (
    SAFETY_FLAGS,
    merge_federated_assets,
    merge_federated_findings,
    merge_federated_services,
    merge_federated_topology_edges,
)
from core_engine.topology.timeline import build_timeline_entries, summarize_timeline


FEDERATED_TOPOLOGY_RECORD_VERSION = 1


def build_federated_topology(
    node_snapshots: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
    label: str = "federated-topology",
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    reports = normalize_node_topology_snapshots(node_snapshots, observed_at=timestamp)
    assets, asset_conflicts = merge_federated_assets(_chain(reports, "assets"))
    services, service_conflicts = merge_federated_services(_chain(reports, "services"))
    edges, edge_conflicts = merge_federated_topology_edges(_chain(reports, "topology_edges"))
    findings, finding_conflicts = merge_federated_findings(_chain(reports, "findings"))
    conflicts = sorted(
        [*asset_conflicts, *service_conflicts, *edge_conflicts, *finding_conflicts],
        key=lambda item: item["conflict_id"],
    )
    graph = build_topology_graph(
        assets=assets,
        services=services,
        topology_edges=edges,
        generated_at=timestamp,
    )
    timeline_entries = build_federated_timeline_entries(conflicts=conflicts, findings=findings, generated_at=timestamp)
    correlation_records = build_federated_correlation_records(conflicts=conflicts, findings=findings, generated_at=timestamp)
    dashboard_summary = build_federated_dashboard_summary(
        assets=assets,
        services=services,
        edges=edges,
        findings=findings,
        conflicts=conflicts,
        graph=graph,
    )
    summary = summarize_federated_topology(
        assets=assets,
        services=services,
        topology_edges=edges,
        findings=findings,
        conflicts=conflicts,
        node_count=len(reports),
        graph=graph,
    )
    record = {
        "record_type": "federated_topology",
        "record_version": FEDERATED_TOPOLOGY_RECORD_VERSION,
        "federated_topology_id": "",
        "label": str(label or "federated-topology"),
        "generated_at": timestamp,
        "source_node_ids": sorted({node_id for report in reports for node_id in report["source_node_ids"]}),
        "node_reports": reports,
        "assets": assets,
        "services": services,
        "topology_edges": edges,
        "findings": findings,
        "conflicts": conflicts,
        "topology": graph,
        "timeline_entries": timeline_entries,
        "timeline_summary": summarize_timeline(timeline_entries),
        "correlation_records": correlation_records,
        "dashboard_summary": dashboard_summary,
        "summary": summary,
        **SAFETY_FLAGS,
    }
    record["federated_topology_id"] = _stable_id("federated-topology", record["source_node_ids"], timestamp, summary)
    return record


def normalize_node_topology_snapshots(
    node_snapshots: Iterable[dict[str, Any]],
    *,
    observed_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = observed_at or _now()
    reports = [_normalize_node_snapshot(snapshot, observed_at=timestamp) for snapshot in node_snapshots if isinstance(snapshot, dict)]
    return sorted(reports, key=lambda item: (item["node_id"], item["snapshot_id"]))


def summarize_federated_topology(
    *,
    assets: Iterable[dict[str, Any]] | None = None,
    services: Iterable[dict[str, Any]] | None = None,
    topology_edges: Iterable[dict[str, Any]] | None = None,
    findings: Iterable[dict[str, Any]] | None = None,
    conflicts: Iterable[dict[str, Any]] | None = None,
    node_count: int = 0,
    graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    asset_rows = _rows(assets)
    service_rows = _rows(services)
    edge_rows = _rows(topology_edges)
    finding_rows = _rows(findings)
    conflict_rows = _rows(conflicts)
    topology_summary = summarize_topology(graph or build_topology_graph(assets=asset_rows, services=service_rows, topology_edges=edge_rows))
    by_conflict_type: dict[str, int] = {}
    for conflict in conflict_rows:
        conflict_type = str(conflict.get("conflict_type") or "unknown")
        by_conflict_type[conflict_type] = by_conflict_type.get(conflict_type, 0) + 1
    return {
        "status": "ok",
        "source_node_count": int(node_count),
        "asset_count": len(asset_rows),
        "service_count": len(service_rows),
        "topology_edge_count": len(edge_rows),
        "finding_count": len(finding_rows),
        "conflict_count": len(conflict_rows),
        "graph_node_count": topology_summary["node_count"],
        "graph_edge_count": topology_summary["edge_count"],
        "relationship_count": topology_summary["relationship_count"],
        "by_conflict_type": dict(sorted(by_conflict_type.items())),
        "recommended_review": bool(conflict_rows) or any(str(row.get("severity") or "info") in {"medium", "high", "critical"} for row in finding_rows),
        **SAFETY_FLAGS,
    }


def build_federated_timeline_entries(
    *,
    conflicts: Iterable[dict[str, Any]] | None = None,
    findings: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    finding_rows = [
        {
            **finding,
            "timestamp": finding.get("timestamp") or finding.get("last_seen_at") or timestamp,
            "finding_type": finding.get("finding_type") or "federated_topology_finding",
        }
        for finding in _rows(findings)
    ]
    conflict_findings = [
        {
            "finding_id": conflict["conflict_id"],
            "finding_type": str(conflict.get("conflict_type") or "federated_topology_conflict"),
            "severity": str(conflict.get("severity") or "medium"),
            "summary": str(conflict.get("summary") or "Federated topology conflict."),
            "timestamp": conflict.get("detected_at") or timestamp,
            "source_refs": list(conflict.get("source_refs") or []),
            "recommended_review": True,
        }
        for conflict in _rows(conflicts)
    ]
    return build_timeline_entries(findings=[*finding_rows, *conflict_findings])


def build_federated_correlation_records(
    *,
    conflicts: Iterable[dict[str, Any]] | None = None,
    findings: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    records: list[dict[str, Any]] = []
    for conflict in _rows(conflicts):
        conflict_type = str(conflict.get("conflict_type") or "federated_topology_conflict")
        records.append(
            {
                "correlation_id": _stable_id("correlation", conflict.get("conflict_id"), conflict_type),
                "correlation_type": conflict_type,
                "severity": str(conflict.get("severity") or "medium"),
                "score": _severity_score(conflict.get("severity")),
                "summary": str(conflict.get("summary") or conflict_type.replace("_", " ")),
                "source_refs": list(conflict.get("source_refs") or []),
                "evidence_refs": [str(conflict.get("affected_ref") or "")],
                "generated_at": timestamp,
                "recommended_review": True,
                **SAFETY_FLAGS,
            }
        )
    for finding in _rows(findings):
        finding_type = str(finding.get("finding_type") or "federated_topology_finding")
        records.append(
            {
                "correlation_id": _stable_id("correlation", finding.get("finding_id"), finding_type),
                "correlation_type": finding_type,
                "severity": str(finding.get("severity") or "info"),
                "score": _severity_score(finding.get("severity")),
                "summary": str(finding.get("summary") or finding_type.replace("_", " ")),
                "source_refs": list(finding.get("source_refs") or []),
                "evidence_refs": [str(finding.get("finding_id") or "")],
                "generated_at": timestamp,
                "recommended_review": bool(finding.get("recommended_review")) or str(finding.get("severity") or "info") in {"medium", "high", "critical"},
                **SAFETY_FLAGS,
            }
        )
    return sorted(records, key=lambda item: item["correlation_id"])


def build_federated_dashboard_summary(
    *,
    assets: Iterable[dict[str, Any]],
    services: Iterable[dict[str, Any]],
    edges: Iterable[dict[str, Any]],
    findings: Iterable[dict[str, Any]],
    conflicts: Iterable[dict[str, Any]],
    graph: dict[str, Any],
) -> dict[str, Any]:
    source_nodes = {
        node
        for row in [*_rows(assets), *_rows(services), *_rows(edges), *_rows(findings)]
        for node in row.get("source_node_ids", [])
    }
    summary = summarize_federated_topology(
        assets=assets,
        services=services,
        topology_edges=edges,
        findings=findings,
        conflicts=conflicts,
        node_count=len(source_nodes),
        graph=graph,
    )
    return {
        "panel": "federated_topology",
        "status": "review_required" if summary["recommended_review"] else "ok",
        "metrics": {
            "source_node_count": summary["source_node_count"],
            "asset_count": summary["asset_count"],
            "service_count": summary["service_count"],
            "topology_edge_count": summary["topology_edge_count"],
            "finding_count": summary["finding_count"],
            "conflict_count": summary["conflict_count"],
        },
        "recommended_review": summary["recommended_review"],
        **SAFETY_FLAGS,
    }


def _normalize_node_snapshot(snapshot: dict[str, Any], *, observed_at: str) -> dict[str, Any]:
    node_id = str(snapshot.get("node_id") or snapshot.get("source_node_id") or _nested(snapshot, "node_state", "node_id") or "node-unknown")
    snapshot_id = str(snapshot.get("snapshot_id") or _nested(snapshot, "snapshot", "snapshot_id") or _stable_id("node-snapshot", node_id, snapshot))
    source_ref = str(snapshot.get("source_ref") or f"node-snapshot:{snapshot_id}")
    body = snapshot.get("snapshot") if isinstance(snapshot.get("snapshot"), dict) else snapshot
    topology = body.get("topology") if isinstance(body.get("topology"), dict) else {}
    assets = _normalize_rows(
        [*_rows(body.get("assets")), *_rows(topology.get("nodes"))],
        node_id=node_id,
        snapshot_id=snapshot_id,
        source_ref=source_ref,
        observed_at=str(body.get("observed_at") or snapshot.get("observed_at") or observed_at),
    )
    service_rows = [*_rows(body.get("services")), *_rows(topology.get("services"))]
    if not service_rows:
        service_rows = _services_from_topology_nodes(topology)
    services = _normalize_rows(
        service_rows,
        node_id=node_id,
        snapshot_id=snapshot_id,
        source_ref=source_ref,
        observed_at=str(body.get("observed_at") or snapshot.get("observed_at") or observed_at),
    )
    edges = _normalize_rows(
        [*_rows(body.get("topology_edges")), *_rows(topology.get("edges"))],
        node_id=node_id,
        snapshot_id=snapshot_id,
        source_ref=source_ref,
        observed_at=str(body.get("observed_at") or snapshot.get("observed_at") or observed_at),
    )
    findings = _normalize_rows(
        _rows(body.get("findings")),
        node_id=node_id,
        snapshot_id=snapshot_id,
        source_ref=source_ref,
        observed_at=str(body.get("observed_at") or snapshot.get("observed_at") or observed_at),
    )
    return {
        "node_id": node_id,
        "source_node_ids": [node_id],
        "snapshot_id": snapshot_id,
        "observed_at": str(body.get("observed_at") or snapshot.get("observed_at") or observed_at),
        "source_refs": [source_ref],
        "assets": assets,
        "services": services,
        "topology_edges": edges,
        "findings": findings,
        **SAFETY_FLAGS,
    }


def _normalize_rows(rows: list[dict[str, Any]], *, node_id: str, snapshot_id: str, source_ref: str, observed_at: str) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["source_node_ids"] = sorted(set([node_id, *[str(value) for value in item.get("source_node_ids") or []]]))
        item["source_refs"] = sorted(set([source_ref, f"snapshot:{snapshot_id}", *[str(value) for value in item.get("source_refs") or []]]))
        item.setdefault("snapshot_id", snapshot_id)
        item.setdefault("observed_at", observed_at)
        item.setdefault("confidence", 0.8)
        item.update(SAFETY_FLAGS)
        normalized.append(item)
    return normalized


def _services_from_topology_nodes(topology: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for node in _rows(topology.get("nodes")):
        count = int(node.get("service_count") or 0)
        if count <= 0:
            continue
        rows.append(
            {
                "asset_id": node.get("asset_id"),
                "target": node.get("asset_id"),
                "port": 0,
                "service_name": "observed_service",
                "observation_count": count,
                "confidence": node.get("confidence", 0.8),
            }
        )
    return rows


def _chain(reports: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for report in reports:
        rows.extend(_rows(report.get(field)))
    return rows


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _nested(payload: dict[str, Any], parent: str, key: str) -> Any:
    row = payload.get(parent)
    return row.get(key) if isinstance(row, dict) else None


def _severity_score(severity: Any) -> float:
    return {"info": 0.0, "low": 0.2, "medium": 0.45, "high": 0.75, "critical": 0.95}.get(str(severity or "info"), 0.0)


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
