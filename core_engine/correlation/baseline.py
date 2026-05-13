from __future__ import annotations

import json
from hashlib import sha256
from typing import Any, Iterable


SAFETY_FLAGS = {
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
    "local_only": True,
}


def build_baseline_from_events(
    events: Iterable[dict[str, Any]],
    *,
    label: str = "event-baseline",
    start_time: str = "",
    end_time: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows = _rows(events)
    assets = [{"asset_id": str(row.get("asset_ref")), "source_refs": [_event_ref(row)]} for row in rows if row.get("asset_ref")]
    services = [{"service_id": str(row.get("service_ref")), "source_refs": [_event_ref(row)]} for row in rows if row.get("service_ref")]
    topology_edges = [{"edge_id": str(row.get("flow_ref")), "source_refs": [_event_ref(row)]} for row in rows if row.get("flow_ref")]
    findings = [
        {
            "finding_id": str(row.get("finding_ref") or row.get("event_id") or f"event-finding-{index}"),
            "category": str((row.get("metadata") or {}).get("category") or row.get("event_type") or "event"),
            "severity": str(row.get("severity") or "info"),
            "source_refs": [_event_ref(row)],
        }
        for index, row in enumerate(rows)
        if row.get("finding_ref") or str(row.get("severity") or "info") in {"medium", "high", "critical"}
    ]
    return _build_baseline(
        label=label,
        start_time=start_time or _time_bound(rows, first=True),
        end_time=end_time or _time_bound(rows, first=False),
        events=rows,
        assets=assets,
        services=services,
        topology_edges=topology_edges,
        findings=findings,
        metadata=metadata,
    )


def build_baseline_from_snapshots(
    snapshots: Iterable[dict[str, Any]],
    *,
    label: str = "snapshot-baseline",
    start_time: str = "",
    end_time: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows = _rows(snapshots)
    assets: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    topology_edges: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for snapshot in rows:
        snapshot_ref = str(snapshot.get("snapshot_id") or snapshot.get("id") or "snapshot")
        assets.extend(_tag_rows(snapshot.get("assets"), snapshot_ref))
        services.extend(_tag_rows(snapshot.get("services"), snapshot_ref))
        topology_edges.extend(_tag_rows(snapshot.get("topology_edges"), snapshot_ref))
        topology_edges.extend(_tag_rows((snapshot.get("topology") or {}).get("edges"), snapshot_ref))
        findings.extend(_tag_rows(snapshot.get("findings"), snapshot_ref))
    return _build_baseline(
        label=label,
        start_time=start_time or _time_bound(rows, first=True),
        end_time=end_time or _time_bound(rows, first=False),
        events=[],
        assets=assets,
        services=services,
        topology_edges=topology_edges,
        findings=findings,
        metadata=metadata,
    )


def build_baseline_from_visibility_reports(
    reports: Iterable[dict[str, Any]],
    *,
    label: str = "visibility-baseline",
    start_time: str = "",
    end_time: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows = _rows(reports)
    assets: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    topology_edges: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for report in rows:
        report_ref = str(report.get("report_id") or report.get("visibility_id") or report.get("node_id") or "visibility-report")
        assets.extend(_tag_rows(report.get("assets"), report_ref))
        services.extend(_tag_rows(report.get("services"), report_ref))
        topology_edges.extend(_tag_rows(report.get("topology_edges"), report_ref))
        findings.extend(_tag_rows(report.get("findings"), report_ref))
    return _build_baseline(
        label=label,
        start_time=start_time or _time_bound(rows, first=True),
        end_time=end_time or _time_bound(rows, first=False),
        events=[],
        assets=assets,
        services=services,
        topology_edges=topology_edges,
        findings=findings,
        metadata=metadata,
    )


def build_baseline_from_aggregated_reports(
    reports: Iterable[dict[str, Any]] | dict[str, Any],
    *,
    label: str = "aggregated-baseline",
    start_time: str = "",
    end_time: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows = [reports] if isinstance(reports, dict) else _rows(reports)
    assets: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    topology_edges: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for report in rows:
        report_ref = str(report.get("aggregation_id") or "aggregated-report")
        assets.extend(_tag_rows(report.get("assets"), report_ref))
        services.extend(_tag_rows(report.get("services"), report_ref))
        topology_edges.extend(_tag_rows(report.get("topology_edges"), report_ref))
        findings.extend(_tag_rows(report.get("findings"), report_ref))
    return _build_baseline(
        label=label,
        start_time=start_time or _time_bound(rows, first=True),
        end_time=end_time or _time_bound(rows, first=False),
        events=[],
        assets=assets,
        services=services,
        topology_edges=topology_edges,
        findings=findings,
        metadata=metadata,
    )


def _build_baseline(
    *,
    label: str,
    start_time: str,
    end_time: str,
    events: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    services: list[dict[str, Any]],
    topology_edges: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    unique_assets = _dedupe(assets, _asset_key)
    unique_services = _dedupe(services, _service_key)
    unique_edges = _dedupe(topology_edges, _topology_key)
    unique_findings = _dedupe(findings, _finding_key)
    payload = {
        "baseline_id": "",
        "label": str(label or "baseline"),
        "start_time": str(start_time or ""),
        "end_time": str(end_time or ""),
        "event_count": len(events),
        "asset_count": len(unique_assets),
        "service_count": len(unique_services),
        "topology_edge_count": len(unique_edges),
        "finding_count": len(unique_findings),
        "metadata": dict(metadata or {}),
        "events": events,
        "assets": unique_assets,
        "services": unique_services,
        "topology_edges": unique_edges,
        "findings": unique_findings,
        **SAFETY_FLAGS,
    }
    payload["baseline_id"] = "baseline-" + sha256(
        json.dumps(
            {
                "label": payload["label"],
                "start_time": payload["start_time"],
                "end_time": payload["end_time"],
                "assets": unique_assets,
                "services": unique_services,
                "topology_edges": unique_edges,
                "findings": unique_findings,
            },
            sort_keys=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()[:16]
    return payload


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _tag_rows(value: Any, source_ref: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _rows(value):
        item = dict(row)
        refs = item.get("source_refs")
        if isinstance(refs, list):
            item["source_refs"] = sorted({str(ref) for ref in refs if ref} | {source_ref})
        else:
            item["source_refs"] = [source_ref]
        rows.append(item)
    return rows


def _dedupe(rows: list[dict[str, Any]], key_fn) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = key_fn(row)
        item = by_key.setdefault(key, dict(row))
        item["correlation_key"] = key
        item["source_refs"] = sorted(set(item.get("source_refs") or []) | set(row.get("source_refs") or []))
    return sorted(by_key.values(), key=lambda item: item["correlation_key"])


def _asset_key(row: dict[str, Any]) -> str:
    return _first(row, "asset_id", "host", "label", "node_id") or "asset-unknown"


def _service_key(row: dict[str, Any]) -> str:
    target = _first(row, "asset_id", "target", "host", "service_id") or "target-unknown"
    port = str(row.get("port") or "0")
    return f"{target}:{port}"


def _topology_key(row: dict[str, Any]) -> str:
    source = _first(row, "source_asset", "src", "source", "from") or "source-unknown"
    target = _first(row, "target_asset", "dst", "target", "to") or "target-unknown"
    relation = _first(row, "relationship_type", "type", "protocol") or "relationship"
    return f"{source}>{target}:{relation}"


def _finding_key(row: dict[str, Any]) -> str:
    return _first(row, "finding_id", "source_ref", "title", "summary", "category") or "finding-unknown"


def _first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _time_bound(rows: list[dict[str, Any]], *, first: bool) -> str:
    values = sorted(
        str(row.get("timestamp") or row.get("observed_at") or row.get("collected_at") or row.get("created_at") or "")
        for row in rows
        if row.get("timestamp") or row.get("observed_at") or row.get("collected_at") or row.get("created_at")
    )
    if not values:
        return ""
    return values[0] if first else values[-1]


def _event_ref(row: dict[str, Any]) -> str:
    return str(row.get("event_id") or row.get("timestamp") or "event")
