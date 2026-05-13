from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable


class AggregationError(ValueError):
    """Raised when a node visibility report is malformed."""


def normalize_node_report(report: dict[str, Any]) -> dict[str, Any]:
    validate_node_report(report)
    node_id = str(report["node_id"])
    collected_at = str(report.get("collected_at") or _now())
    normalized = {
        "node_id": node_id,
        "node_label": str(report.get("node_label") or node_id),
        "collected_at": collected_at,
        "assets": [_with_source(row, node_id, collected_at, "asset") for row in _rows(report.get("assets"))],
        "services": [_with_source(row, node_id, collected_at, "service") for row in _rows(report.get("services"))],
        "topology_edges": [_with_source(row, node_id, collected_at, "edge") for row in _rows(report.get("topology_edges"))],
        "findings": [_with_source(row, node_id, collected_at, "finding") for row in _rows(report.get("findings"))],
        "metadata": dict(report.get("metadata") or {}),
        "raw_payload_stored": bool(report.get("raw_payload_stored", False)),
        "automatic_changes": bool(report.get("automatic_changes", False)),
        "administrator_controlled": bool(report.get("administrator_controlled", True)),
        "local_only": True,
    }
    validate_node_report(normalized)
    return normalized


def validate_node_report(report: dict[str, Any]) -> None:
    if not isinstance(report, dict):
        raise AggregationError("node report must be an object")
    node_id = report.get("node_id")
    if not isinstance(node_id, str) or not node_id.strip():
        raise AggregationError("node_id must be a non-empty string")
    for field_name in ("assets", "services", "topology_edges", "findings"):
        value = report.get(field_name, [])
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise AggregationError(f"{field_name} must be a list of objects")
    if not isinstance(report.get("metadata", {}), dict):
        raise AggregationError("metadata must be an object")
    if report.get("raw_payload_stored", False) is not False:
        raise AggregationError("node reports cannot store raw payloads")
    if report.get("automatic_changes", False) is not False:
        raise AggregationError("node reports cannot request automatic changes")
    if report.get("administrator_controlled", True) is not True:
        raise AggregationError("node reports must remain administrator controlled")


def collect_node_reports(reports: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [normalize_node_report(report) for report in reports]


def summarize_collection(reports: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(reports)
    return {
        "status": "ok",
        "node_count": len(rows),
        "asset_count": sum(len(_rows(row.get("assets"))) for row in rows),
        "service_count": sum(len(_rows(row.get("services"))) for row in rows),
        "topology_edge_count": sum(len(_rows(row.get("topology_edges"))) for row in rows),
        "finding_count": sum(len(_rows(row.get("findings"))) for row in rows),
        "source_node_ids": sorted({str(row.get("node_id")) for row in rows if row.get("node_id")}),
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
        "local_only": True,
    }


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _with_source(row: dict[str, Any], node_id: str, collected_at: str, prefix: str) -> dict[str, Any]:
    item = dict(row)
    item.setdefault("source_node_ids", [node_id])
    item.setdefault("source_refs", [f"{node_id}:{prefix}:{_record_id(item, prefix)}"])
    item.setdefault("first_seen_at", collected_at)
    item.setdefault("last_seen_at", collected_at)
    item.setdefault("confidence", float(item.get("confidence") or 0.0))
    return item


def _record_id(row: dict[str, Any], prefix: str) -> str:
    for key in ("asset_id", "service_id", "edge_id", "finding_id", "id"):
        value = row.get(key)
        if value:
            return str(value)
    return prefix + "-unknown"


def _now() -> str:
    return datetime.now(UTC).isoformat()
