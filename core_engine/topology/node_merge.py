from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.aggregation.conflict_resolution import build_conflict_record


SAFETY_FLAGS = {
    "local_only": True,
    "read_only": True,
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
}


def merge_federated_assets(rows: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return _merge_rows(
        rows,
        key_fn=lambda row: _first(row, "asset_id", "host", "target", "label") or "asset-unknown",
        record_type="asset",
        duplicate_conflict_type="duplicate_asset",
        conflict_fields={"label": "asset_label_drift"},
        prefer_fields=("asset_id", "label", "category", "role"),
    )


def merge_federated_services(rows: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return _merge_rows(
        rows,
        key_fn=lambda row: "|".join([_first(row, "asset_id", "target", "host") or "asset-unknown", str(row.get("port") or "0")]),
        record_type="service",
        duplicate_conflict_type="duplicate_service",
        conflict_fields={"service": "service_name_drift", "service_name": "service_name_drift"},
        prefer_fields=("service_id", "asset_id", "target", "port", "service", "service_name"),
        sum_fields=("observation_count",),
    )


def merge_federated_topology_edges(rows: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return _merge_rows(
        rows,
        key_fn=lambda row: "|".join(
            [
                _first(row, "source_asset", "src", "source", "from") or "source-unknown",
                _first(row, "target_asset", "dst", "target", "to") or "target-unknown",
                _first(row, "relationship_type", "type") or "relationship",
            ]
        ),
        record_type="topology_edge",
        duplicate_conflict_type="duplicate_topology_edge",
        conflict_fields={"protocol_service_label": "edge_disagreement", "service_label": "edge_disagreement", "protocol": "edge_disagreement"},
        prefer_fields=("edge_id", "source_asset", "target_asset", "relationship_type", "protocol_service_label", "service_label", "protocol"),
        sum_fields=("observation_count", "flow_count"),
    )


def merge_federated_findings(rows: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return _merge_rows(
        rows,
        key_fn=lambda row: _first(row, "finding_id", "source_ref", "title", "summary") or "finding-unknown",
        record_type="finding",
        duplicate_conflict_type="duplicate_finding",
        conflict_fields={"severity": "finding_severity_drift"},
        prefer_fields=("finding_id", "finding_type", "severity", "title", "summary"),
    )


def build_federated_conflict(
    *,
    conflict_type: str,
    affected_ref: str,
    source_node_ids: list[str],
    source_refs: list[str] | None = None,
    summary: str,
    severity: str = "medium",
    recommended_review: bool = True,
) -> dict[str, Any]:
    record = build_conflict_record(
        conflict_type=conflict_type,
        affected_ref=affected_ref,
        source_node_ids=source_node_ids,
        summary=summary,
        severity=severity,
        recommended_review=recommended_review,
    )
    record["source_refs"] = sorted(set(str(ref) for ref in source_refs or [] if str(ref).strip()))
    record["local_only"] = True
    record["read_only"] = True
    return record


def _merge_rows(
    rows: Iterable[dict[str, Any]],
    *,
    key_fn,
    record_type: str,
    duplicate_conflict_type: str,
    conflict_fields: dict[str, str],
    prefer_fields: tuple[str, ...],
    sum_fields: tuple[str, ...] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        key = key_fn(row)
        grouped.setdefault(key, []).append(dict(row))

    merged: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for key in sorted(grouped):
        group = grouped[key]
        item = _base_record(record_type, key, group, prefer_fields=prefer_fields, sum_fields=sum_fields)
        if len(group) > 1:
            conflicts.append(
                build_federated_conflict(
                    conflict_type=duplicate_conflict_type,
                    affected_ref=f"{record_type}:{key}",
                    source_node_ids=item["source_node_ids"],
                    source_refs=item["source_refs"],
                    summary=f"{record_type} {key} was reported by multiple trusted node snapshots.",
                    severity="low",
                    recommended_review=True,
                )
            )
        for field, conflict_type in conflict_fields.items():
            values = sorted({str(row.get(field)) for row in group if row.get(field) not in (None, "")})
            if len(values) > 1:
                conflicts.append(
                    build_federated_conflict(
                        conflict_type=conflict_type,
                        affected_ref=f"{record_type}:{key}",
                        source_node_ids=item["source_node_ids"],
                        source_refs=item["source_refs"],
                        summary=f"{record_type} {key} has conflicting {field} values: {', '.join(values)}.",
                        severity="medium",
                        recommended_review=True,
                    )
                )
        merged.append(item)
    return merged, _dedupe_conflicts(conflicts)


def _base_record(
    record_type: str,
    key: str,
    rows: list[dict[str, Any]],
    *,
    prefer_fields: tuple[str, ...],
    sum_fields: tuple[str, ...],
) -> dict[str, Any]:
    ordered = sorted(rows, key=lambda row: (str(row.get("observed_at") or row.get("last_seen_at") or ""), json.dumps(row, sort_keys=True, default=str)))
    selected = ordered[-1]
    source_node_ids = sorted({node for row in rows for node in _source_nodes(row)})
    source_refs = sorted({ref for row in rows for ref in _source_refs(row)})
    confidence_values = [_confidence(row) for row in rows]
    first_seen = min((str(row.get("first_seen_at") or row.get("observed_at") or row.get("collected_at") or "") for row in rows if row.get("first_seen_at") or row.get("observed_at") or row.get("collected_at")), default="")
    last_seen = max((str(row.get("last_seen_at") or row.get("observed_at") or row.get("collected_at") or "") for row in rows if row.get("last_seen_at") or row.get("observed_at") or row.get("collected_at")), default=first_seen)
    item: dict[str, Any] = {
        "record_type": record_type,
        "merge_key": key,
        "source_node_ids": source_node_ids,
        "source_refs": source_refs,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "confidence": _combined_confidence(confidence_values),
        "observation_count": sum(int(row.get("observation_count") or 1) for row in rows),
        **SAFETY_FLAGS,
    }
    for field in prefer_fields:
        value = selected.get(field)
        if value in (None, ""):
            value = _first_non_empty(rows, field)
        if value not in (None, ""):
            item[field] = value
    for field in sum_fields:
        if field in item:
            continue
        total = sum(int(row.get(field) or 0) for row in rows)
        if total:
            item[field] = total
    _fill_canonical_fields(item, record_type, key)
    item[f"{record_type}_id"] = str(item.get(f"{record_type}_id") or _stable_id(record_type, key, source_node_ids))
    return item


def _fill_canonical_fields(item: dict[str, Any], record_type: str, key: str) -> None:
    if record_type == "asset":
        item.setdefault("asset_id", key)
        item.setdefault("label", item["asset_id"])
        item.setdefault("category", item.get("role") or "asset")
    elif record_type == "service":
        asset_id, _, port = key.partition("|")
        item.setdefault("asset_id", asset_id)
        item.setdefault("target", asset_id)
        item.setdefault("port", int(port) if port.isdigit() else 0)
        item.setdefault("service_name", item.get("service") or "unknown")
    elif record_type == "topology_edge":
        source, target, relationship = (key.split("|") + ["", "", ""])[:3]
        item.setdefault("source_asset", source)
        item.setdefault("target_asset", target)
        item.setdefault("relationship_type", relationship or "relationship")
    elif record_type == "finding":
        item.setdefault("finding_id", _stable_id("finding", key))
        item.setdefault("finding_type", "federated_topology_finding")
        item.setdefault("severity", "info")
        item.setdefault("summary", str(item.get("title") or item["finding_type"]).replace("_", " "))


def _source_nodes(row: dict[str, Any]) -> list[str]:
    if isinstance(row.get("source_node_ids"), list):
        return [str(item) for item in row["source_node_ids"] if str(item).strip()]
    if row.get("source_node_id"):
        return [str(row["source_node_id"])]
    if row.get("node_id"):
        return [str(row["node_id"])]
    return []


def _source_refs(row: dict[str, Any]) -> list[str]:
    refs = row.get("source_refs")
    if isinstance(refs, list):
        return [str(item) for item in refs if str(item).strip()]
    for key in ("source_ref", "snapshot_id", "asset_id", "service_id", "edge_id", "finding_id"):
        if row.get(key):
            return [f"{key}:{row[key]}"]
    return []


def _first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        if row.get(key) not in (None, ""):
            return str(row[key])
    return ""


def _first_non_empty(rows: list[dict[str, Any]], field: str) -> Any:
    for row in rows:
        if row.get(field) not in (None, ""):
            return row[field]
    return None


def _confidence(row: dict[str, Any]) -> float:
    try:
        value = float(row.get("confidence") or 0.0)
    except (TypeError, ValueError):
        value = 0.0
    return min(max(value, 0.0), 1.0)


def _combined_confidence(values: list[float]) -> float:
    if not values:
        return 0.0
    average = sum(values) / len(values)
    source_bonus = min(0.15, max(0, len(values) - 1) * 0.05)
    return round(min(1.0, average + source_bonus), 3)


def _dedupe_conflicts(conflicts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted({conflict["conflict_id"]: conflict for conflict in conflicts}.values(), key=lambda item: item["conflict_id"])


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
