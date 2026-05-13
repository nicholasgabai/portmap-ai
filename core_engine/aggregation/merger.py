from __future__ import annotations

from typing import Any, Iterable

from core_engine.aggregation.collector import collect_node_reports
from core_engine.aggregation.conflict_resolution import build_conflict_record


def merge_node_reports(reports: Iterable[dict[str, Any]]) -> dict[str, Any]:
    normalized = collect_node_reports(reports)
    assets, asset_conflicts = merge_assets(_chain(normalized, "assets"))
    services, service_conflicts = merge_services(_chain(normalized, "services"))
    edges, edge_conflicts = merge_topology_edges(_chain(normalized, "topology_edges"))
    findings, finding_conflicts = merge_findings(_chain(normalized, "findings"))
    conflicts = asset_conflicts + service_conflicts + edge_conflicts + finding_conflicts
    return {
        "status": "ok",
        "node_count": len(normalized),
        "source_node_ids": sorted({report["node_id"] for report in normalized}),
        "assets": assets,
        "services": services,
        "topology_edges": edges,
        "findings": findings,
        "conflicts": sorted(conflicts, key=lambda item: item["conflict_id"]),
        "summary": {
            "asset_count": len(assets),
            "service_count": len(services),
            "topology_edge_count": len(edges),
            "finding_count": len(findings),
            "conflict_count": len(conflicts),
        },
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
        "local_only": True,
    }


def merge_assets(rows: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return _merge_rows(
        rows,
        key_fn=lambda row: _first(row, "asset_id", "host", "label") or "asset-unknown",
        record_type="asset",
        duplicate_conflict_type="duplicate_asset",
        conflict_fields={"label": "conflicting_asset_labels", "category": "conflicting_asset_categories"},
        optional_fields=("label", "category"),
    )


def merge_services(rows: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return _merge_rows(
        rows,
        key_fn=lambda row: "|".join([_first(row, "asset_id", "target", "host") or "target-unknown", str(row.get("port") or "0")]),
        record_type="service",
        duplicate_conflict_type="duplicate_service",
        conflict_fields={"service": "conflicting_service_names", "service_name": "conflicting_service_names"},
        optional_fields=("service", "service_name", "port"),
    )


def merge_topology_edges(rows: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return _merge_rows(
        rows,
        key_fn=lambda row: "|".join([
            _first(row, "source_asset", "src", "source", "from") or "source-unknown",
            _first(row, "target_asset", "dst", "target", "to") or "target-unknown",
            _first(row, "relationship_type", "type") or "relationship",
        ]),
        record_type="topology_edge",
        duplicate_conflict_type="duplicate_topology_edge",
        conflict_fields={"protocol": "conflicting_protocols", "service_label": "conflicting_service_labels"},
        optional_fields=("source_asset", "src", "target_asset", "dst", "relationship_type", "type"),
        sum_fields=("observation_count", "flow_count"),
    )


def merge_findings(rows: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return _merge_rows(
        rows,
        key_fn=lambda row: _first(row, "finding_id", "source_ref", "title", "summary") or "finding-unknown",
        record_type="finding",
        duplicate_conflict_type="duplicate_finding",
        conflict_fields={"severity": "conflicting_severities", "title": "conflicting_titles"},
        optional_fields=("title", "severity"),
    )


def _merge_rows(
    rows: Iterable[dict[str, Any]],
    *,
    key_fn,
    record_type: str,
    duplicate_conflict_type: str,
    conflict_fields: dict[str, str],
    optional_fields: tuple[str, ...] = (),
    sum_fields: tuple[str, ...] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    merged: dict[str, dict[str, Any]] = {}
    conflicts: list[dict[str, Any]] = []
    observed_values: dict[tuple[str, str], set[str]] = {}
    observed_keys: dict[str, int] = {}
    confidence_values: dict[str, set[str]] = {}
    source_by_key: dict[str, set[str]] = {}
    for row in rows:
        key = key_fn(row)
        observed_keys[key] = observed_keys.get(key, 0) + 1
        source_by_key.setdefault(key, set()).update(_source_nodes(row))
        if key not in merged:
            item = dict(row)
            item["source_node_ids"] = sorted(set(_source_nodes(row)))
            item["source_refs"] = sorted(set(_source_refs(row)))
            item["first_seen_at"] = _first(row, "first_seen_at", "collected_at") or ""
            item["last_seen_at"] = _first(row, "last_seen_at", "collected_at") or item["first_seen_at"]
            item["confidence"] = _confidence(row)
            item["merge_key"] = key
            merged[key] = item
        else:
            item = merged[key]
            before_sources = set(item.get("source_node_ids") or [])
            item["source_node_ids"] = sorted(before_sources | set(_source_nodes(row)))
            item["source_refs"] = sorted(set(item.get("source_refs") or []) | set(_source_refs(row)))
            item["first_seen_at"] = min(filter(None, [str(item.get("first_seen_at") or ""), _first(row, "first_seen_at", "collected_at") or ""]))
            item["last_seen_at"] = max(filter(None, [str(item.get("last_seen_at") or ""), _first(row, "last_seen_at", "collected_at") or ""]))
            item["confidence"] = max(float(item.get("confidence") or 0.0), _confidence(row))
            for field in sum_fields:
                if field in row:
                    item[field] = int(item.get(field) or 0) + int(row.get(field) or 0)
        if observed_keys[key] == 2:
            conflicts.append(
                build_conflict_record(
                    conflict_type=duplicate_conflict_type,
                    affected_ref=f"{record_type}:{key}",
                    source_node_ids=sorted(source_by_key[key]),
                    summary=f"{record_type} {key} was reported by multiple node summaries.",
                    severity="low",
                    recommended_review=True,
                )
            )
        confidence_values.setdefault(key, set()).add(f"{_confidence(row):.4f}")
        if len(confidence_values[key]) > 1:
            conflicts.append(
                build_conflict_record(
                    conflict_type="different_confidence_values",
                    affected_ref=f"{record_type}:{key}",
                    source_node_ids=merged[key]["source_node_ids"],
                    summary=f"{record_type} {key} has different confidence values: {', '.join(sorted(confidence_values[key]))}",
                    severity="low",
                    recommended_review=True,
                )
            )
        missing = _missing_optional_fields(row, optional_fields)
        if missing:
            conflicts.append(
                build_conflict_record(
                    conflict_type="missing_optional_fields",
                    affected_ref=f"{record_type}:{key}",
                    source_node_ids=merged[key]["source_node_ids"],
                    summary=f"{record_type} {key} is missing optional fields: {', '.join(missing)}",
                    severity="info",
                    recommended_review=True,
                )
            )
        for field, conflict_type in conflict_fields.items():
            value = row.get(field)
            if value in (None, ""):
                continue
            values = observed_values.setdefault((key, conflict_type), set())
            values.add(str(value))
            if len(values) > 1:
                conflicts.append(
                    build_conflict_record(
                        conflict_type=conflict_type,
                        affected_ref=f"{record_type}:{key}",
                        source_node_ids=merged[key]["source_node_ids"],
                        summary=f"{record_type} {key} has conflicting {field} values: {', '.join(sorted(values))}",
                        severity="medium",
                        recommended_review=True,
                    )
                )
    return sorted(merged.values(), key=lambda item: item["merge_key"]), _dedupe_conflicts(conflicts)


def _missing_optional_fields(row: dict[str, Any], fields: tuple[str, ...]) -> list[str]:
    missing: list[str] = []
    seen_alias_groups: set[frozenset[str]] = set()
    alias_groups = (
        frozenset({"service", "service_name"}),
        frozenset({"source_asset", "src", "source", "from"}),
        frozenset({"target_asset", "dst", "target", "to"}),
        frozenset({"relationship_type", "type"}),
    )
    for group in alias_groups:
        if not group.intersection(fields):
            continue
        seen_alias_groups.add(group)
        if not any(row.get(field) not in (None, "") for field in group):
            missing.append("/".join(sorted(group.intersection(fields))))
    for field in fields:
        if any(field in group for group in seen_alias_groups):
            continue
        if row.get(field) in (None, ""):
            missing.append(field)
    return sorted(set(missing))


def _chain(reports: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for report in reports:
        rows.extend(report.get(field) or [])
    return rows


def _source_nodes(row: dict[str, Any]) -> list[str]:
    nodes = row.get("source_node_ids")
    if isinstance(nodes, list):
        return [str(node) for node in nodes if node]
    node_id = row.get("node_id")
    return [str(node_id)] if node_id else []


def _source_refs(row: dict[str, Any]) -> list[str]:
    refs = row.get("source_refs")
    if isinstance(refs, list):
        return [str(ref) for ref in refs if ref]
    return []


def _first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _confidence(row: dict[str, Any]) -> float:
    try:
        value = float(row.get("confidence") or 0.0)
    except (TypeError, ValueError):
        value = 0.0
    return min(max(value, 0.0), 1.0)


def _dedupe_conflicts(conflicts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {conflict["conflict_id"]: conflict for conflict in conflicts}
    return sorted(by_id.values(), key=lambda item: item["conflict_id"])
