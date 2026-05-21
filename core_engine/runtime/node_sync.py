from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.nodes.registry import NodeRegistry
from core_engine.runtime.distributed_state import (
    SAFETY_FLAGS,
    normalize_node_runtime_state,
    summarize_role_counts,
)


CONFLICT_SEVERITY = {
    "duplicate_node": "low",
    "role_conflict": "high",
    "label_conflict": "medium",
    "profile_conflict": "medium",
    "health_conflict": "medium",
    "missing_node": "high",
    "stale_node": "medium",
}


def build_cluster_runtime_state(
    reports: Iterable[dict[str, Any]] | NodeRegistry,
    *,
    expected_nodes: Iterable[str] | None = None,
    generated_at: str | None = None,
    stale_after_seconds: float | None = None,
    source_ref: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    normalized = normalize_node_runtime_states(
        reports,
        generated_at=timestamp,
        stale_after_seconds=stale_after_seconds,
        source_ref=source_ref,
    )
    merged = merge_node_runtime_states(normalized, generated_at=timestamp)
    missing = detect_missing_node_states(merged["nodes"], expected_nodes=expected_nodes, generated_at=timestamp)
    stale = detect_stale_node_states(merged["nodes"], generated_at=timestamp)
    conflicts = [*merged["conflicts"], *missing, *stale]
    summary = summarize_cluster_runtime_state(merged["nodes"], conflicts=conflicts, generated_at=timestamp)
    return {
        "record_type": "distributed_cluster_runtime_state",
        "cluster_state_id": _stable_id("cluster-state", timestamp, summary, conflicts),
        "generated_at": timestamp,
        "nodes": merged["nodes"],
        "conflicts": conflicts,
        "summary": summary,
        **SAFETY_FLAGS,
    }


def normalize_node_runtime_states(
    reports: Iterable[dict[str, Any]] | NodeRegistry,
    *,
    generated_at: str | None = None,
    stale_after_seconds: float | None = None,
    source_ref: str | None = None,
) -> list[dict[str, Any]]:
    if isinstance(reports, NodeRegistry):
        rows = reports.list_nodes()
    else:
        rows = list(reports)
    states = [
        normalize_node_runtime_state(
            report,
            generated_at=generated_at,
            stale_after_seconds=stale_after_seconds,
            source_ref=source_ref,
        )
        for report in rows
    ]
    return sorted(states, key=lambda item: (str(item.get("node_id") or ""), str(item.get("observed_at") or "")))


def merge_node_runtime_states(
    states: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for state in states:
        node_id = str(state.get("node_id") or "")
        if not node_id:
            continue
        grouped.setdefault(node_id, []).append(dict(state))

    merged: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for node_id in sorted(grouped):
        rows = sorted(grouped[node_id], key=lambda item: (str(item.get("observed_at") or ""), str(item.get("state_id") or "")))
        chosen = dict(rows[-1])
        source_refs = set(chosen.get("source_refs") or [])
        for row in rows[:-1]:
            source_refs.update(row.get("source_refs") or [])
        chosen["source_refs"] = sorted(str(item) for item in source_refs)
        if len(rows) > 1:
            conflicts.extend(_duplicate_conflicts(node_id, rows, generated_at=timestamp))
        merged.append(chosen)
    return {
        "nodes": merged,
        "conflicts": sorted(conflicts, key=lambda item: (item["conflict_type"], item["affected_ref"], item["conflict_id"])),
        **SAFETY_FLAGS,
    }


def detect_missing_node_states(
    states: Iterable[dict[str, Any]],
    *,
    expected_nodes: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    present = {str(state.get("node_id")) for state in states if state.get("node_id")}
    conflicts: list[dict[str, Any]] = []
    for node_id in sorted(str(item) for item in expected_nodes or [] if str(item).strip()):
        if node_id not in present:
            conflicts.append(
                build_node_state_conflict(
                    "missing_node",
                    affected_ref=f"node:{node_id}",
                    source_node_ids=[node_id],
                    summary=f"Expected trusted node {node_id} was not present in distributed runtime state input.",
                    generated_at=generated_at,
                )
            )
    return conflicts


def detect_stale_node_states(
    states: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    for state in states:
        if state.get("sync_status") == "stale":
            node_id = str(state.get("node_id") or "unknown")
            conflicts.append(
                build_node_state_conflict(
                    "stale_node",
                    affected_ref=f"node:{node_id}",
                    source_node_ids=[node_id],
                    source_refs=list(state.get("source_refs") or []),
                    summary=f"Trusted node {node_id} has stale runtime state.",
                    generated_at=generated_at,
                )
            )
    return conflicts


def summarize_cluster_runtime_state(
    states: Iterable[dict[str, Any]],
    *,
    conflicts: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = sorted([dict(state) for state in states], key=lambda item: str(item.get("node_id") or ""))
    conflict_rows = [dict(conflict) for conflict in conflicts or []]
    role_counts = summarize_role_counts(rows)
    by_conflict_type: dict[str, int] = {}
    for conflict in conflict_rows:
        conflict_type = str(conflict.get("conflict_type") or "unknown")
        by_conflict_type[conflict_type] = by_conflict_type.get(conflict_type, 0) + 1
    current_count = sum(1 for row in rows if row.get("sync_status") == "current")
    stale_count = sum(1 for row in rows if row.get("sync_status") == "stale")
    missing_count = sum(1 for row in rows if row.get("sync_status") == "missing") + by_conflict_type.get("missing_node", 0)
    return {
        "generated_at": generated_at or _now(),
        "node_count": len(rows),
        "current_node_count": current_count,
        "stale_node_count": stale_count,
        "missing_node_count": missing_count,
        "conflict_count": len(conflict_rows),
        "by_conflict_type": dict(sorted(by_conflict_type.items())),
        "roles": role_counts,
        "administrator_review_required": bool(conflict_rows),
        **SAFETY_FLAGS,
    }


def build_node_state_conflict(
    conflict_type: str,
    *,
    affected_ref: str,
    source_node_ids: list[str] | None = None,
    source_refs: list[str] | None = None,
    summary: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    severity = CONFLICT_SEVERITY.get(conflict_type, "medium")
    payload = {
        "conflict_type": conflict_type,
        "affected_ref": affected_ref,
        "source_node_ids": sorted(set(str(item) for item in source_node_ids or [] if str(item).strip())),
        "source_refs": sorted(set(str(item) for item in source_refs or [] if str(item).strip())),
        "summary": summary,
        "severity": severity,
        "recommended_review": True,
        "detected_at": generated_at or _now(),
        **SAFETY_FLAGS,
    }
    payload["conflict_id"] = _stable_id("node-state-conflict", conflict_type, affected_ref, payload["source_node_ids"], summary)
    return payload


def _duplicate_conflicts(node_id: str, rows: list[dict[str, Any]], *, generated_at: str | None) -> list[dict[str, Any]]:
    conflicts = [
        build_node_state_conflict(
            "duplicate_node",
            affected_ref=f"node:{node_id}",
            source_node_ids=[node_id],
            source_refs=_all_source_refs(rows),
            summary=f"Multiple runtime state records were provided for trusted node {node_id}; latest observed record was selected.",
            generated_at=generated_at,
        )
    ]
    role_values = sorted({str(row.get("role") or "") for row in rows if row.get("role")})
    if len(role_values) > 1:
        conflicts.append(
            build_node_state_conflict(
                "role_conflict",
                affected_ref=f"node:{node_id}",
                source_node_ids=[node_id],
                source_refs=_all_source_refs(rows),
                summary=f"Trusted node {node_id} has conflicting role values: {', '.join(role_values)}.",
                generated_at=generated_at,
            )
        )
    label_values = sorted({str(row.get("node_label") or "") for row in rows if row.get("node_label")})
    if len(label_values) > 1:
        conflicts.append(
            build_node_state_conflict(
                "label_conflict",
                affected_ref=f"node:{node_id}",
                source_node_ids=[node_id],
                source_refs=_all_source_refs(rows),
                summary=f"Trusted node {node_id} has conflicting labels.",
                generated_at=generated_at,
            )
        )
    profile_values = sorted(
        {
            str((row.get("profile_summary") or {}).get("profile_id") or "")
            for row in rows
            if isinstance(row.get("profile_summary"), dict) and (row.get("profile_summary") or {}).get("profile_id")
        }
    )
    if len(profile_values) > 1:
        conflicts.append(
            build_node_state_conflict(
                "profile_conflict",
                affected_ref=f"node:{node_id}",
                source_node_ids=[node_id],
                source_refs=_all_source_refs(rows),
                summary=f"Trusted node {node_id} has conflicting runtime profile references.",
                generated_at=generated_at,
            )
        )
    health_values = sorted(
        {
            str((row.get("health_summary") or {}).get("status") or "")
            for row in rows
            if isinstance(row.get("health_summary"), dict) and (row.get("health_summary") or {}).get("status")
        }
    )
    if len(health_values) > 1:
        conflicts.append(
            build_node_state_conflict(
                "health_conflict",
                affected_ref=f"node:{node_id}",
                source_node_ids=[node_id],
                source_refs=_all_source_refs(rows),
                summary=f"Trusted node {node_id} has conflicting runtime health status values.",
                generated_at=generated_at,
            )
        )
    return conflicts


def _all_source_refs(rows: list[dict[str, Any]]) -> list[str]:
    refs: set[str] = set()
    for row in rows:
        refs.update(str(item) for item in row.get("source_refs") or [] if str(item).strip())
    return sorted(refs)


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
