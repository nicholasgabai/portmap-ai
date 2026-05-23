from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.federation.signing import SIGNING_RECORD_VERSION, SIGNING_SAFETY_FLAGS
from core_engine.runtime.node_sync import build_cluster_runtime_state


CLUSTER_SYNC_RECORD_VERSION = 1


def build_merged_cluster_state(
    accepted_updates: Iterable[dict[str, Any]],
    *,
    expected_nodes: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    updates = sorted([dict(update) for update in accepted_updates], key=lambda item: str(item.get("update_id") or ""))
    runtime_rows = _latest_payloads(updates, scope="runtime-summary")
    health_rows = _latest_payloads(updates, scope="health-summary")
    topology_rows = _latest_payloads(updates, scope="topology-summary")
    review_rows = _latest_payloads(updates, scope="review-summary")
    export_rows = _latest_payloads(updates, scope="export-summary")
    visibility_rows = _latest_payloads(updates, scope="operator-visibility")
    service_rows = _latest_payloads(updates, scope="service-readiness")
    distributed_runtime = (
        build_cluster_runtime_state(runtime_rows, expected_nodes=expected_nodes, generated_at=timestamp)
        if runtime_rows
        else _empty_runtime_state(expected_nodes=expected_nodes, generated_at=timestamp)
    )
    summary = summarize_merged_cluster_state(
        runtime_state=distributed_runtime,
        health_rows=health_rows,
        topology_rows=topology_rows,
        review_rows=review_rows,
        export_rows=export_rows,
        visibility_rows=visibility_rows,
        service_rows=service_rows,
        updates=updates,
        generated_at=timestamp,
    )
    record = {
        "record_type": "live_merged_cluster_state",
        "record_version": CLUSTER_SYNC_RECORD_VERSION,
        "cluster_state_id": "",
        "generated_at": timestamp,
        "distributed_runtime_state": distributed_runtime,
        "health_summaries": health_rows,
        "topology_summaries": topology_rows,
        "review_summaries": review_rows,
        "export_summaries": export_rows,
        "operator_visibility_summaries": visibility_rows,
        "service_readiness_summaries": service_rows,
        "summary": summary,
        **SIGNING_SAFETY_FLAGS,
    }
    record["cluster_state_id"] = _stable_id("live-cluster-state", timestamp, summary)
    return record


def summarize_merged_cluster_state(
    *,
    runtime_state: dict[str, Any],
    health_rows: Iterable[dict[str, Any]] | None = None,
    topology_rows: Iterable[dict[str, Any]] | None = None,
    review_rows: Iterable[dict[str, Any]] | None = None,
    export_rows: Iterable[dict[str, Any]] | None = None,
    visibility_rows: Iterable[dict[str, Any]] | None = None,
    service_rows: Iterable[dict[str, Any]] | None = None,
    updates: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    update_rows = [dict(row) for row in updates or []]
    by_scope: dict[str, int] = {}
    for update in update_rows:
        scope = str(update.get("trust_scope_label") or "unknown")
        by_scope[scope] = by_scope.get(scope, 0) + 1
    runtime_summary = runtime_state.get("summary") if isinstance(runtime_state.get("summary"), dict) else {}
    source_nodes = sorted(
        set(
            str(update.get("source_node_id") or "")
            for update in update_rows
            if str(update.get("source_node_id") or "").strip()
        )
    )
    return {
        "generated_at": timestamp,
        "accepted_update_count": len(update_rows),
        "source_node_count": len(source_nodes),
        "source_node_ids": source_nodes,
        "runtime_node_count": int(runtime_summary.get("node_count") or 0),
        "runtime_conflict_count": int(runtime_summary.get("conflict_count") or 0),
        "health_summary_count": len(_rows(health_rows)),
        "topology_summary_count": len(_rows(topology_rows)),
        "review_summary_count": len(_rows(review_rows)),
        "export_summary_count": len(_rows(export_rows)),
        "operator_visibility_summary_count": len(_rows(visibility_rows)),
        "service_readiness_summary_count": len(_rows(service_rows)),
        "by_trust_scope": dict(sorted(by_scope.items())),
        "administrator_review_required": bool(runtime_summary.get("administrator_review_required")),
        **SIGNING_SAFETY_FLAGS,
    }


def build_cluster_sync_dashboard_status(
    *,
    sync_summary: dict[str, Any],
    merged_cluster_state: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    merged_summary = merged_cluster_state.get("summary") if isinstance(merged_cluster_state.get("summary"), dict) else {}
    status = str(sync_summary.get("status") or "unknown")
    return {
        "record_type": "live_cluster_sync_status",
        "panel": "live_cluster_synchronization",
        "status": status,
        "generated_at": timestamp,
        "metrics": {
            "accepted_update_count": int(sync_summary.get("accepted_update_count") or 0),
            "rejected_update_count": int(sync_summary.get("rejected_update_count") or 0),
            "stale_update_count": int(sync_summary.get("stale_update_count") or 0),
            "replayed_update_count": int(sync_summary.get("replayed_update_count") or 0),
            "source_node_count": int(merged_summary.get("source_node_count") or 0),
            "runtime_node_count": int(merged_summary.get("runtime_node_count") or 0),
            "conflict_count": int(sync_summary.get("conflict_count") or 0),
            "drift_count": int(sync_summary.get("drift_count") or 0),
        },
        "api": {
            "status": status,
            "sync_summary": dict(sync_summary),
            "cluster_summary": dict(merged_summary),
        },
        "recommended_review": bool(sync_summary.get("administrator_review_required") or merged_summary.get("administrator_review_required")),
        **SIGNING_SAFETY_FLAGS,
    }


def _latest_payloads(updates: list[dict[str, Any]], *, scope: str) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for update in sorted(updates, key=lambda item: (str(item.get("source_node_id") or ""), int(item.get("sequence") or 0), str(item.get("update_id") or ""))):
        if update.get("trust_scope_label") != scope:
            continue
        node_id = str(update.get("source_node_id") or "")
        payload = update.get("summary_payload") if isinstance(update.get("summary_payload"), dict) else {}
        if not node_id or not payload:
            continue
        latest[node_id] = dict(payload)
    return [latest[node_id] for node_id in sorted(latest)]


def _empty_runtime_state(*, expected_nodes: Iterable[str] | None, generated_at: str) -> dict[str, Any]:
    return build_cluster_runtime_state([], expected_nodes=expected_nodes, generated_at=generated_at)


def _rows(values: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(row) for row in values or [] if isinstance(row, dict)]


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
