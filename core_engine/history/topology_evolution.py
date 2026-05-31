from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.export.node_manifest import digest_payload
from core_engine.history.baseline_decay import BASELINE_DECAY_SAFETY_FLAGS
from core_engine.history.relationship_history import (
    RELATIONSHIP_HISTORY_SAFETY_FLAGS,
    build_relationship_history_records,
    deterministic_relationship_history_json,
    summarize_relationship_history,
)


TOPOLOGY_EVOLUTION_RECORD_VERSION = 1

TOPOLOGY_EVOLUTION_SAFETY_FLAGS = {
    **RELATIONSHIP_HISTORY_SAFETY_FLAGS,
    **BASELINE_DECAY_SAFETY_FLAGS,
    "topology_evolution_only": True,
    "metadata_only": True,
    "local_first": True,
    "bounded_retention": True,
    "advisory_only": True,
    "dry_run_safe": True,
    "payload_bytes_stored": 0,
    "credentials_stored": False,
    "external_services_used": False,
    "automatic_enforcement": False,
    "firewall_changes": False,
}


def build_topology_evolution_report(
    *,
    topology_records: Iterable[dict[str, Any]] | None = None,
    previous_relationships: Iterable[dict[str, Any]] | None = None,
    historical_snapshots: Iterable[dict[str, Any]] | None = None,
    baseline_decay_report: dict[str, Any] | None = None,
    generated_at: str | None = None,
    max_relationships: int = 500,
    stable_recurrence_threshold: int = 3,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    relationships = build_relationship_history_records(
        topology_records or [],
        previous_relationships=previous_relationships,
        generated_at=timestamp,
        max_relationships=max_relationships,
        stable_recurrence_threshold=stable_recurrence_threshold,
    )
    relationship_summary = summarize_relationship_history(relationships, generated_at=timestamp)
    drift = summarize_topology_drift(relationships=relationships, previous_relationships=previous_relationships, generated_at=timestamp)
    paths = build_recurring_communication_path_summaries(relationships, generated_at=timestamp)
    maturity = build_topology_maturity_summary(relationships, baseline_decay_report=baseline_decay_report, generated_at=timestamp)
    export = build_topology_evolution_export_summary(
        relationship_summary=relationship_summary,
        drift_summary=drift,
        communication_paths=paths,
        generated_at=timestamp,
    )
    dashboard = build_topology_evolution_dashboard_record(
        relationship_summary=relationship_summary,
        drift_summary=drift,
        maturity_summary=maturity,
        communication_paths=paths,
        generated_at=timestamp,
    )
    api = build_topology_evolution_api_response(
        relationships=relationships,
        relationship_summary=relationship_summary,
        drift_summary=drift,
        communication_paths=paths,
        maturity_summary=maturity,
        dashboard=dashboard,
        export=export,
        historical_snapshots=historical_snapshots,
        generated_at=timestamp,
    )
    return {
        "record_type": "long_term_topology_evolution_report",
        "record_version": TOPOLOGY_EVOLUTION_RECORD_VERSION,
        "report_id": "topology-evolution-" + _digest({"generated_at": timestamp, "relationships": [row.get("relationship_id") for row in relationships]})[:16],
        "generated_at": timestamp,
        "relationships": relationships,
        "relationship_summary": relationship_summary,
        "drift_summary": drift,
        "communication_paths": paths,
        "maturity_summary": maturity,
        "historical_snapshot_context": _snapshot_context(historical_snapshots),
        "dashboard_status": dashboard,
        "api_status": api,
        "export_summary": export,
        **TOPOLOGY_EVOLUTION_SAFETY_FLAGS,
    }


def summarize_topology_drift(
    *,
    relationships: Iterable[dict[str, Any]],
    previous_relationships: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    current_rows = [row for row in _rows(relationships) if row.get("classification") != "malformed"]
    previous_rows = _rows(previous_relationships)
    current_keys = {str(row.get("relationship_key") or "") for row in current_rows if row.get("relationship_key")}
    previous_keys = {str(row.get("relationship_key") or "") for row in previous_rows if row.get("relationship_key")}
    dormant = {str(row.get("relationship_key") or "") for row in current_rows if row.get("dormant_relationship")}
    returned = {str(row.get("relationship_key") or "") for row in current_rows if row.get("dormant_returned")}
    added = sorted(current_keys - previous_keys)
    removed = sorted((previous_keys - current_keys) | dormant)
    status = "review_required" if added or removed or returned else "stable"
    return {
        "record_type": "long_term_topology_drift_summary",
        "record_version": TOPOLOGY_EVOLUTION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": status,
        "added_relationship_count": len(added),
        "removed_relationship_count": len(removed),
        "dormant_return_count": len(returned),
        "stable_relationship_count": sum(1 for row in current_rows if row.get("stable_relationship")),
        "transient_relationship_count": sum(1 for row in current_rows if row.get("transient_relationship")),
        "added_relationship_keys": added,
        "removed_relationship_keys": removed,
        "dormant_return_relationship_keys": sorted(returned),
        "operator_summary": "Topology relationships changed over historical metadata." if status == "review_required" else "Topology relationships are stable against previous metadata.",
        **TOPOLOGY_EVOLUTION_SAFETY_FLAGS,
    }


def build_recurring_communication_path_summaries(
    relationships: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    rows = [row for row in _rows(relationships) if row.get("classification") != "malformed"]
    paths = []
    for row in rows:
        if int(row.get("recurrence_count") or 0) <= 1 and not row.get("stable_relationship"):
            continue
        path = {
            "record_type": "recurring_communication_path_summary",
            "record_version": TOPOLOGY_EVOLUTION_RECORD_VERSION,
            "generated_at": generated_at or _now(),
            "relationship_key": str(row.get("relationship_key") or ""),
            "source_asset": str(row.get("source_asset") or ""),
            "target_asset": str(row.get("target_asset") or ""),
            "protocol": str(row.get("protocol") or "unknown"),
            "recurrence_count": int(row.get("recurrence_count") or 0),
            "observation_count": int(row.get("observation_count") or 0),
            "confidence": float(row.get("confidence") or 0.0),
            "stable_relationship": bool(row.get("stable_relationship")),
            "dormant_returned": bool(row.get("dormant_returned")),
            **TOPOLOGY_EVOLUTION_SAFETY_FLAGS,
        }
        path["path_id"] = "communication-path-" + _digest({"relationship_key": path["relationship_key"]})[:16]
        paths.append(path)
    return sorted(paths, key=lambda item: (str(item.get("source_asset") or ""), str(item.get("target_asset") or ""), str(item.get("protocol") or "")))


def build_topology_maturity_summary(
    relationships: Iterable[dict[str, Any]],
    *,
    baseline_decay_report: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [row for row in _rows(relationships) if row.get("classification") != "malformed"]
    decay_summary = baseline_decay_report.get("summary") if isinstance((baseline_decay_report or {}).get("summary"), dict) else {}
    average = round(sum(float(row.get("topology_maturity_score") or 0.0) for row in rows) / len(rows), 3) if rows else 0.0
    return {
        "record_type": "topology_maturity_summary",
        "record_version": TOPOLOGY_EVOLUTION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "relationship_count": len(rows),
        "average_topology_maturity_score": average,
        "mature_relationship_count": sum(1 for row in rows if float(row.get("topology_maturity_score") or 0.0) >= 0.75),
        "baseline_decay_context_state": "provided" if baseline_decay_report else "not_provided",
        "baseline_decay_stale_count": int(decay_summary.get("stale_count") or 0),
        "baseline_decay_dormant_count": int(decay_summary.get("dormant_count") or 0),
        **TOPOLOGY_EVOLUTION_SAFETY_FLAGS,
    }


def build_topology_evolution_dashboard_record(
    *,
    relationship_summary: dict[str, Any],
    drift_summary: dict[str, Any],
    maturity_summary: dict[str, Any],
    communication_paths: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "topology_evolution_dashboard",
        "record_version": TOPOLOGY_EVOLUTION_RECORD_VERSION,
        "panel": "long_term_topology_evolution",
        "generated_at": generated_at or _now(),
        "status": str(drift_summary.get("status") or "unknown"),
        "metrics": {
            "relationship_count": int(relationship_summary.get("relationship_count") or 0),
            "stable_relationship_count": int(relationship_summary.get("stable_relationship_count") or 0),
            "transient_relationship_count": int(relationship_summary.get("transient_relationship_count") or 0),
            "dormant_return_count": int(relationship_summary.get("dormant_return_count") or 0),
            "added_relationship_count": int(drift_summary.get("added_relationship_count") or 0),
            "removed_relationship_count": int(drift_summary.get("removed_relationship_count") or 0),
            "average_maturity_score": float(maturity_summary.get("average_topology_maturity_score") or 0.0),
            "recurring_path_count": len(_rows(communication_paths)),
        },
        "recommended_review": str(drift_summary.get("status") or "") == "review_required",
        **TOPOLOGY_EVOLUTION_SAFETY_FLAGS,
    }


def build_topology_evolution_export_summary(
    *,
    relationship_summary: dict[str, Any],
    drift_summary: dict[str, Any],
    communication_paths: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    payload = {
        "record_type": "topology_evolution_export_summary",
        "record_version": TOPOLOGY_EVOLUTION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "record_counts": {
            "relationships": int(relationship_summary.get("relationship_count") or 0),
            "stable": int(relationship_summary.get("stable_relationship_count") or 0),
            "transient": int(relationship_summary.get("transient_relationship_count") or 0),
            "dormant": int(relationship_summary.get("dormant_relationship_count") or 0),
            "dormant_returns": int(relationship_summary.get("dormant_return_count") or 0),
            "communication_paths": len(_rows(communication_paths)),
        },
        "drift_status": str(drift_summary.get("status") or "unknown"),
        "digest": "",
        **TOPOLOGY_EVOLUTION_SAFETY_FLAGS,
    }
    payload["digest"] = digest_payload({"record_counts": payload["record_counts"], "drift_status": payload["drift_status"]})
    return payload


def build_topology_evolution_api_response(
    *,
    relationships: Iterable[dict[str, Any]],
    relationship_summary: dict[str, Any],
    drift_summary: dict[str, Any],
    communication_paths: Iterable[dict[str, Any]],
    maturity_summary: dict[str, Any],
    dashboard: dict[str, Any],
    export: dict[str, Any],
    historical_snapshots: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "topology_evolution_api",
        "record_version": TOPOLOGY_EVOLUTION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "relationships": _rows(relationships),
        "relationship_summary": dict(relationship_summary),
        "drift_summary": dict(drift_summary),
        "communication_paths": _rows(communication_paths),
        "maturity_summary": dict(maturity_summary),
        "historical_snapshot_context": _snapshot_context(historical_snapshots),
        "dashboard": dict(dashboard),
        "export_summary": dict(export),
        **TOPOLOGY_EVOLUTION_SAFETY_FLAGS,
    }


def deterministic_topology_evolution_json(record: dict[str, Any]) -> str:
    return deterministic_relationship_history_json(record)


def _snapshot_context(snapshots: Iterable[dict[str, Any]] | None) -> dict[str, Any]:
    rows = _rows(snapshots)
    return {
        "snapshot_count": len(rows),
        "snapshot_ids": [str(row.get("snapshot_id") or "") for row in rows],
        "snapshot_digests": [str(row.get("snapshot_digest") or "") for row in rows if row.get("snapshot_digest")],
    }


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
