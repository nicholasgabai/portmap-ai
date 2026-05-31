from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.history.operator_views import (
    LONG_TERM_OPERATOR_VIEW_SAFETY_FLAGS,
    build_long_term_intelligence_api_response,
    build_long_term_intelligence_dashboard_record,
    build_long_term_intelligence_export_summary,
    build_long_term_privacy_safety_summary,
)
from core_engine.history.resource_retention import RESOURCE_RETENTION_SAFETY_FLAGS
from core_engine.history.snapshot_store import summarize_snapshot_store


LONG_TERM_INTELLIGENCE_RECORD_VERSION = 1

LONG_TERM_INTELLIGENCE_COMPONENTS = (
    "historical_snapshots",
    "baseline_decay",
    "topology_evolution",
    "historical_replay",
    "resource_retention",
)

LONG_TERM_INTELLIGENCE_SAFETY_FLAGS = {
    **RESOURCE_RETENTION_SAFETY_FLAGS,
    **LONG_TERM_OPERATOR_VIEW_SAFETY_FLAGS,
    "long_term_intelligence_summary": True,
    "metadata_only": True,
    "local_first": True,
    "bounded_retention": True,
    "advisory_only": True,
    "dry_run_safe": True,
    "dashboard_safe": True,
    "export_ready": True,
    "automatic_deletion": False,
    "delete_performed": False,
    "packet_payloads_stored": False,
    "credentials_stored": False,
    "raw_browsing_history_stored": False,
    "external_services_used": False,
    "automatic_enforcement": False,
    "firewall_changes": False,
}


def build_long_term_intelligence_summary(
    *,
    historical_snapshots: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    snapshot_store_summary: dict[str, Any] | None = None,
    baseline_decay_report: dict[str, Any] | None = None,
    topology_evolution_report: dict[str, Any] | None = None,
    historical_replay_report: dict[str, Any] | None = None,
    resource_retention_report: dict[str, Any] | None = None,
    behavioral_intelligence_summary: dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rollups = {
        "historical_snapshots": build_historical_snapshot_rollup(
            historical_snapshots=historical_snapshots,
            snapshot_store_summary=snapshot_store_summary,
            generated_at=timestamp,
        ),
        "baseline_decay": build_baseline_decay_rollup(baseline_decay_report, generated_at=timestamp),
        "topology_evolution": build_topology_evolution_rollup(topology_evolution_report, generated_at=timestamp),
        "historical_replay": build_historical_replay_rollup(historical_replay_report, generated_at=timestamp),
        "resource_retention": build_resource_retention_rollup(resource_retention_report, generated_at=timestamp),
    }
    state_summary = build_long_term_state_summary(
        rollups=rollups,
        behavioral_intelligence_summary=behavioral_intelligence_summary,
        runtime_health=runtime_health,
        generated_at=timestamp,
    )
    recommendations = build_long_term_recommendation_records(
        rollups=rollups,
        state_summary=state_summary,
        generated_at=timestamp,
    )
    privacy = build_long_term_privacy_safety_summary(generated_at=timestamp)
    export = build_long_term_intelligence_export_summary(
        rollups=rollups,
        state_summary=state_summary,
        recommendations=recommendations,
        generated_at=timestamp,
    )
    dashboard = build_long_term_intelligence_dashboard_record(
        rollups=rollups,
        state_summary=state_summary,
        recommendations=recommendations,
        generated_at=timestamp,
    )
    api = build_long_term_intelligence_api_response(
        rollups=rollups,
        state_summary=state_summary,
        recommendations=recommendations,
        privacy_safety_summary=privacy,
        dashboard=dashboard,
        export=export,
        generated_at=timestamp,
    )
    return {
        "record_type": "long_term_intelligence_summary",
        "record_version": LONG_TERM_INTELLIGENCE_RECORD_VERSION,
        "summary_id": "long-term-intelligence-" + _digest({"generated_at": timestamp, "state": state_summary, "rollups": rollups})[:16],
        "generated_at": timestamp,
        "status": str(state_summary.get("overall_state") or "unknown"),
        "component_rollups": rollups,
        "state_summary": state_summary,
        "recommendations": recommendations,
        "privacy_safety_summary": privacy,
        "dashboard_status": dashboard,
        "api_status": api,
        "export_summary": export,
        **LONG_TERM_INTELLIGENCE_SAFETY_FLAGS,
    }


def build_historical_snapshot_rollup(
    *,
    historical_snapshots: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    snapshot_store_summary: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    summary = _snapshot_summary(historical_snapshots, snapshot_store_summary=snapshot_store_summary, generated_at=generated_at)
    count = int(summary.get("snapshot_count") or 0)
    malformed = int(summary.get("malformed_snapshot_count") or summary.get("malformed_count") or 0)
    state = _availability_state(available=bool(historical_snapshots or snapshot_store_summary), count=count, degraded=malformed > 0)
    return _rollup(
        component="historical_snapshots",
        source_report_type=str(summary.get("record_type") or "historical_snapshot_store_summary"),
        state=state,
        record_count=count,
        recommended_review_count=malformed,
        metrics={
            "snapshot_count": count,
            "source_label_count": len(summary.get("source_labels") or []),
            "malformed_snapshot_count": malformed,
        },
        generated_at=generated_at,
    )


def build_baseline_decay_rollup(report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    summary = _summary(report)
    count = int(summary.get("record_count") or 0)
    stale = int(summary.get("stale_count") or 0)
    dormant = int(summary.get("dormant_count") or 0)
    malformed = int(summary.get("malformed_record_count") or 0)
    state = _availability_state(available=bool(report), count=count, degraded=bool(stale or dormant or malformed))
    return _rollup(
        component="baseline_decay",
        source_report_type=_report_type(report),
        state=state,
        record_count=count,
        recommended_review_count=stale + dormant + malformed,
        metrics={
            "record_count": count,
            "inactive_count": int(summary.get("inactive_count") or 0),
            "stale_count": stale,
            "dormant_count": dormant,
            "mature_count": int(summary.get("mature_count") or 0),
            "malformed_record_count": malformed,
        },
        generated_at=generated_at,
    )


def build_topology_evolution_rollup(report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    relationship = report.get("relationship_summary") if isinstance((report or {}).get("relationship_summary"), dict) else {}
    drift = report.get("drift_summary") if isinstance((report or {}).get("drift_summary"), dict) else {}
    count = int(relationship.get("relationship_count") or 0)
    added = int(drift.get("added_relationship_count") or 0)
    removed = int(drift.get("removed_relationship_count") or 0)
    dormant = int(drift.get("dormant_return_count") or relationship.get("dormant_return_count") or 0)
    degraded = str(drift.get("status") or "") == "review_required" or bool(added or removed or dormant)
    state = _availability_state(available=bool(report), count=count, degraded=degraded)
    return _rollup(
        component="topology_evolution",
        source_report_type=_report_type(report),
        state=state,
        record_count=count,
        recommended_review_count=added + removed + dormant,
        metrics={
            "relationship_count": count,
            "stable_relationship_count": int(relationship.get("stable_relationship_count") or 0),
            "transient_relationship_count": int(relationship.get("transient_relationship_count") or 0),
            "added_relationship_count": added,
            "removed_relationship_count": removed,
            "dormant_return_count": dormant,
        },
        generated_at=generated_at,
    )


def build_historical_replay_rollup(report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    sequence = report.get("snapshot_sequence") if isinstance((report or {}).get("snapshot_sequence"), dict) else {}
    events = report.get("timeline_events") if isinstance((report or {}).get("timeline_events"), list) else []
    malformed = int(sequence.get("malformed_snapshot_count") or len(report.get("malformed_snapshots") or []) if isinstance(report, dict) else 0)
    truncated = int((report or {}).get("truncated_event_count") or 0) if isinstance(report, dict) else 0
    count = len(events)
    state = _availability_state(available=bool(report), count=count, degraded=bool(malformed or truncated))
    return _rollup(
        component="historical_replay",
        source_report_type=_report_type(report),
        state=state,
        record_count=count,
        recommended_review_count=malformed + truncated,
        metrics={
            "timeline_event_count": count,
            "snapshot_count": int(sequence.get("snapshot_count") or 0),
            "malformed_snapshot_count": malformed,
            "truncated_event_count": truncated,
        },
        generated_at=generated_at,
    )


def build_resource_retention_rollup(report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    summary = _summary(report)
    count = int(summary.get("recommendation_count") or len((report or {}).get("recommendations") or []) if isinstance(report, dict) else 0)
    over_limit = int(summary.get("over_limit_recommendation_count") or 0)
    status = str(summary.get("status") or "unavailable")
    state = "unavailable" if not report else "degraded" if status in {"degraded", "unavailable"} or over_limit else "supported"
    return _rollup(
        component="resource_retention",
        source_report_type=_report_type(report),
        state=state,
        record_count=count,
        recommended_review_count=over_limit,
        metrics={
            "recommendation_count": count,
            "over_limit_recommendation_count": over_limit,
            "resource_factor": float(summary.get("resource_factor") or 0.0),
            "storage_status": str(summary.get("storage_status") or "unknown"),
            "memory_status": str(summary.get("memory_status") or "unknown"),
        },
        generated_at=generated_at,
    )


def build_long_term_state_summary(
    *,
    rollups: dict[str, dict[str, Any]],
    behavioral_intelligence_summary: dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    states = {name: str((rollups.get(name) or {}).get("state") or "unavailable") for name in LONG_TERM_INTELLIGENCE_COMPONENTS}
    supported = [name for name, state in states.items() if state == "supported"]
    degraded = [name for name, state in states.items() if state == "degraded"]
    unavailable = [name for name, state in states.items() if state == "unavailable"]
    if not supported and not degraded:
        overall = "unavailable"
    elif degraded or unavailable:
        overall = "degraded"
    else:
        overall = "supported"
    return {
        "record_type": "long_term_intelligence_state_summary",
        "record_version": LONG_TERM_INTELLIGENCE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "overall_state": overall,
        "component_states": states,
        "supported_component_count": len(supported),
        "degraded_component_count": len(degraded),
        "unavailable_component_count": len(unavailable),
        "recommended_review_count": sum(int((rollups.get(name) or {}).get("recommended_review_count") or 0) for name in LONG_TERM_INTELLIGENCE_COMPONENTS),
        "total_record_count": sum(int((rollups.get(name) or {}).get("record_count") or 0) for name in LONG_TERM_INTELLIGENCE_COMPONENTS),
        "behavioral_intelligence_state": str((behavioral_intelligence_summary or {}).get("status") or (behavioral_intelligence_summary or {}).get("state") or "not_provided"),
        "runtime_health_state": str((runtime_health or {}).get("status") or (runtime_health or {}).get("overall_status") or "not_provided"),
        "advisory_only": True,
        "enforcement_allowed": False,
        **LONG_TERM_INTELLIGENCE_SAFETY_FLAGS,
    }


def build_long_term_recommendation_records(
    *,
    rollups: dict[str, dict[str, Any]],
    state_summary: dict[str, Any],
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    recommendations = []
    for name in LONG_TERM_INTELLIGENCE_COMPONENTS:
        rollup = rollups.get(name) or {}
        if str(rollup.get("state")) == "unavailable":
            recommendations.append(_recommendation(name, "provide_historical_summary", "low", "Add sanitized local historical summary input for this component.", timestamp))
        elif str(rollup.get("state")) == "degraded" or int(rollup.get("recommended_review_count") or 0) > 0:
            recommendations.append(_recommendation(name, "operator_review_recommended", "medium", "Review degraded historical metadata before relying on long-term conclusions.", timestamp))
    if str(state_summary.get("overall_state")) == "supported" and not recommendations:
        recommendations.append(_recommendation("long_term_intelligence", "continue_monitoring", "info", "Continue retaining bounded metadata summaries for future historical review.", timestamp))
    return recommendations


def deterministic_long_term_intelligence_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _rollup(
    *,
    component: str,
    source_report_type: str,
    state: str,
    record_count: int,
    recommended_review_count: int,
    metrics: dict[str, Any],
    generated_at: str | None,
) -> dict[str, Any]:
    return {
        "record_type": "long_term_intelligence_component_rollup",
        "record_version": LONG_TERM_INTELLIGENCE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "component": component,
        "source_report_type": source_report_type,
        "state": state,
        "record_count": int(record_count),
        "recommended_review_count": int(recommended_review_count),
        "metrics": dict(sorted(metrics.items())),
        **LONG_TERM_INTELLIGENCE_SAFETY_FLAGS,
    }


def _snapshot_summary(
    snapshots: Iterable[dict[str, Any]] | dict[str, Any] | None,
    *,
    snapshot_store_summary: dict[str, Any] | None,
    generated_at: str | None,
) -> dict[str, Any]:
    if isinstance(snapshot_store_summary, dict):
        return dict(snapshot_store_summary)
    if snapshots is None:
        return {}
    if isinstance(snapshots, dict):
        if isinstance(snapshots.get("summary"), dict):
            return dict(snapshots["summary"])
        if isinstance(snapshots.get("snapshots"), list):
            return summarize_snapshot_store(snapshots["snapshots"], generated_at=generated_at)
        if snapshots.get("record_type") == "historical_snapshot":
            return summarize_snapshot_store([snapshots], generated_at=generated_at)
        return {"record_type": "historical_snapshot_store_summary", "snapshot_count": 0, "malformed_snapshot_count": 1}
    return summarize_snapshot_store([row for row in snapshots if isinstance(row, dict)], generated_at=generated_at)


def _availability_state(*, available: bool, count: int, degraded: bool) -> str:
    if not available:
        return "unavailable"
    if degraded or count == 0:
        return "degraded"
    return "supported"


def _summary(report: dict[str, Any] | None) -> dict[str, Any]:
    return report.get("summary") if isinstance((report or {}).get("summary"), dict) else {}


def _report_type(report: dict[str, Any] | None) -> str:
    return str((report or {}).get("record_type") or "unavailable")


def _recommendation(component: str, action: str, severity: str, summary: str, generated_at: str) -> dict[str, Any]:
    row = {
        "record_type": "long_term_intelligence_recommendation",
        "record_version": LONG_TERM_INTELLIGENCE_RECORD_VERSION,
        "generated_at": generated_at,
        "component": component,
        "action": action,
        "severity": severity,
        "summary": summary,
        "advisory_only": True,
        "enforcement_allowed": False,
        **LONG_TERM_INTELLIGENCE_SAFETY_FLAGS,
    }
    row["recommendation_id"] = "long-term-intelligence-recommendation-" + _digest({"component": component, "action": action, "severity": severity})[:16]
    return row


def _digest(payload: Any) -> str:
    return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
