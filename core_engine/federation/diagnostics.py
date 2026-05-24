from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.federation.health import build_federation_health_event, build_federation_health_summary
from core_engine.federation.signing import SIGNING_SAFETY_FLAGS


FEDERATION_DIAGNOSTICS_RECORD_VERSION = 1


def build_federation_diagnostics(
    *,
    trust_profile: dict[str, Any] | None = None,
    transport_sessions: list[dict[str, Any]] | None = None,
    signed_exchanges: list[dict[str, Any]] | dict[str, Any] | None = None,
    sync_result: dict[str, Any] | None = None,
    event_batch: dict[str, Any] | None = None,
    cluster_health: dict[str, Any] | None = None,
    distributed_state: dict[str, Any] | None = None,
    thresholds: dict[str, int] | None = None,
    edge_device: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    health = build_federation_health_summary(
        trust_profile=trust_profile,
        transport_sessions=transport_sessions,
        signed_exchanges=signed_exchanges,
        sync_result=sync_result,
        event_batch=event_batch,
        cluster_health=cluster_health,
        distributed_state=distributed_state,
        thresholds=thresholds,
        edge_device=edge_device,
        generated_at=timestamp,
    )
    recommendations = build_federation_recommendations(health, generated_at=timestamp)
    dashboard = build_federation_dashboard_health_record(health, recommendations=recommendations, generated_at=timestamp)
    event = build_federation_health_event(health, generated_at=timestamp)
    api = build_federation_diagnostics_api(health=health, recommendations=recommendations, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "federation_diagnostics",
        "record_version": FEDERATION_DIAGNOSTICS_RECORD_VERSION,
        "diagnostics_id": _stable_id("federation-diagnostics", timestamp, health.get("readiness"), health.get("summary")),
        "generated_at": timestamp,
        "status": health["status"],
        "health": health,
        "recommendations": recommendations,
        "dashboard_status": dashboard,
        "api_status": api,
        "health_event": event,
        **SIGNING_SAFETY_FLAGS,
    }


def build_federation_recommendations(health: dict[str, Any], *, generated_at: str | None = None) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    recommendations: list[dict[str, Any]] = []
    for check in health.get("checks") or []:
        status = str(check.get("status") or "unknown")
        severity = str(check.get("severity") or "info")
        if status == "ok" and severity == "info":
            continue
        name = str(check.get("name") or "federation_check")
        recommendations.append(
            {
                "record_type": "federation_diagnostic_recommendation",
                "recommendation_id": _stable_id("federation-rec", name, status, severity, check.get("message")),
                "check_name": name,
                "severity": severity,
                "status": status,
                "summary": _recommendation_summary(name, check),
                "operator_action": _operator_action(name),
                "generated_at": timestamp,
                "automatic_changes": False,
                "remote_command_execution": False,
                **SIGNING_SAFETY_FLAGS,
            }
        )
    return sorted(recommendations, key=lambda item: item["recommendation_id"])


def build_federation_dashboard_health_record(
    health: dict[str, Any],
    *,
    recommendations: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    summary = health.get("summary") if isinstance(health.get("summary"), dict) else {}
    readiness = health.get("readiness") if isinstance(health.get("readiness"), dict) else {}
    checks = health.get("checks") if isinstance(health.get("checks"), list) else []
    metric_details = _metric_details(checks)
    return {
        "record_type": "federation_dashboard_health",
        "panel": "federation_diagnostics",
        "status": str(health.get("status") or "unknown"),
        "generated_at": timestamp,
        "metrics": {
            "readiness_score": int(readiness.get("score") or 0),
            "check_count": int(summary.get("check_count") or 0),
            "degraded_count": int(summary.get("degraded_count") or 0),
            "unavailable_count": int(summary.get("unavailable_count") or 0),
            "rejected_update_count": metric_details["rejected_update_count"],
            "stale_update_count": metric_details["stale_update_count"],
            "duplicate_event_count": metric_details["duplicate_event_count"],
            "replayed_update_count": metric_details["replayed_update_count"],
            "rejected_event_count": metric_details["rejected_event_count"],
            "recommendation_count": len(recommendations or []),
        },
        "recommended_review": bool(recommendations),
        **SIGNING_SAFETY_FLAGS,
    }


def build_federation_diagnostics_api(
    *,
    health: dict[str, Any],
    recommendations: list[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "federation_diagnostics_api",
        "generated_at": generated_at or _now(),
        "status": str(health.get("status") or "unknown"),
        "health_summary": dict(health.get("summary") or {}),
        "readiness": dict(health.get("readiness") or {}),
        "recommendations": list(recommendations),
        "dashboard": dict(dashboard),
        **SIGNING_SAFETY_FLAGS,
    }


def deterministic_federation_diagnostics_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _metric_details(checks: list[dict[str, Any]]) -> dict[str, int]:
    metrics = {
        "rejected_update_count": 0,
        "stale_update_count": 0,
        "duplicate_event_count": 0,
        "replayed_update_count": 0,
        "rejected_event_count": 0,
    }
    for check in checks:
        details = check.get("details") if isinstance(check.get("details"), dict) else {}
        metrics["rejected_update_count"] += int(details.get("rejected_update_count") or 0)
        metrics["stale_update_count"] += int(details.get("stale_update_count") or 0)
        metrics["duplicate_event_count"] += int(details.get("duplicate_event_count") or 0)
        metrics["replayed_update_count"] += int(details.get("replayed_update_count") or 0)
        metrics["rejected_event_count"] += int(details.get("rejected_event_count") or 0)
    return metrics


def _recommendation_summary(name: str, check: dict[str, Any]) -> str:
    message = str(check.get("message") or "")
    if message:
        return message
    return f"Review federation diagnostic check: {name}."


def _operator_action(name: str) -> str:
    actions = {
        "trusted_peers": "Review approved peer records and expiration timestamps.",
        "transport_sessions": "Review transport session status and expiration before accepting federation updates.",
        "signed_exchanges": "Inspect rejected signed exchange records and signature metadata.",
        "synchronization_window": "Review synchronization window replay counters, conflicts, and drift records.",
        "distributed_events": "Review rejected or duplicate event propagation records.",
        "replay_windows": "Review nonce, sequence, and stale-record counters before accepting more live updates.",
        "distributed_runtime": "Review distributed node state and cluster health rollups.",
    }
    return actions.get(name, "Review the diagnostic details before enabling additional federation workflows.")


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
