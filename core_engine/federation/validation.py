from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.federation.diagnostics import build_federation_diagnostics
from core_engine.federation.health import (
    DEFAULT_FEDERATION_THRESHOLDS,
    calculate_federation_readiness_score,
    summarize_federation_health_checks,
)
from core_engine.federation.runtime_checks import (
    ACTIVE_FEDERATION_VALIDATION_RECORD_VERSION,
    ACTIVE_FEDERATION_VALIDATION_SAFETY_FLAGS,
    build_active_federation_validation_checks,
)


def build_active_federation_validation(
    *,
    runtime_manager: dict[str, Any] | None = None,
    peer_registry: dict[str, Any] | None = None,
    exchange_scheduler: dict[str, Any] | None = None,
    trust_profile: dict[str, Any] | None = None,
    transport_sessions: Iterable[dict[str, Any]] | None = None,
    signed_exchanges: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    sync_result: dict[str, Any] | None = None,
    event_batch: dict[str, Any] | None = None,
    diagnostics: dict[str, Any] | None = None,
    thresholds: dict[str, int] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build active federation validation records without executing runtime work."""
    timestamp = generated_at or _now()
    diagnostic_record = diagnostics or build_federation_diagnostics(
        trust_profile=trust_profile,
        transport_sessions=list(transport_sessions or []),
        signed_exchanges=signed_exchanges,
        sync_result=sync_result,
        event_batch=event_batch,
        generated_at=timestamp,
    )
    checks = build_active_federation_validation_checks(
        runtime_manager=runtime_manager,
        peer_registry=peer_registry,
        exchange_scheduler=exchange_scheduler,
        trust_profile=trust_profile,
        signed_exchanges=signed_exchanges,
        sync_result=sync_result,
        event_batch=event_batch,
        generated_at=timestamp,
    )
    summary = summarize_active_federation_validation_checks(checks, generated_at=timestamp)
    readiness = calculate_active_federation_validation_score(checks, thresholds=thresholds)
    recommendations = build_active_federation_validation_recommendations(checks, generated_at=timestamp)
    dashboard = build_active_federation_validation_dashboard_record(
        summary=summary,
        readiness=readiness,
        recommendations=recommendations,
        diagnostics=diagnostic_record,
        generated_at=timestamp,
    )
    api = build_active_federation_validation_api_response(
        summary=summary,
        readiness=readiness,
        checks=checks,
        recommendations=recommendations,
        dashboard=dashboard,
        generated_at=timestamp,
    )
    status = "ready" if readiness["status"] == "ready" and summary["degraded_count"] == 0 and summary["unavailable_count"] == 0 else "review_required"
    return {
        "record_type": "active_federation_validation",
        "record_version": ACTIVE_FEDERATION_VALIDATION_RECORD_VERSION,
        "validation_id": _stable_id("active-federation-validation", timestamp, summary, readiness),
        "generated_at": timestamp,
        "status": status,
        "checks": checks,
        "summary": {**summary, "status": status},
        "readiness": readiness,
        "diagnostics_summary": {
            "status": str(diagnostic_record.get("status") or "unknown"),
            "readiness": dict((diagnostic_record.get("health") or {}).get("readiness") or {}),
        },
        "recommendations": recommendations,
        "dashboard_status": dashboard,
        "api_status": api,
        **ACTIVE_FEDERATION_VALIDATION_SAFETY_FLAGS,
    }


def summarize_active_federation_validation_checks(
    checks: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    summary = summarize_federation_health_checks(checks, generated_at=timestamp)
    rows = [dict(check) for check in checks or [] if isinstance(check, dict)]
    return {
        "record_type": "active_federation_validation_summary",
        "record_version": ACTIVE_FEDERATION_VALIDATION_RECORD_VERSION,
        "generated_at": timestamp,
        "check_count": int(summary.get("check_count") or 0),
        "degraded_count": int(summary.get("degraded_count") or 0),
        "unavailable_count": int(summary.get("unavailable_count") or 0),
        "critical_count": int(summary.get("critical_count") or 0),
        "high_count": int(summary.get("high_count") or 0),
        "by_status": dict(summary.get("by_status") or {}),
        "by_severity": dict(summary.get("by_severity") or {}),
        "ready_check_count": sum(1 for check in rows if check.get("status") == "ok"),
        "operator_summary": _operator_summary(rows),
        **ACTIVE_FEDERATION_VALIDATION_SAFETY_FLAGS,
    }


def calculate_active_federation_validation_score(
    checks: Iterable[dict[str, Any]],
    *,
    thresholds: dict[str, int] | None = None,
) -> dict[str, Any]:
    threshold_values = dict(DEFAULT_FEDERATION_THRESHOLDS)
    threshold_values.update({key: int(value) for key, value in dict(thresholds or {}).items() if key in threshold_values})
    return {
        **calculate_federation_readiness_score(checks, thresholds=threshold_values),
        "record_type": "active_federation_validation_readiness",
        "record_version": ACTIVE_FEDERATION_VALIDATION_RECORD_VERSION,
        **ACTIVE_FEDERATION_VALIDATION_SAFETY_FLAGS,
    }


def build_active_federation_validation_recommendations(
    checks: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    recommendations = []
    for check in sorted([dict(row) for row in checks or [] if isinstance(row, dict)], key=lambda item: str(item.get("name") or "")):
        if check.get("status") == "ok" and check.get("severity") == "info":
            continue
        name = str(check.get("name") or "active_federation")
        recommendations.append(
            {
                "record_type": "active_federation_validation_recommendation",
                "record_version": ACTIVE_FEDERATION_VALIDATION_RECORD_VERSION,
                "recommendation_id": _stable_id("active-federation-rec", name, check.get("status"), check.get("message")),
                "check_name": name,
                "status": str(check.get("status") or "unknown"),
                "severity": str(check.get("severity") or "info"),
                "summary": str(check.get("message") or f"Review active federation validation check {name}."),
                "operator_action": _operator_action(name),
                "generated_at": timestamp,
                **ACTIVE_FEDERATION_VALIDATION_SAFETY_FLAGS,
            }
        )
    return recommendations


def build_active_federation_validation_dashboard_record(
    *,
    summary: dict[str, Any],
    readiness: dict[str, Any],
    recommendations: Iterable[dict[str, Any]],
    diagnostics: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    return {
        "record_type": "active_federation_validation_dashboard",
        "panel": "active_federation_validation",
        "status": "ready" if readiness.get("status") == "ready" and int(summary.get("degraded_count") or 0) == 0 and int(summary.get("unavailable_count") or 0) == 0 else "review_required",
        "generated_at": timestamp,
        "metrics": {
            "readiness_score": int(readiness.get("score") or 0),
            "check_count": int(summary.get("check_count") or 0),
            "ready_check_count": int(summary.get("ready_check_count") or 0),
            "degraded_count": int(summary.get("degraded_count") or 0),
            "unavailable_count": int(summary.get("unavailable_count") or 0),
            "recommendation_count": len(list(recommendations or [])),
        },
        "diagnostics_status": str((diagnostics or {}).get("status") or "unknown"),
        "recommended_review": bool(int(summary.get("degraded_count") or 0) or int(summary.get("unavailable_count") or 0) or len(list(recommendations or []))),
        **ACTIVE_FEDERATION_VALIDATION_SAFETY_FLAGS,
    }


def build_active_federation_validation_api_response(
    *,
    summary: dict[str, Any],
    readiness: dict[str, Any],
    checks: Iterable[dict[str, Any]],
    recommendations: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "active_federation_validation_api",
        "generated_at": generated_at or _now(),
        "status": str(dashboard.get("status") or "unknown"),
        "summary": dict(summary),
        "readiness": dict(readiness),
        "checks": [dict(check) for check in checks or [] if isinstance(check, dict)],
        "recommendations": [dict(rec) for rec in recommendations or [] if isinstance(rec, dict)],
        "dashboard": dict(dashboard),
        **ACTIVE_FEDERATION_VALIDATION_SAFETY_FLAGS,
    }


def deterministic_active_federation_validation_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _operator_summary(checks: list[dict[str, Any]]) -> str:
    degraded = [check for check in checks if check.get("status") == "degraded"]
    unavailable = [check for check in checks if check.get("status") == "unavailable"]
    if degraded or unavailable:
        return f"Active federation validation requires review for {len(degraded)} degraded and {len(unavailable)} unavailable check(s)."
    return f"Active federation validation passed {len(checks)} check(s)."


def _operator_action(name: str) -> str:
    actions = {
        "trusted_peers": "Review peer lifecycle and trust scope records before enabling active exchange.",
        "signed_exchanges": "Review signature metadata, digest validation, and trusted peer hooks.",
        "synchronization_window": "Review accepted, rejected, stale, replayed, conflict, and drift counters.",
        "event_propagation": "Review distributed event propagation counters and duplicate classifications.",
        "replay_windows": "Review replay-window sequence and nonce metadata before accepting more updates.",
        "runtime_scheduler": "Review exchange scheduler job state, backoff, and failure counters.",
        "federation_runtime": "Review runtime manager state and planned loop records.",
    }
    return actions.get(name, "Review validation details before enabling active federation runtime loops.")


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
