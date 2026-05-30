from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS


BEHAVIORAL_INTELLIGENCE_RECORD_VERSION = 1

BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS = {
    **TELEMETRY_SAFETY_FLAGS,
    "advisory_only": True,
    "dry_run_safe": True,
    "metadata_only": True,
    "automatic_enforcement": False,
    "automatic_blocking": False,
    "firewall_changes": False,
    "external_reputation_calls": False,
    "raw_payload_stored": False,
    "credentials_stored": False,
    "dashboard_safe": True,
    "export_ready": True,
}

COMPONENT_ORDER = (
    "baselines",
    "temporal_anomalies",
    "service_fingerprints",
    "dns_destination_behavior",
    "adaptive_risk",
)


def build_behavioral_intelligence_summary(
    *,
    behavior_baseline_report: dict[str, Any] | None = None,
    temporal_anomaly_report: dict[str, Any] | None = None,
    service_fingerprint_report: dict[str, Any] | None = None,
    dns_destination_behavior_report: dict[str, Any] | None = None,
    adaptive_risk_report: dict[str, Any] | None = None,
    gateway_validation_summary: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rollups = {
        "baselines": build_baseline_summary_rollup(behavior_baseline_report, generated_at=timestamp),
        "temporal_anomalies": build_temporal_anomaly_rollup(temporal_anomaly_report, generated_at=timestamp),
        "service_fingerprints": build_service_fingerprint_rollup(service_fingerprint_report, generated_at=timestamp),
        "dns_destination_behavior": build_dns_destination_behavior_rollup(dns_destination_behavior_report, generated_at=timestamp),
        "adaptive_risk": build_adaptive_risk_rollup(adaptive_risk_report, generated_at=timestamp),
    }
    state_summary = build_behavioral_state_summary(rollups=rollups, gateway_validation_summary=gateway_validation_summary, generated_at=timestamp)
    recommendations = build_behavioral_recommendation_records(rollups=rollups, state_summary=state_summary, generated_at=timestamp)
    explanations = build_behavioral_explanation_records(rollups=rollups, state_summary=state_summary, generated_at=timestamp)
    privacy = build_behavioral_privacy_safety_summary(generated_at=timestamp)
    export = build_behavioral_intelligence_export_record(
        rollups=rollups,
        state_summary=state_summary,
        recommendations=recommendations,
        generated_at=timestamp,
    )
    dashboard = build_behavioral_intelligence_dashboard_record(
        rollups=rollups,
        state_summary=state_summary,
        recommendations=recommendations,
        generated_at=timestamp,
    )
    api = build_behavioral_intelligence_api_response(
        rollups=rollups,
        state_summary=state_summary,
        recommendations=recommendations,
        explanations=explanations,
        dashboard=dashboard,
        export=export,
        privacy_safety_summary=privacy,
        generated_at=timestamp,
    )
    report = {
        "record_type": "behavioral_intelligence_summary",
        "record_version": BEHAVIORAL_INTELLIGENCE_RECORD_VERSION,
        "generated_at": timestamp,
        "status": state_summary["overall_state"],
        "component_rollups": rollups,
        "state_summary": state_summary,
        "recommendations": recommendations,
        "explanations": explanations,
        "privacy_safety_summary": privacy,
        "dashboard_status": dashboard,
        "api_status": api,
        "export_summary": export,
        **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
    }
    report["summary_id"] = "behavioral-summary-" + _digest(
        {"generated_at": timestamp, "states": state_summary.get("component_states"), "record_counts": export.get("record_counts")}
    )[:16]
    return report


def build_baseline_summary_rollup(report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    summary = _summary(report)
    metrics = _dashboard_metrics(report)
    return _rollup(
        component="baselines",
        available=bool(report),
        generated_at=generated_at,
        metrics={
            "baseline_entry_count": _int(metrics, summary, "baseline_entry_count"),
            "stable_behavior_count": _int(metrics, summary, "stable_behavior_count"),
            "novel_behavior_count": _int(metrics, summary, "novel_behavior_count"),
            "decaying_inactive_count": _int(metrics, summary, "decaying_inactive_count"),
            "average_confidence": _float(metrics, summary, "average_confidence"),
        },
        review_count=_int(metrics, summary, "novel_behavior_count") + _int(metrics, summary, "decaying_inactive_count"),
        confidence=_float(metrics, summary, "average_confidence"),
        source_report_type=_report_type(report),
        by_state=dict(summary.get("by_behavior_state") or {}),
    )


def build_temporal_anomaly_rollup(report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    summary = _summary(report)
    metrics = _dashboard_metrics(report)
    return _rollup(
        component="temporal_anomalies",
        available=bool(report),
        generated_at=generated_at,
        metrics={
            "anomaly_count": _int(metrics, summary, "anomaly_count"),
            "burst_count": _int(metrics, summary, "burst_count"),
            "rare_service_timing_count": _int(metrics, summary, "rare_service_timing_count"),
            "volume_drift_count": _int(metrics, summary, "volume_drift_count"),
            "novel_behavior_count": _int(metrics, summary, "novel_behavior_count"),
            "average_confidence": _float(metrics, summary, "average_confidence"),
        },
        review_count=_int(metrics, summary, "anomaly_count"),
        confidence=_float(metrics, summary, "average_confidence"),
        source_report_type=_report_type(report),
        by_state=dict(summary.get("by_label") or {}),
    )


def build_service_fingerprint_rollup(report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    summary = _summary(report)
    profile_summary = report.get("profile_summary") if isinstance((report or {}).get("profile_summary"), dict) else {}
    metrics = _dashboard_metrics(report)
    return _rollup(
        component="service_fingerprints",
        available=bool(report),
        generated_at=generated_at,
        metrics={
            "fingerprint_count": _int(metrics, summary, "fingerprint_count"),
            "profile_count": _int(metrics, profile_summary, "profile_count"),
            "stable_profile_count": _int(metrics, profile_summary, "stable_profile_count"),
            "unusual_combination_count": _int(metrics, profile_summary, "unusual_combination_count"),
            "dormant_reappeared_count": _int(metrics, profile_summary, "dormant_reappeared_count"),
            "average_confidence": _float(metrics, profile_summary, "average_confidence"),
        },
        review_count=_int(metrics, profile_summary, "unusual_combination_count") + _int(metrics, profile_summary, "dormant_reappeared_count"),
        confidence=_float(metrics, profile_summary, "average_confidence"),
        source_report_type=_report_type(report),
        by_state=dict(profile_summary.get("by_behavior_state") or {}),
    )


def build_dns_destination_behavior_rollup(report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    summary = _summary(report)
    metrics = _dashboard_metrics(report)
    review_count = (
        _int(metrics, summary, "new_destination_count")
        + _int(metrics, summary, "unusual_resolver_count")
        + _int(metrics, summary, "dormant_return_count")
        + _int(metrics, summary, "drift_count")
    )
    return _rollup(
        component="dns_destination_behavior",
        available=bool(report),
        generated_at=generated_at,
        metrics={
            "destination_count": _int(metrics, summary, "destination_count"),
            "stable_destination_count": _int(metrics, summary, "stable_destination_count"),
            "new_destination_count": _int(metrics, summary, "new_destination_count"),
            "unusual_resolver_count": _int(metrics, summary, "unusual_resolver_count"),
            "dormant_return_count": _int(metrics, summary, "dormant_return_count"),
            "drift_count": _int(metrics, summary, "drift_count"),
            "average_confidence": _float(metrics, summary, "average_confidence"),
        },
        review_count=review_count,
        confidence=_float(metrics, summary, "average_confidence"),
        source_report_type=_report_type(report),
        by_state=dict(summary.get("by_behavior_state") or {}),
    )


def build_adaptive_risk_rollup(report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    summary = _summary(report)
    metrics = _dashboard_metrics(report)
    return _rollup(
        component="adaptive_risk",
        available=bool(report),
        generated_at=generated_at,
        metrics={
            "record_count": _int(metrics, summary, "record_count"),
            "score_increase_count": _int(metrics, summary, "score_increase_count"),
            "score_reduction_count": _int(metrics, summary, "score_reduction_count"),
            "average_base_score": _float(metrics, summary, "average_base_score"),
            "average_adjusted_score": _float(metrics, summary, "average_adjusted_score"),
            "average_confidence": _float(metrics, summary, "average_confidence"),
        },
        review_count=_int(metrics, summary, "score_increase_count"),
        confidence=_float(metrics, summary, "average_confidence"),
        source_report_type=_report_type(report),
        by_state=dict(summary.get("by_adjustment_reason") or {}),
    )


def build_behavioral_state_summary(
    *,
    rollups: dict[str, dict[str, Any]],
    gateway_validation_summary: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    states = {name: str((rollups.get(name) or {}).get("state") or "unavailable") for name in COMPONENT_ORDER}
    unavailable = [name for name, state in states.items() if state == "unavailable"]
    degraded = [name for name, state in states.items() if state == "degraded"]
    supported = [name for name, state in states.items() if state == "supported"]
    if not supported and not degraded:
        overall = "unavailable"
    elif unavailable or degraded:
        overall = "degraded"
    else:
        overall = "supported"
    review_count = sum(int((rollups.get(name) or {}).get("recommended_review_count") or 0) for name in COMPONENT_ORDER)
    gateway_state = _gateway_state(gateway_validation_summary)
    return {
        "record_type": "behavioral_intelligence_state_summary",
        "record_version": BEHAVIORAL_INTELLIGENCE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "overall_state": overall,
        "component_states": states,
        "supported_component_count": len(supported),
        "degraded_component_count": len(degraded),
        "unavailable_component_count": len(unavailable),
        "recommended_review_count": review_count,
        "gateway_validation_state": gateway_state,
        "advisory_only": True,
        "enforcement_allowed": False,
        **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
    }


def build_behavioral_recommendation_records(
    *,
    rollups: dict[str, dict[str, Any]],
    state_summary: dict[str, Any],
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    recommendations: list[dict[str, Any]] = []
    for name in COMPONENT_ORDER:
        rollup = rollups.get(name) or {}
        if str(rollup.get("state")) == "unavailable":
            recommendations.append(_recommendation(name, "provide_component_summary", "low", "Add sanitized local summary input for this behavior component.", timestamp))
        elif int(rollup.get("recommended_review_count") or 0) > 0:
            recommendations.append(_recommendation(name, "operator_review_recommended", "medium", "Review advisory behavior changes before considering any manual follow-up.", timestamp))
    if str(state_summary.get("overall_state")) == "supported" and not recommendations:
        recommendations.append(_recommendation("behavioral_intelligence", "continue_monitoring", "info", "Continue collecting local metadata summaries and review future behavior drift.", timestamp))
    return recommendations


def build_behavioral_explanation_records(
    *,
    rollups: dict[str, dict[str, Any]],
    state_summary: dict[str, Any],
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    explanations = []
    for name in COMPONENT_ORDER:
        rollup = rollups.get(name) or {}
        explanations.append(
            {
                "record_type": "behavioral_intelligence_explanation",
                "record_version": BEHAVIORAL_INTELLIGENCE_RECORD_VERSION,
                "generated_at": timestamp,
                "component": name,
                "state": str(rollup.get("state") or "unavailable"),
                "what_changed": _component_change_text(name, rollup),
                "why_it_matters": _component_reason_text(name),
                "operator_action": "review_advisory_summary" if int(rollup.get("recommended_review_count") or 0) else "no_action_required",
                "why_no_enforcement": "Behavioral intelligence summaries are advisory-only; no blocking, firewall, service, packet, or external reputation action is applied.",
                "confidence": float(rollup.get("confidence") or 0.0),
                **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
            }
        )
    explanations.append(
        {
            "record_type": "behavioral_intelligence_explanation",
            "record_version": BEHAVIORAL_INTELLIGENCE_RECORD_VERSION,
            "generated_at": timestamp,
            "component": "overall",
            "state": str(state_summary.get("overall_state") or "unknown"),
            "what_changed": f"Behavioral intelligence summary state is {state_summary.get('overall_state')}.",
            "why_it_matters": "The combined state shows whether local behavior evidence is available, complete, and reviewable.",
            "operator_action": "review_recommendations" if int(state_summary.get("recommended_review_count") or 0) else "continue_monitoring",
            "why_no_enforcement": "Operator review remains separate from enforcement; this phase does not execute remediation.",
            "confidence": _average_confidence(rollups.values()),
            **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
        }
    )
    for row in explanations:
        row["explanation_id"] = "behavior-explanation-" + _digest({"component": row["component"], "state": row["state"], "generated_at": timestamp})[:16]
    return explanations


def build_behavioral_privacy_safety_summary(*, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "behavioral_intelligence_privacy_safety_summary",
        "record_version": BEHAVIORAL_INTELLIGENCE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "payloads_stored": False,
        "credentials_stored": False,
        "raw_dns_payloads_stored": False,
        "raw_browsing_history_stored": False,
        "external_reputation_calls": False,
        "automatic_enforcement": False,
        "firewall_changes": False,
        "operator_review_required_for_action": True,
        **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
    }


def build_behavioral_intelligence_export_record(
    *,
    rollups: dict[str, dict[str, Any]],
    state_summary: dict[str, Any],
    recommendations: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    record_counts = {
        name: int((rollups.get(name) or {}).get("record_count") or 0)
        for name in COMPONENT_ORDER
    }
    payload = {
        "record_type": "behavioral_intelligence_export_summary",
        "record_version": BEHAVIORAL_INTELLIGENCE_RECORD_VERSION,
        "generated_at": timestamp,
        "overall_state": str(state_summary.get("overall_state") or "unknown"),
        "record_counts": record_counts,
        "recommendation_count": len(_rows(recommendations)),
        "digest": "",
        **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
    }
    payload["digest"] = "sha256:" + _digest({"overall_state": payload["overall_state"], "record_counts": record_counts, "recommendation_count": payload["recommendation_count"]})
    return payload


def build_behavioral_intelligence_dashboard_record(
    *,
    rollups: dict[str, dict[str, Any]],
    state_summary: dict[str, Any],
    recommendations: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    return {
        "record_type": "behavioral_intelligence_dashboard",
        "panel": "behavioral_intelligence",
        "status": str(state_summary.get("overall_state") or "unknown"),
        "generated_at": timestamp,
        "metrics": {
            "supported_component_count": int(state_summary.get("supported_component_count") or 0),
            "degraded_component_count": int(state_summary.get("degraded_component_count") or 0),
            "unavailable_component_count": int(state_summary.get("unavailable_component_count") or 0),
            "recommended_review_count": int(state_summary.get("recommended_review_count") or 0),
            "average_confidence": _average_confidence(rollups.values()),
        },
        "component_rows": [
            {
                "component": name,
                "state": (rollups.get(name) or {}).get("state"),
                "record_count": (rollups.get(name) or {}).get("record_count"),
                "recommended_review_count": (rollups.get(name) or {}).get("recommended_review_count"),
                "confidence": (rollups.get(name) or {}).get("confidence"),
            }
            for name in COMPONENT_ORDER
        ],
        "recommendations": _rows(recommendations)[:20],
        "recommended_review": int(state_summary.get("recommended_review_count") or 0) > 0,
        **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
    }


def build_behavioral_intelligence_api_response(
    *,
    rollups: dict[str, dict[str, Any]],
    state_summary: dict[str, Any],
    recommendations: Iterable[dict[str, Any]],
    explanations: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    export: dict[str, Any],
    privacy_safety_summary: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "behavioral_intelligence_api",
        "status": str(state_summary.get("overall_state") or "unknown"),
        "generated_at": generated_at or _now(),
        "rollups": dict(rollups),
        "state_summary": dict(state_summary),
        "recommendations": _rows(recommendations),
        "explanations": _rows(explanations),
        "dashboard": dict(dashboard),
        "export_summary": dict(export),
        "privacy_safety_summary": dict(privacy_safety_summary),
        **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
    }


def deterministic_behavioral_intelligence_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _rollup(
    *,
    component: str,
    available: bool,
    generated_at: str | None,
    metrics: dict[str, Any],
    review_count: int,
    confidence: float,
    source_report_type: str,
    by_state: dict[str, Any],
) -> dict[str, Any]:
    record_count = _record_count(component, metrics)
    state = "unavailable"
    if available and record_count == 0:
        state = "degraded"
    elif available:
        state = "degraded" if review_count else "supported"
    return {
        "record_type": "behavioral_intelligence_component_rollup",
        "record_version": BEHAVIORAL_INTELLIGENCE_RECORD_VERSION,
        "component": component,
        "source_report_type": source_report_type,
        "generated_at": generated_at or _now(),
        "state": state,
        "record_count": record_count,
        "recommended_review_count": int(review_count),
        "confidence": round(max(0.0, min(1.0, float(confidence))), 3),
        "metrics": dict(sorted(metrics.items())),
        "by_state": dict(sorted(by_state.items())),
        **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
    }


def _record_count(component: str, metrics: dict[str, Any]) -> int:
    keys = {
        "baselines": "baseline_entry_count",
        "temporal_anomalies": "anomaly_count",
        "service_fingerprints": "profile_count",
        "dns_destination_behavior": "destination_count",
        "adaptive_risk": "record_count",
    }
    return int(metrics.get(keys.get(component, "record_count")) or 0)


def _recommendation(component: str, action: str, severity: str, summary: str, generated_at: str) -> dict[str, Any]:
    row = {
        "record_type": "behavioral_intelligence_recommendation",
        "record_version": BEHAVIORAL_INTELLIGENCE_RECORD_VERSION,
        "generated_at": generated_at,
        "component": component,
        "action": action,
        "severity": severity,
        "summary": summary,
        "advisory_only": True,
        "enforcement_allowed": False,
        **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
    }
    row["recommendation_id"] = "behavior-recommendation-" + _digest({"component": component, "action": action, "severity": severity})[:16]
    return row


def _component_change_text(component: str, rollup: dict[str, Any]) -> str:
    return f"{component} state is {rollup.get('state')} with {rollup.get('record_count')} records and {rollup.get('recommended_review_count')} review hints."


def _component_reason_text(component: str) -> str:
    reasons = {
        "baselines": "Historical baselines distinguish stable local behavior from newly observed activity.",
        "temporal_anomalies": "Anomaly windows show short, medium, and long behavior changes against local baselines.",
        "service_fingerprints": "Service fingerprints identify expected and unusual process, service, protocol, and port combinations.",
        "dns_destination_behavior": "DNS and destination summaries show recurring, novel, and drifting destination metadata.",
        "adaptive_risk": "Adaptive risk weighting explains how local behavioral evidence moved advisory scores.",
    }
    return reasons.get(component, "Behavioral summary records support operator review.")


def _summary(report: dict[str, Any] | None) -> dict[str, Any]:
    return report.get("summary") if isinstance((report or {}).get("summary"), dict) else {}


def _dashboard_metrics(report: dict[str, Any] | None) -> dict[str, Any]:
    dashboard = report.get("dashboard_status") if isinstance((report or {}).get("dashboard_status"), dict) else {}
    return dashboard.get("metrics") if isinstance(dashboard.get("metrics"), dict) else {}


def _report_type(report: dict[str, Any] | None) -> str:
    return str((report or {}).get("record_type") or "unavailable")


def _int(primary: dict[str, Any], fallback: dict[str, Any], key: str) -> int:
    return int(primary.get(key) if primary.get(key) is not None else fallback.get(key) or 0)


def _float(primary: dict[str, Any], fallback: dict[str, Any], key: str) -> float:
    return float(primary.get(key) if primary.get(key) is not None else fallback.get(key) or 0.0)


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _average_confidence(rollups: Iterable[dict[str, Any]]) -> float:
    values = [float(row.get("confidence") or 0.0) for row in rollups if float(row.get("confidence") or 0.0) > 0]
    return round(sum(values) / len(values), 3) if values else 0.0


def _gateway_state(gateway_validation_summary: dict[str, Any] | None) -> str:
    if not gateway_validation_summary:
        return "not_provided"
    return str(gateway_validation_summary.get("overall_state") or gateway_validation_summary.get("status") or "unknown")


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
