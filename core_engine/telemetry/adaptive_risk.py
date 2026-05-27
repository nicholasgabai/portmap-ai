from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.risk_weights import (
    ADAPTIVE_RISK_SAFETY_FLAGS,
    ADAPTIVE_RISK_WEIGHT_RECORD_VERSION,
    apply_adaptive_risk_weights,
    clamp_risk_score,
    deterministic_risk_weight_json,
)


ADAPTIVE_RISK_RECORD_VERSION = 1
DEFAULT_ADAPTIVE_RISK_BASE_SCORE = 0.5


class AdaptiveRiskError(ValueError):
    """Raised when adaptive risk input is malformed."""


def build_adaptive_risk_report(
    *,
    risk_inputs: Iterable[dict[str, Any]] | None = None,
    baseline_report: dict[str, Any] | None = None,
    temporal_anomaly_report: dict[str, Any] | None = None,
    service_fingerprint_report: dict[str, Any] | None = None,
    dns_destination_behavior_report: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    inputs = _risk_inputs(risk_inputs)
    contexts = {
        "baseline_context": build_baseline_risk_context(baseline_report),
        "anomaly_context": build_anomaly_risk_context(temporal_anomaly_report),
        "service_fingerprint_context": build_service_fingerprint_risk_context(service_fingerprint_report),
        "destination_context": build_destination_risk_context(dns_destination_behavior_report),
    }
    records = [
        build_adaptive_risk_record(
            risk_input=row,
            generated_at=timestamp,
            **contexts,
        )
        for row in inputs
    ]
    summary = summarize_adaptive_risk_records(records, generated_at=timestamp)
    dashboard = build_adaptive_risk_dashboard_record(summary=summary, records=records, generated_at=timestamp)
    api = build_adaptive_risk_api_response(summary=summary, records=records, dashboard=dashboard, generated_at=timestamp)
    export = build_adaptive_risk_export_record(summary=summary, records=records, generated_at=timestamp)
    return {
        "record_type": "adaptive_risk_report",
        "record_version": ADAPTIVE_RISK_RECORD_VERSION,
        "report_id": "adaptive-risk-report-" + _digest({"generated_at": timestamp, "records": [row.get("adaptive_risk_id") for row in records]})[:16],
        "generated_at": timestamp,
        "records": records,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        "export_summary": export,
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }


def build_adaptive_risk_record(
    *,
    risk_input: dict[str, Any],
    baseline_context: dict[str, Any],
    anomaly_context: dict[str, Any],
    service_fingerprint_context: dict[str, Any],
    destination_context: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not isinstance(risk_input, dict):
        raise AdaptiveRiskError("risk_input must be an object")
    base_score = clamp_risk_score(float(risk_input.get("base_score", DEFAULT_ADAPTIVE_RISK_BASE_SCORE)))
    confidence = float(risk_input.get("confidence", _combined_confidence(baseline_context, anomaly_context, service_fingerprint_context, destination_context)))
    weight_result = apply_adaptive_risk_weights(
        base_score=base_score,
        baseline_context=baseline_context,
        anomaly_context=anomaly_context,
        service_fingerprint_context=service_fingerprint_context,
        destination_context=destination_context,
        confidence=confidence,
        generated_at=timestamp,
    )
    explanation = build_adaptive_risk_explanation(
        base_score=base_score,
        adjusted_score=float(weight_result.get("adjusted_score") or base_score),
        adjustments=weight_result.get("adjustments") or [],
        baseline_context=baseline_context,
        anomaly_context=anomaly_context,
        service_fingerprint_context=service_fingerprint_context,
        destination_context=destination_context,
        confidence=float(weight_result.get("confidence") or confidence),
        generated_at=timestamp,
    )
    record = {
        "record_type": "adaptive_risk_record",
        "record_version": ADAPTIVE_RISK_RECORD_VERSION,
        "generated_at": timestamp,
        "source_ref": str(risk_input.get("source_ref") or "adaptive-risk:local"),
        "base_score": base_score,
        "adjusted_score": float(weight_result.get("adjusted_score") or base_score),
        "confidence": float(weight_result.get("confidence") or confidence),
        "adjustment_reason": list(weight_result.get("adjustment_reasons") or []),
        "baseline_context": dict(baseline_context),
        "anomaly_context": dict(anomaly_context),
        "service_fingerprint_context": dict(service_fingerprint_context),
        "destination_context": dict(destination_context),
        "weight_result": weight_result,
        "explanation": explanation,
        "safety_mode": str(risk_input.get("safety_mode") or "dry_run_advisory"),
        "enforcement_allowed": False,
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }
    record["adaptive_risk_id"] = "adaptive-risk-" + _digest({"source_ref": record["source_ref"], "base_score": base_score, "generated_at": timestamp})[:16]
    return record


def build_baseline_risk_context(baseline_report: dict[str, Any] | None) -> dict[str, Any]:
    summary = baseline_report.get("summary") if isinstance((baseline_report or {}).get("summary"), dict) else {}
    entries = _rows((baseline_report or {}).get("entries") if isinstance(baseline_report, dict) else [])
    return {
        "record_type": "adaptive_risk_baseline_context",
        "stable_behavior_count": int(summary.get("stable_behavior_count") or 0),
        "new_behavior_count": int(summary.get("novel_behavior_count") or 0),
        "recurring_behavior_count": int(summary.get("recurring_behavior_count") or 0),
        "decaying_inactive_count": int(summary.get("decaying_inactive_count") or 0),
        "confidence": float(summary.get("average_confidence") or 0.0),
        "evidence_refs": _ids(entries, "baseline_id"),
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }


def build_anomaly_risk_context(temporal_anomaly_report: dict[str, Any] | None) -> dict[str, Any]:
    summary = temporal_anomaly_report.get("summary") if isinstance((temporal_anomaly_report or {}).get("summary"), dict) else {}
    anomalies = _rows((temporal_anomaly_report or {}).get("anomalies") if isinstance(temporal_anomaly_report, dict) else [])
    return {
        "record_type": "adaptive_risk_anomaly_context",
        "anomaly_count": int(summary.get("anomaly_count") or 0),
        "burst_count": int(summary.get("burst_count") or 0),
        "rare_service_timing_count": int(summary.get("rare_service_timing_count") or 0),
        "volume_drift_count": int(summary.get("volume_drift_count") or 0),
        "new_behavior_count": int(summary.get("novel_behavior_count") or 0),
        "confidence": float(summary.get("average_confidence") or 0.0),
        "evidence_refs": _ids(anomalies, "anomaly_id"),
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }


def build_service_fingerprint_risk_context(service_fingerprint_report: dict[str, Any] | None) -> dict[str, Any]:
    summary = service_fingerprint_report.get("profile_summary") if isinstance((service_fingerprint_report or {}).get("profile_summary"), dict) else {}
    profiles = _rows((service_fingerprint_report or {}).get("profiles") if isinstance(service_fingerprint_report, dict) else [])
    return {
        "record_type": "adaptive_risk_service_fingerprint_context",
        "profile_count": int(summary.get("profile_count") or 0),
        "stable_profile_count": int(summary.get("stable_profile_count") or 0),
        "unusual_combination_count": int(summary.get("unusual_combination_count") or 0),
        "low_confidence_count": int(summary.get("low_confidence_count") or 0),
        "dormant_reappeared_count": int(summary.get("dormant_reappeared_count") or 0),
        "confidence": float(summary.get("average_confidence") or 0.0),
        "evidence_refs": _ids(profiles, "profile_id"),
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }


def build_destination_risk_context(dns_destination_behavior_report: dict[str, Any] | None) -> dict[str, Any]:
    summary = dns_destination_behavior_report.get("summary") if isinstance((dns_destination_behavior_report or {}).get("summary"), dict) else {}
    profiles = _rows((dns_destination_behavior_report or {}).get("profiles") if isinstance(dns_destination_behavior_report, dict) else [])
    return {
        "record_type": "adaptive_risk_destination_context",
        "destination_count": int(summary.get("destination_count") or 0),
        "stable_destination_count": int(summary.get("stable_destination_count") or 0),
        "new_destination_count": int(summary.get("new_destination_count") or 0),
        "unusual_resolver_count": int(summary.get("unusual_resolver_count") or 0),
        "dormant_return_count": int(summary.get("dormant_return_count") or 0),
        "drift_count": int(summary.get("drift_count") or 0),
        "confidence": float(summary.get("average_confidence") or 0.0),
        "evidence_refs": _ids(profiles, "profile_id"),
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }


def build_adaptive_risk_explanation(
    *,
    base_score: float,
    adjusted_score: float,
    adjustments: Iterable[dict[str, Any]],
    baseline_context: dict[str, Any],
    anomaly_context: dict[str, Any],
    service_fingerprint_context: dict[str, Any],
    destination_context: dict[str, Any],
    confidence: float,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    adjustment_rows = _rows(adjustments)
    direction = "unchanged"
    if float(adjusted_score) > float(base_score):
        direction = "increased"
    elif float(adjusted_score) < float(base_score):
        direction = "reduced"
    reason_text = _reason_text(adjustment_rows)
    explanation = {
        "record_type": "adaptive_risk_explanation",
        "record_version": ADAPTIVE_RISK_RECORD_VERSION,
        "generated_at": timestamp,
        "what_changed": f"Risk score {direction} from {base_score:.3f} to {adjusted_score:.3f}.",
        "why_score_moved": reason_text,
        "local_evidence_contributed": {
            "baseline_evidence_count": len(baseline_context.get("evidence_refs") or []),
            "anomaly_evidence_count": len(anomaly_context.get("evidence_refs") or []),
            "service_fingerprint_evidence_count": len(service_fingerprint_context.get("evidence_refs") or []),
            "destination_evidence_count": len(destination_context.get("evidence_refs") or []),
        },
        "why_no_enforcement": "Adaptive risk weighting is advisory-only; enforcement is disabled by default and no blocking, firewall, service, or packet changes are applied.",
        "confidence": round(max(0.0, min(1.0, float(confidence))), 3),
        "limitations": _limitations(
            baseline_context,
            anomaly_context,
            service_fingerprint_context,
            destination_context,
            confidence=confidence,
        ),
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }
    explanation["explanation_id"] = "adaptive-risk-explanation-" + _digest({"base_score": base_score, "adjusted_score": adjusted_score, "reasons": [row.get("reason") for row in adjustment_rows]})[:16]
    return explanation


def summarize_adaptive_risk_records(records: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = _rows(records)
    increases = [row for row in rows if float(row.get("adjusted_score") or 0.0) > float(row.get("base_score") or 0.0)]
    reductions = [row for row in rows if float(row.get("adjusted_score") or 0.0) < float(row.get("base_score") or 0.0)]
    return {
        "record_type": "adaptive_risk_summary",
        "record_version": ADAPTIVE_RISK_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "record_count": len(rows),
        "score_increase_count": len(increases),
        "score_reduction_count": len(reductions),
        "average_base_score": round(sum(float(row.get("base_score") or 0.0) for row in rows) / len(rows), 3) if rows else 0.0,
        "average_adjusted_score": round(sum(float(row.get("adjusted_score") or 0.0) for row in rows) / len(rows), 3) if rows else 0.0,
        "average_confidence": round(sum(float(row.get("confidence") or 0.0) for row in rows) / len(rows), 3) if rows else 0.0,
        "by_adjustment_reason": _reason_counts(rows),
        "enforcement_allowed": False,
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }


def build_adaptive_risk_dashboard_record(*, summary: dict[str, Any], records: Iterable[dict[str, Any]], generated_at: str | None = None) -> dict[str, Any]:
    rows = _rows(records)
    return {
        "record_type": "adaptive_risk_dashboard",
        "panel": "adaptive_risk",
        "status": "review_required" if int(summary.get("score_increase_count") or 0) else "ok",
        "generated_at": generated_at or _now(),
        "metrics": {
            "record_count": int(summary.get("record_count") or 0),
            "score_increase_count": int(summary.get("score_increase_count") or 0),
            "score_reduction_count": int(summary.get("score_reduction_count") or 0),
            "average_base_score": float(summary.get("average_base_score") or 0.0),
            "average_adjusted_score": float(summary.get("average_adjusted_score") or 0.0),
            "average_confidence": float(summary.get("average_confidence") or 0.0),
        },
        "rows": [
            {
                "source_ref": row.get("source_ref"),
                "base_score": row.get("base_score"),
                "adjusted_score": row.get("adjusted_score"),
                "adjustment_reason": list(row.get("adjustment_reason") or []),
                "confidence": row.get("confidence"),
            }
            for row in sorted(rows, key=lambda item: str(item.get("source_ref") or ""))[:50]
        ],
        "recommended_review": int(summary.get("score_increase_count") or 0) > 0,
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }


def build_adaptive_risk_api_response(*, summary: dict[str, Any], records: Iterable[dict[str, Any]], dashboard: dict[str, Any], generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "adaptive_risk_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "records": _rows(records),
        "dashboard": dict(dashboard),
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }


def build_adaptive_risk_export_record(*, summary: dict[str, Any], records: Iterable[dict[str, Any]], generated_at: str | None = None) -> dict[str, Any]:
    rows = _rows(records)
    payload = {
        "record_type": "adaptive_risk_export_summary",
        "record_version": ADAPTIVE_RISK_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "record_counts": {
            "adaptive_risk_records": len(rows),
            "score_increases": int(summary.get("score_increase_count") or 0),
            "score_reductions": int(summary.get("score_reduction_count") or 0),
        },
        "adaptive_risk_ids": [str(row.get("adaptive_risk_id") or "") for row in rows],
        "digest": "",
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }
    payload["digest"] = "sha256:" + _digest({"record_counts": payload["record_counts"], "adaptive_risk_ids": payload["adaptive_risk_ids"]})
    return payload


def build_adaptive_risk_operator_panel(adaptive_risk_report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not adaptive_risk_report:
        return {
            "record_type": "adaptive_risk_empty_dashboard_summary",
            "panel": "adaptive_risk",
            "status": "empty",
            "generated_at": timestamp,
            "metrics": {},
            "rows": [],
            **ADAPTIVE_RISK_SAFETY_FLAGS,
        }
    dashboard = adaptive_risk_report.get("dashboard_status") if isinstance(adaptive_risk_report.get("dashboard_status"), dict) else {}
    summary = adaptive_risk_report.get("summary") if isinstance(adaptive_risk_report.get("summary"), dict) else {}
    metrics = dashboard.get("metrics") if isinstance(dashboard.get("metrics"), dict) else {}
    return {
        "record_type": "adaptive_risk_operator_panel",
        "panel": "adaptive_risk",
        "status": str(dashboard.get("status") or "ok"),
        "generated_at": timestamp,
        "metrics": {
            "record_count": int(metrics.get("record_count") or summary.get("record_count") or 0),
            "score_increase_count": int(metrics.get("score_increase_count") or summary.get("score_increase_count") or 0),
            "score_reduction_count": int(metrics.get("score_reduction_count") or summary.get("score_reduction_count") or 0),
            "average_adjusted_score": float(metrics.get("average_adjusted_score") or summary.get("average_adjusted_score") or 0.0),
            "average_confidence": float(metrics.get("average_confidence") or summary.get("average_confidence") or 0.0),
        },
        "rows": list(dashboard.get("rows") or []),
        "recommended_review": bool(dashboard.get("recommended_review")),
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }


def deterministic_adaptive_risk_json(record: dict[str, Any]) -> str:
    return deterministic_risk_weight_json(record)


def _risk_inputs(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    rows = _rows(value)
    if rows:
        return rows
    return [{"source_ref": "adaptive-risk:default", "base_score": DEFAULT_ADAPTIVE_RISK_BASE_SCORE}]


def _combined_confidence(*contexts: dict[str, Any]) -> float:
    values = [float(context.get("confidence") or 0.0) for context in contexts if float(context.get("confidence") or 0.0) > 0]
    return round(sum(values) / len(values), 3) if values else 0.5


def _reason_text(adjustments: list[dict[str, Any]]) -> str:
    if not adjustments:
        return "No local behavioral evidence changed the advisory score."
    reasons = ", ".join(str(row.get("reason") or "unknown") for row in adjustments)
    return f"Local behavioral evidence applied these advisory adjustments: {reasons}."


def _limitations(*contexts: dict[str, Any], confidence: float) -> list[str]:
    limitations = []
    if float(confidence) < 0.45:
        limitations.append("low_confidence_input")
    if not any(context.get("evidence_refs") for context in contexts):
        limitations.append("limited_local_evidence")
    if not limitations:
        limitations.append("metadata_only_advisory_context")
    return sorted(set(limitations))


def _reason_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in records:
        for reason in row.get("adjustment_reason") or []:
            key = str(reason or "unknown")
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def _ids(rows: Iterable[dict[str, Any]], field_name: str) -> list[str]:
    return sorted(str(row.get(field_name) or "") for row in rows if row.get(field_name))


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
