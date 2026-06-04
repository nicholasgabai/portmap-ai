from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.behavior.drift_detection import (
    BEHAVIOR_DRIFT_RECORD_VERSION,
    BehavioralDriftError,
    DRIFT_SAFETY_FLAGS,
    build_behavior_drift_records,
)


ENVIRONMENT_DRIFT_RECORD_VERSION = 1


class EnvironmentDriftError(ValueError):
    """Raised when environment drift inputs are malformed."""


def build_environment_drift_summary(
    drift_records: Iterable[dict[str, Any]] | None = None,
    *,
    comparisons: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if drift_records is None and comparisons is not None:
        try:
            records = build_behavior_drift_records(comparisons, generated_at=timestamp)
        except BehavioralDriftError as exc:
            raise EnvironmentDriftError("comparisons must be iterable") from exc
    else:
        try:
            records = [dict(row) for row in drift_records or [] if isinstance(row, dict)]
        except TypeError as exc:
            raise EnvironmentDriftError("drift_records must be iterable") from exc
    affected = sorted({str(row.get("drift_class") or "unknown") for row in records if str(row.get("drift_severity") or "unknown") not in {"stable", "unknown"}})
    stability = score_environment_stability(records)
    trend = classify_drift_trend(records)
    recurring = any(str(row.get("recurrence_state") or "") == "recurring" and str(row.get("drift_severity") or "") != "stable" for row in records)
    unusual = any(str(row.get("drift_severity") or "") in {"moderate_drift", "major_drift"} for row in records)
    confidence = score_environment_drift_confidence(records)
    return {
        "record_type": "environment_drift_summary",
        "record_version": ENVIRONMENT_DRIFT_RECORD_VERSION,
        "environment_drift_id": "environment-drift-" + _digest({"generated_at": timestamp, "drifts": [row.get("drift_id") for row in records]})[:16],
        "generated_at": timestamp,
        "affected_categories": affected,
        "stability_score": stability,
        "drift_trend": trend,
        "recurring_change_detected": recurring,
        "unusual_change_detected": unusual,
        "confidence_score": confidence,
        "operator_summary": operator_environment_summary(stability_score=stability, drift_trend=trend, unusual_change_detected=unusual),
        "drift_records": sorted(records, key=lambda item: str(item.get("drift_id") or "")),
        "threat_verdict": "not_assessed",
        "enforcement_action": "none",
        **DRIFT_SAFETY_FLAGS,
    }


def build_environment_drift_dashboard_record(
    environment_summary: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    summary = dict(environment_summary or {})
    return {
        "record_type": "environment_drift_dashboard",
        "panel": "environment_behavioral_drift",
        "status": "review_required" if summary.get("unusual_change_detected") else "ok",
        "generated_at": generated_at or summary.get("generated_at") or _now(),
        "metrics": {
            "affected_category_count": len(summary.get("affected_categories") or []),
            "stability_score": float(summary.get("stability_score") or 0.0),
            "confidence_score": float(summary.get("confidence_score") or 0.0),
            "recurring_change_detected": bool(summary.get("recurring_change_detected")),
            "unusual_change_detected": bool(summary.get("unusual_change_detected")),
        },
        "operator_summary": str(summary.get("operator_summary") or ""),
        "recommended_review": bool(summary.get("unusual_change_detected")),
        **DRIFT_SAFETY_FLAGS,
    }


def build_environment_drift_api_response(
    environment_summary: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    summary = dict(environment_summary or {})
    return {
        "record_type": "environment_drift_api",
        "status": "review_required" if summary.get("unusual_change_detected") else "ok",
        "generated_at": generated_at or summary.get("generated_at") or _now(),
        "environment_drift": summary,
        **DRIFT_SAFETY_FLAGS,
    }


def build_environment_drift_report(
    comparisons: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    try:
        records = build_behavior_drift_records(comparisons, generated_at=timestamp)
    except (BehavioralDriftError, TypeError) as exc:
        raise EnvironmentDriftError("comparisons must be iterable") from exc
    summary = build_environment_drift_summary(records, generated_at=timestamp)
    return {
        "record_type": "environment_drift_report",
        "record_version": ENVIRONMENT_DRIFT_RECORD_VERSION,
        "report_id": "environment-drift-report-" + _digest({"generated_at": timestamp, "summary": summary.get("environment_drift_id")})[:16],
        "generated_at": timestamp,
        "drift_records": records,
        "environment_summary": summary,
        "dashboard_status": build_environment_drift_dashboard_record(summary, generated_at=timestamp),
        "api_status": build_environment_drift_api_response(summary, generated_at=timestamp),
        **DRIFT_SAFETY_FLAGS,
    }


def score_environment_stability(drift_records: Iterable[dict[str, Any]]) -> float:
    rows = [dict(row) for row in drift_records or [] if isinstance(row, dict)]
    if not rows:
        return 1.0
    average_drift = sum(float(row.get("drift_score") or 0.0) for row in rows) / len(rows)
    major_penalty = sum(0.08 for row in rows if row.get("drift_severity") == "major_drift")
    moderate_penalty = sum(0.04 for row in rows if row.get("drift_severity") == "moderate_drift")
    return round(max(0.0, min(1.0, 1.0 - average_drift - major_penalty - moderate_penalty)), 3)


def classify_drift_trend(drift_records: Iterable[dict[str, Any]]) -> str:
    rows = [dict(row) for row in drift_records or [] if isinstance(row, dict)]
    if not rows:
        return "stable"
    major = sum(1 for row in rows if row.get("drift_severity") == "major_drift")
    moderate = sum(1 for row in rows if row.get("drift_severity") == "moderate_drift")
    minor = sum(1 for row in rows if row.get("drift_severity") == "minor_drift")
    stable = sum(1 for row in rows if row.get("drift_severity") == "stable")
    if major:
        return "rapid_change"
    if moderate >= 2 or (moderate and minor):
        return "gradual_change"
    if minor:
        return "minor_variation"
    if stable == len(rows):
        return "stable"
    return "unknown"


def score_environment_drift_confidence(drift_records: Iterable[dict[str, Any]]) -> float:
    rows = [dict(row) for row in drift_records or [] if isinstance(row, dict)]
    if not rows:
        return 0.5
    average = sum(float(row.get("confidence_score") or 0.0) for row in rows) / len(rows)
    coverage = min(len(rows) / 6, 0.2)
    return round(min(1.0, average * 0.8 + coverage), 3)


def operator_environment_summary(*, stability_score: float, drift_trend: str, unusual_change_detected: bool) -> str:
    if unusual_change_detected:
        return f"Review environment drift trend {drift_trend}; this is not a threat verdict and no enforcement was applied."
    return f"Environment drift trend is {drift_trend} with stability score {stability_score}."


def deterministic_environment_drift_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
