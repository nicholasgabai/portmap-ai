from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable


BEHAVIOR_DRIFT_RECORD_VERSION = 1
DRIFT_CLASSES = {
    "application_behavior",
    "service_behavior",
    "destination_behavior",
    "flow_behavior",
    "topology_behavior",
    "protocol_behavior",
    "unknown",
}
DRIFT_STATES = {"stable", "minor_drift", "moderate_drift", "major_drift", "unknown"}

DRIFT_SAFETY_FLAGS = {
    "local_only": True,
    "metadata_only": True,
    "advisory_only": True,
    "read_only": True,
    "raw_payload_stored": False,
    "raw_packet_stored": False,
    "packet_payload_inspected": False,
    "pcap_generated": False,
    "raw_dns_history_stored": False,
    "credential_material_stored": False,
    "hostname_stored": False,
    "ip_address_stored": False,
    "mac_address_stored": False,
    "username_stored": False,
    "threat_verdict_generated": False,
    "automatic_changes": False,
    "enforcement_enabled": False,
}


class BehavioralDriftError(ValueError):
    """Raised when behavioral drift inputs are malformed."""


def build_behavior_drift_record(
    *,
    baseline_record: dict[str, Any] | None = None,
    current_record: dict[str, Any] | None = None,
    drift_class: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if baseline_record is not None and not isinstance(baseline_record, dict):
        raise BehavioralDriftError("baseline_record must be an object")
    if current_record is not None and not isinstance(current_record, dict):
        raise BehavioralDriftError("current_record must be an object")
    timestamp = generated_at or _now()
    baseline = dict(baseline_record or {})
    current = dict(current_record or {})
    normalized_class = normalize_drift_class(drift_class or current.get("drift_class") or baseline.get("drift_class") or current.get("category") or baseline.get("category"))
    score = score_behavior_drift(baseline, current)
    state = classify_drift_state(score=score, malformed=not baseline and not current)
    recurrence_state = classify_recurrence_state(baseline, current)
    confidence = score_drift_confidence(
        baseline=baseline,
        current=current,
        drift_score=score,
        recurrence_state=recurrence_state,
    )
    mode = normalize_source_mode(current.get("source_mode") or baseline.get("source_mode") or current.get("data_source") or baseline.get("data_source") or "unknown")
    record = {
        "record_type": "behavior_drift_record",
        "record_version": BEHAVIOR_DRIFT_RECORD_VERSION,
        "drift_id": "behavior-drift-"
        + _digest(
            {
                "baseline_reference": _reference(baseline, "baseline"),
                "current_reference": _reference(current, "current"),
                "drift_class": normalized_class,
                "source_mode": mode,
            }
        )[:16],
        "generated_at": timestamp,
        "drift_class": normalized_class,
        "baseline_reference": _reference(baseline, "baseline"),
        "current_reference": _reference(current, "current"),
        "drift_score": score,
        "drift_severity": state,
        "drift_state": state,
        "recurrence_state": recurrence_state,
        "confidence_score": confidence,
        "source_mode": mode,
        "data_source": mode,
        "evidence_summary": build_drift_evidence_summary(baseline, current),
        "advisory_notes": _advisory_notes(state=state, drift_class=normalized_class),
        **DRIFT_SAFETY_FLAGS,
    }
    return record


def build_behavior_drift_records(
    comparisons: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    try:
        rows = [dict(row) for row in comparisons or [] if isinstance(row, dict)]
    except TypeError as exc:
        raise BehavioralDriftError("comparisons must be iterable") from exc
    records = [
        build_behavior_drift_record(
            baseline_record=row.get("baseline_record") or row.get("baseline"),
            current_record=row.get("current_record") or row.get("current"),
            drift_class=row.get("drift_class"),
            generated_at=timestamp,
        )
        for row in rows
    ]
    return sorted(records, key=lambda item: str(item.get("drift_id") or ""))


def build_behavior_drift_report(
    comparisons: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    records = build_behavior_drift_records(comparisons, generated_at=timestamp)
    summary = summarize_behavior_drift(records, generated_at=timestamp)
    return {
        "record_type": "behavior_drift_report",
        "record_version": BEHAVIOR_DRIFT_RECORD_VERSION,
        "report_id": "behavior-drift-report-" + _digest({"generated_at": timestamp, "drifts": [row["drift_id"] for row in records]})[:16],
        "generated_at": timestamp,
        "drift_records": records,
        "summary": summary,
        "dashboard_status": build_behavior_drift_dashboard(summary=summary, drift_records=records, generated_at=timestamp),
        "api_status": build_behavior_drift_api(summary=summary, drift_records=records, generated_at=timestamp),
        **DRIFT_SAFETY_FLAGS,
    }


def summarize_behavior_drift(
    drift_records: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in drift_records or [] if isinstance(row, dict)]
    by_class: dict[str, int] = {}
    for row in rows:
        drift_class = str(row.get("drift_class") or "unknown")
        by_class[drift_class] = by_class.get(drift_class, 0) + 1
    return {
        "record_type": "behavior_drift_summary",
        "record_version": BEHAVIOR_DRIFT_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "drift_count": len(rows),
        "stable_count": _count_state(rows, "stable"),
        "minor_drift_count": _count_state(rows, "minor_drift"),
        "moderate_drift_count": _count_state(rows, "moderate_drift"),
        "major_drift_count": _count_state(rows, "major_drift"),
        "unknown_count": _count_state(rows, "unknown"),
        "average_drift_score": _average(rows, "drift_score"),
        "average_confidence_score": _average(rows, "confidence_score"),
        "by_drift_class": dict(sorted(by_class.items())),
        "source_modes": sorted({str(row.get("source_mode") or "unknown") for row in rows}) or ["unknown"],
        **DRIFT_SAFETY_FLAGS,
    }


def build_behavior_drift_dashboard(
    *,
    summary: dict[str, Any],
    drift_records: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in drift_records or [] if isinstance(row, dict)]
    status = "review_required" if int(summary.get("major_drift_count") or 0) or int(summary.get("moderate_drift_count") or 0) else "ok"
    return {
        "record_type": "behavior_drift_dashboard",
        "panel": "behavioral_drift_detection",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "drift_count": int(summary.get("drift_count") or 0),
            "stable_count": int(summary.get("stable_count") or 0),
            "moderate_drift_count": int(summary.get("moderate_drift_count") or 0),
            "major_drift_count": int(summary.get("major_drift_count") or 0),
            "average_drift_score": float(summary.get("average_drift_score") or 0.0),
        },
        "rows": [
            {
                "drift_id": row.get("drift_id"),
                "drift_class": row.get("drift_class"),
                "drift_severity": row.get("drift_severity"),
                "drift_score": row.get("drift_score"),
                "confidence_score": row.get("confidence_score"),
                "source_mode": row.get("source_mode"),
            }
            for row in rows
        ],
        "recommended_review": status != "ok",
        **DRIFT_SAFETY_FLAGS,
    }


def build_behavior_drift_api(
    *,
    summary: dict[str, Any],
    drift_records: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in drift_records or [] if isinstance(row, dict)]
    return {
        "record_type": "behavior_drift_api",
        "status": "review_required" if int(summary.get("major_drift_count") or 0) else "ok",
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "drift_records": rows,
        **DRIFT_SAFETY_FLAGS,
    }


def score_behavior_drift(baseline: dict[str, Any], current: dict[str, Any]) -> float:
    if not baseline and not current:
        return 0.0
    baseline_score = _score_value(baseline)
    current_score = _score_value(current)
    score_delta = abs(current_score - baseline_score)
    frequency_delta = _frequency_delta(baseline, current)
    label_delta = 0.25 if _label_value(baseline) and _label_value(current) and _label_value(baseline) != _label_value(current) else 0.0
    drift_flag = 0.2 if current.get("drift_detected") else 0.0
    novelty = 0.18 if current.get("novelty") or current.get("new_behavior") else 0.0
    return round(min(1.0, score_delta * 0.38 + frequency_delta * 0.28 + label_delta + drift_flag + novelty), 3)


def classify_drift_state(*, score: float, malformed: bool = False) -> str:
    if malformed:
        return "unknown"
    value = _clamp(score)
    if value >= 0.72:
        return "major_drift"
    if value >= 0.45:
        return "moderate_drift"
    if value >= 0.18:
        return "minor_drift"
    return "stable"


def classify_recurrence_state(baseline: dict[str, Any], current: dict[str, Any]) -> str:
    if not baseline and not current:
        return "unknown"
    if current.get("recurring_behavior") or current.get("recurrence_score", 0) and float(current.get("recurrence_score") or 0) >= 0.6:
        return "recurring"
    if current.get("novelty") or current.get("new_behavior"):
        return "new"
    if baseline and not current:
        return "decayed"
    if baseline and current:
        return "seen_before"
    return "unknown"


def score_drift_confidence(
    *,
    baseline: dict[str, Any],
    current: dict[str, Any],
    drift_score: float,
    recurrence_state: str,
) -> float:
    score = 0.18
    if baseline:
        score += 0.2
    if current:
        score += 0.22
    score += min(_clamp(drift_score) * 0.24, 0.24)
    if recurrence_state in {"recurring", "seen_before"}:
        score += 0.12
    if _reference(baseline, "baseline") and _reference(current, "current"):
        score += 0.04
    return round(min(1.0, score), 3)


def build_drift_evidence_summary(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    return {
        "baseline_score": _score_value(baseline),
        "current_score": _score_value(current),
        "baseline_frequency": _frequency_value(baseline),
        "current_frequency": _frequency_value(current),
        "baseline_label": _label_value(baseline),
        "current_label": _label_value(current),
        "privacy_mode": "metadata_only",
    }


def normalize_drift_class(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    if text in {"application", "app", "app_behavior"}:
        text = "application_behavior"
    elif text in {"service", "service_fingerprint"}:
        text = "service_behavior"
    elif text in {"destination", "dns", "domain"}:
        text = "destination_behavior"
    elif text in {"flow", "session"}:
        text = "flow_behavior"
    elif text in {"topology", "relationship"}:
        text = "topology_behavior"
    elif text == "protocol":
        text = "protocol_behavior"
    return text if text in DRIFT_CLASSES else "unknown"


def normalize_source_mode(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    return text if text in {"live", "simulated", "fixture", "replay", "unknown"} else "unknown"


def deterministic_behavior_drift_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _score_value(row: dict[str, Any]) -> float:
    for field in ("rolling_average_score", "confidence_score", "confidence", "risk_score", "score", "relationship_strength"):
        if row.get(field) not in {None, ""}:
            return _clamp(row.get(field))
    return 0.0


def _frequency_value(row: dict[str, Any]) -> int:
    for field in ("observation_count", "frequency", "count", "flow_count"):
        if row.get(field) not in {None, ""}:
            try:
                return max(0, int(row.get(field) or 0))
            except (TypeError, ValueError):
                return 0
    return 0


def _frequency_delta(baseline: dict[str, Any], current: dict[str, Any]) -> float:
    baseline_count = _frequency_value(baseline)
    current_count = _frequency_value(current)
    denominator = max(baseline_count, current_count, 1)
    return round(abs(current_count - baseline_count) / denominator, 3)


def _label_value(row: dict[str, Any]) -> str:
    for field in ("behavior_state", "classification_label", "candidate_app_class", "service_name", "protocol", "relationship_state", "destination_class"):
        value = row.get(field)
        if value not in {None, ""}:
            return str(value)[:80]
    return ""


def _reference(row: dict[str, Any], prefix: str) -> str:
    for field in (
        f"{prefix}_reference",
        f"{prefix}_id",
        "baseline_id",
        "signature_id",
        "attribution_id",
        "relationship_id",
        "flow_id",
        "record_id",
        "current_id",
    ):
        value = row.get(field)
        if value not in {None, ""}:
            return str(value)[:96]
    return ""


def _advisory_notes(*, state: str, drift_class: str) -> list[str]:
    return [
        f"{drift_class} drift state is {state}",
        "drift is an advisory baseline comparison, not a threat verdict",
        "metadata-only drift record; no payloads, packet captures, credentials, or enforcement actions are stored",
    ]


def _count_state(rows: list[dict[str, Any]], state: str) -> int:
    return sum(1 for row in rows if row.get("drift_severity") == state or row.get("drift_state") == state)


def _average(rows: list[dict[str, Any]], field_name: str) -> float:
    if not rows:
        return 0.0
    return round(sum(float(row.get(field_name) or 0.0) for row in rows) / len(rows), 3)


def _clamp(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return round(max(0.0, min(1.0, number)), 3)


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
