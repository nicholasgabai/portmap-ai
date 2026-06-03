from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.attribution.confidence_models import ATTRIBUTION_SAFETY_FLAGS


SIGNATURE_LEARNING_RECORD_VERSION = 1
SIGNATURE_CLASSES = {
    "recurring_port_pattern",
    "protocol_pattern",
    "destination_pattern",
    "timing_pattern",
    "process_service_pattern",
    "flow_relationship_pattern",
    "unknown",
}

SIGNATURE_SAFETY_FLAGS = {
    **ATTRIBUTION_SAFETY_FLAGS,
    "full_dns_queries_stored": False,
    "raw_dns_browsing_history_stored": False,
    "payload_bytes_stored": 0,
}


class SignatureLearningError(ValueError):
    """Raised when behavioral signature inputs are malformed."""


def build_behavioral_signature_record(
    observation: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(observation, dict):
        raise SignatureLearningError("observation must be an object")
    timestamp = generated_at or _now()
    signature_class = normalize_signature_class(observation.get("signature_class") or _infer_signature_class(observation))
    recurrence = _score_recurrence(observation)
    stability = _score_stability(observation)
    drift = bool(observation.get("drift_detected"))
    mode = normalize_source_mode(observation.get("source_mode") or observation.get("data_source") or "unknown")
    confidence = score_signature_confidence(
        recurrence_score=recurrence,
        stability_score=stability,
        drift_detected=drift,
        source_mode=mode,
    )
    safe_evidence = _safe_signature_evidence(observation)
    record = {
        "record_type": "metadata_behavioral_signature",
        "record_version": SIGNATURE_LEARNING_RECORD_VERSION,
        "signature_id": "app-signature-" + _digest({"class": signature_class, "evidence": safe_evidence, "source_mode": mode, "drift_detected": drift})[:16],
        "generated_at": timestamp,
        "signature_class": signature_class,
        "recurrence_score": recurrence,
        "stability_score": stability,
        "drift_detected": drift,
        "learned_from_source_mode": mode,
        "source_mode": mode,
        "confidence_score": confidence,
        "privacy_mode": "redacted_metadata_only",
        "evidence_summary": safe_evidence,
        "advisory_notes": _signature_notes(signature_class=signature_class, drift_detected=drift),
        **SIGNATURE_SAFETY_FLAGS,
    }
    return record


def build_behavioral_signature_records(
    observations: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    try:
        rows = [build_behavioral_signature_record(row, generated_at=timestamp) for row in observations or [] if isinstance(row, dict)]
    except TypeError as exc:
        raise SignatureLearningError("observations must be iterable") from exc
    return sorted(_dedupe(rows), key=lambda item: str(item.get("signature_id") or ""))


def build_signature_learning_report(
    observations: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    signatures = build_behavioral_signature_records(observations, generated_at=timestamp)
    summary = summarize_behavioral_signatures(signatures, generated_at=timestamp)
    return {
        "record_type": "metadata_behavioral_signature_report",
        "record_version": SIGNATURE_LEARNING_RECORD_VERSION,
        "report_id": "app-signature-report-" + _digest({"generated_at": timestamp, "signatures": [row["signature_id"] for row in signatures]})[:16],
        "generated_at": timestamp,
        "signatures": signatures,
        "summary": summary,
        "dashboard_status": build_signature_dashboard(summary=summary, signatures=signatures, generated_at=timestamp),
        "api_status": build_signature_api(summary=summary, signatures=signatures, generated_at=timestamp),
        **SIGNATURE_SAFETY_FLAGS,
    }


def summarize_behavioral_signatures(
    signatures: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in signatures or [] if isinstance(row, dict)]
    by_class: dict[str, int] = {}
    for row in rows:
        signature_class = str(row.get("signature_class") or "unknown")
        by_class[signature_class] = by_class.get(signature_class, 0) + 1
    return {
        "record_type": "metadata_behavioral_signature_summary",
        "record_version": SIGNATURE_LEARNING_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "signature_count": len(rows),
        "drift_detected_count": sum(1 for row in rows if row.get("drift_detected")),
        "average_recurrence_score": _average(rows, "recurrence_score"),
        "average_stability_score": _average(rows, "stability_score"),
        "average_confidence_score": _average(rows, "confidence_score"),
        "by_signature_class": dict(sorted(by_class.items())),
        "source_modes": sorted({str(row.get("source_mode") or "unknown") for row in rows}) or ["unknown"],
        **SIGNATURE_SAFETY_FLAGS,
    }


def build_signature_dashboard(
    *,
    summary: dict[str, Any],
    signatures: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in signatures or [] if isinstance(row, dict)]
    return {
        "record_type": "metadata_behavioral_signature_dashboard",
        "panel": "dynamic_application_signatures",
        "status": "review_required" if int(summary.get("drift_detected_count") or 0) else "ok",
        "generated_at": generated_at or _now(),
        "metrics": {
            "signature_count": int(summary.get("signature_count") or 0),
            "drift_detected_count": int(summary.get("drift_detected_count") or 0),
            "average_confidence_score": float(summary.get("average_confidence_score") or 0.0),
        },
        "rows": [
            {
                "signature_id": row.get("signature_id"),
                "signature_class": row.get("signature_class"),
                "recurrence_score": row.get("recurrence_score"),
                "confidence_score": row.get("confidence_score"),
                "source_mode": row.get("source_mode"),
            }
            for row in rows
        ],
        **SIGNATURE_SAFETY_FLAGS,
    }


def build_signature_api(
    *,
    summary: dict[str, Any],
    signatures: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in signatures or [] if isinstance(row, dict)]
    return {
        "record_type": "metadata_behavioral_signature_api",
        "status": "ok",
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "signatures": rows,
        **SIGNATURE_SAFETY_FLAGS,
    }


def score_signature_confidence(
    *,
    recurrence_score: float,
    stability_score: float,
    drift_detected: bool = False,
    source_mode: str = "unknown",
) -> float:
    score = _clamp(recurrence_score) * 0.52 + _clamp(stability_score) * 0.38
    if normalize_source_mode(source_mode) in {"fixture", "simulated"}:
        score = min(score, 0.82)
    if drift_detected:
        score -= 0.12
    return round(max(0.0, min(1.0, score + 0.1)), 3)


def normalize_signature_class(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return text if text in SIGNATURE_CLASSES else "unknown"


def normalize_source_mode(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    return text if text in {"live", "simulated", "fixture", "replay", "unknown"} else "unknown"


def deterministic_signature_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _infer_signature_class(observation: dict[str, Any]) -> str:
    if observation.get("process_hint") or observation.get("service_hint"):
        return "process_service_pattern"
    if observation.get("destination_behavior_hint") or observation.get("domain_summary") or observation.get("domain_hash"):
        return "destination_pattern"
    if observation.get("flow_behavior_hint") or observation.get("relationship_reference"):
        return "flow_relationship_pattern"
    if observation.get("protocol_hint"):
        return "protocol_pattern"
    if observation.get("port") or observation.get("local_port") or observation.get("remote_port"):
        return "recurring_port_pattern"
    return "unknown"


def _score_recurrence(observation: dict[str, Any]) -> float:
    if observation.get("recurrence_score") not in {None, ""}:
        return _clamp(observation.get("recurrence_score"))
    count = int(observation.get("observation_count") or observation.get("frequency") or 1)
    score = min(count / 8, 0.65)
    if observation.get("recurring") or observation.get("stable_behavior"):
        score += 0.25
    return round(min(1.0, score), 3)


def _score_stability(observation: dict[str, Any]) -> float:
    if observation.get("stability_score") not in {None, ""}:
        return _clamp(observation.get("stability_score"))
    score = 0.2
    if observation.get("protocol_hint") not in {None, "", "unknown"}:
        score += 0.2
    if observation.get("service_hint") not in {None, "", "Unknown", "Unattributed"}:
        score += 0.2
    if observation.get("process_hint") not in {None, "", "Unknown", "Unattributed"}:
        score += 0.15
    if observation.get("destination_behavior_hint") or observation.get("domain_hash") or observation.get("domain_summary"):
        score += 0.12
    if observation.get("flow_behavior_hint"):
        score += 0.13
    return round(min(1.0, score), 3)


def _safe_signature_evidence(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_hint": _safe_hint(observation.get("process_hint") or observation.get("process_attribution"), fallback="Unknown", source_mode=observation.get("source_mode")),
        "service_hint": _safe_hint(observation.get("service_hint") or observation.get("service_attribution"), fallback="Unattributed", source_mode=observation.get("source_mode")),
        "protocol_hint": _safe_token(observation.get("protocol_hint") or observation.get("protocol")),
        "destination_behavior_hint": _safe_destination_hint(observation),
        "flow_behavior_hint": _safe_token(observation.get("flow_behavior_hint") or observation.get("relationship_state") or observation.get("session_state")),
        "port_class": _port_class(observation.get("port") or observation.get("local_port") or observation.get("remote_port")),
    }


def _safe_destination_hint(observation: dict[str, Any]) -> str:
    if observation.get("domain_hash"):
        return "hashed-domain:" + str(observation.get("domain_hash"))[:24]
    if observation.get("domain_summary") or observation.get("destination_behavior_hint"):
        return "redacted-destination"
    return _safe_token(observation.get("destination_class") or "unknown")


def _safe_hint(value: Any, *, fallback: str, source_mode: Any = "unknown") -> str:
    if isinstance(value, dict):
        value = value.get("display_name") or value.get("service_name") or value.get("process_name") or value.get("name") or value.get("value")
    text = str(value or "").strip()
    if not text:
        return fallback
    lowered = text.lower()
    if lowered in {"unknown", "none"}:
        return "Unknown"
    if lowered == "unattributed":
        return fallback
    if lowered in {"dummy_app", "dummy_db"} and normalize_source_mode(source_mode) not in {"fixture", "simulated"}:
        return fallback
    return text[:80]


def _port_class(value: Any) -> str:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return "unknown"
    if port < 1024:
        return "well_known"
    if port < 49152:
        return "registered"
    if port <= 65535:
        return "ephemeral"
    return "unknown"


def _signature_notes(*, signature_class: str, drift_detected: bool) -> list[str]:
    notes = [
        f"signature class is {signature_class}",
        "metadata-only behavioral signature; no payloads, raw DNS history, host identifiers, or credentials are stored",
    ]
    if drift_detected:
        notes.append("drift detected; operator review is advisory")
    return notes


def _dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        existing = grouped.get(row["signature_id"])
        if existing is None or float(row.get("confidence_score") or 0.0) > float(existing.get("confidence_score") or 0.0):
            grouped[row["signature_id"]] = row
    return list(grouped.values())


def _average(rows: list[dict[str, Any]], field_name: str) -> float:
    if not rows:
        return 0.0
    return round(sum(float(row.get(field_name) or 0.0) for row in rows) / len(rows), 3)


def _safe_token(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return text[:80] if text else "unknown"


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
