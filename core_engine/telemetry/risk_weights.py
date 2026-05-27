from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS


ADAPTIVE_RISK_WEIGHT_RECORD_VERSION = 1

ADAPTIVE_RISK_SAFETY_FLAGS = {
    **TELEMETRY_SAFETY_FLAGS,
    "metadata_only": True,
    "advisory_only": True,
    "dry_run_safe": True,
    "automatic_blocking": False,
    "firewall_changes": False,
    "service_changes": False,
    "packet_modification": False,
    "enforcement_allowed": False,
    "payloads_stored": False,
    "credentials_stored": False,
    "raw_browsing_history_stored": False,
    "external_reputation_calls": False,
    "user_deanonymization": False,
}


def build_risk_adjustment(
    *,
    reason: str,
    delta: float,
    evidence_refs: Iterable[str] | None = None,
    confidence: float = 0.5,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    adjustment = {
        "record_type": "adaptive_risk_weight_adjustment",
        "record_version": ADAPTIVE_RISK_WEIGHT_RECORD_VERSION,
        "generated_at": timestamp,
        "reason": str(reason),
        "delta": round(float(delta), 3),
        "confidence": _clamp(confidence),
        "evidence_refs": sorted(str(ref) for ref in evidence_refs or [] if ref),
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }
    adjustment["adjustment_id"] = "risk-adjustment-" + _digest({"reason": reason, "delta": adjustment["delta"], "evidence_refs": adjustment["evidence_refs"]})[:16]
    return adjustment


def stable_behavior_adjustment(*, context: dict[str, Any], generated_at: str | None = None) -> dict[str, Any] | None:
    if int(context.get("stable_behavior_count") or 0) <= 0:
        return None
    return build_risk_adjustment(
        reason="known_stable_behavior",
        delta=-0.1,
        evidence_refs=context.get("evidence_refs"),
        confidence=float(context.get("confidence") or 0.7),
        generated_at=generated_at,
    )


def new_behavior_adjustment(*, context: dict[str, Any], generated_at: str | None = None) -> dict[str, Any] | None:
    if int(context.get("new_behavior_count") or 0) <= 0:
        return None
    return build_risk_adjustment(
        reason="new_behavior_observed",
        delta=0.1,
        evidence_refs=context.get("evidence_refs"),
        confidence=float(context.get("confidence") or 0.55),
        generated_at=generated_at,
    )


def burst_anomaly_adjustment(*, context: dict[str, Any], generated_at: str | None = None) -> dict[str, Any] | None:
    if int(context.get("burst_count") or 0) <= 0:
        return None
    return build_risk_adjustment(
        reason="temporal_burst_anomaly",
        delta=0.12,
        evidence_refs=context.get("evidence_refs"),
        confidence=float(context.get("confidence") or 0.65),
        generated_at=generated_at,
    )


def unusual_service_fingerprint_adjustment(*, context: dict[str, Any], generated_at: str | None = None) -> dict[str, Any] | None:
    if int(context.get("unusual_combination_count") or 0) <= 0:
        return None
    return build_risk_adjustment(
        reason="unusual_process_port_pair",
        delta=0.14,
        evidence_refs=context.get("evidence_refs"),
        confidence=float(context.get("confidence") or 0.65),
        generated_at=generated_at,
    )


def unusual_destination_adjustment(*, context: dict[str, Any], generated_at: str | None = None) -> dict[str, Any] | None:
    if int(context.get("unusual_resolver_count") or 0) <= 0 and int(context.get("drift_count") or 0) <= 0:
        return None
    return build_risk_adjustment(
        reason="unusual_resolver_or_destination",
        delta=0.12,
        evidence_refs=context.get("evidence_refs"),
        confidence=float(context.get("confidence") or 0.6),
        generated_at=generated_at,
    )


def low_confidence_dampening_adjustment(*, confidence: float, generated_at: str | None = None) -> dict[str, Any] | None:
    if float(confidence) >= 0.45:
        return None
    return build_risk_adjustment(
        reason="low_confidence_dampening",
        delta=-0.08,
        evidence_refs=[],
        confidence=confidence,
        generated_at=generated_at,
    )


def mature_baseline_confidence_adjustment(*, context: dict[str, Any], generated_at: str | None = None) -> dict[str, Any] | None:
    if int(context.get("stable_behavior_count") or 0) <= 0 or float(context.get("confidence") or 0.0) < 0.75:
        return None
    return build_risk_adjustment(
        reason="mature_baseline_confidence",
        delta=-0.04,
        evidence_refs=context.get("evidence_refs"),
        confidence=float(context.get("confidence") or 0.75),
        generated_at=generated_at,
    )


def apply_adaptive_risk_weights(
    *,
    base_score: float,
    baseline_context: dict[str, Any] | None = None,
    anomaly_context: dict[str, Any] | None = None,
    service_fingerprint_context: dict[str, Any] | None = None,
    destination_context: dict[str, Any] | None = None,
    confidence: float = 0.7,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    adjustments = [
        stable_behavior_adjustment(context=baseline_context or {}, generated_at=timestamp),
        new_behavior_adjustment(context=baseline_context or {}, generated_at=timestamp),
        burst_anomaly_adjustment(context=anomaly_context or {}, generated_at=timestamp),
        unusual_service_fingerprint_adjustment(context=service_fingerprint_context or {}, generated_at=timestamp),
        unusual_destination_adjustment(context=destination_context or {}, generated_at=timestamp),
        mature_baseline_confidence_adjustment(context=baseline_context or {}, generated_at=timestamp),
        low_confidence_dampening_adjustment(confidence=confidence, generated_at=timestamp),
    ]
    selected = [row for row in adjustments if row is not None]
    raw_delta = sum(float(row.get("delta") or 0.0) for row in selected)
    dampener = max(0.35, min(1.0, float(confidence)))
    adjusted_delta = raw_delta * dampener
    adjusted_score = clamp_risk_score(float(base_score) + adjusted_delta)
    return {
        "record_type": "adaptive_risk_weight_result",
        "record_version": ADAPTIVE_RISK_WEIGHT_RECORD_VERSION,
        "generated_at": timestamp,
        "base_score": clamp_risk_score(base_score),
        "adjusted_score": adjusted_score,
        "raw_delta": round(raw_delta, 3),
        "adjusted_delta": round(adjusted_delta, 3),
        "confidence": _clamp(confidence),
        "adjustments": selected,
        "adjustment_reasons": [str(row.get("reason") or "") for row in selected],
        **ADAPTIVE_RISK_SAFETY_FLAGS,
    }


def clamp_risk_score(value: float) -> float:
    return round(max(0.0, min(1.0, float(value))), 3)


def deterministic_risk_weight_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _clamp(value: float) -> float:
    return round(max(0.0, min(1.0, float(value))), 3)


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
