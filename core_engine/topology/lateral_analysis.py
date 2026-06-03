from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.topology.relationship_graphs import (
    RELATIONSHIP_SAFETY_FLAGS,
    build_node_relationship_record,
)


LATERAL_ANALYSIS_RECORD_VERSION = 1
LATERAL_RELATIONSHIP_STATES = {"expected", "unusual", "suspicious", "isolated", "unknown"}


class LateralAnalysisError(ValueError):
    """Raised when lateral relationship analysis inputs are malformed."""


def build_lateral_relationship_analysis(
    relationship: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(relationship, dict):
        raise LateralAnalysisError("relationship must be an object")
    timestamp = generated_at or _now()
    row = relationship if relationship.get("record_type") == "cross_node_relationship" else build_node_relationship_record(relationship, generated_at=timestamp)
    recurrence = _clamp(row.get("recurring_interaction_score"))
    topology_risk = score_topology_risk(row)
    spread_potential = score_spread_potential(row, topology_risk=topology_risk, recurrence_score=recurrence)
    unusual_peer = detect_unusual_peer(row)
    state = classify_lateral_relationship(
        row,
        topology_risk=topology_risk,
        spread_potential=spread_potential,
        unusual_peer_detected=unusual_peer,
    )
    confidence = score_lateral_confidence(
        row,
        lateral_relationship_state=state,
        topology_risk=topology_risk,
        spread_potential=spread_potential,
    )
    return {
        "record_type": "lateral_relationship_analysis",
        "record_version": LATERAL_ANALYSIS_RECORD_VERSION,
        "analysis_id": "lateral-analysis-"
        + _digest(
            {
                "relationship_reference": row.get("relationship_id"),
                "state": state,
                "source_mode": row.get("source_mode"),
            }
        )[:16],
        "generated_at": timestamp,
        "relationship_reference": str(row.get("relationship_id") or ""),
        "lateral_relationship_state": state,
        "recurrence_score": recurrence,
        "topology_risk": topology_risk,
        "spread_potential": spread_potential,
        "unusual_peer_detected": unusual_peer,
        "drift_detected": bool(row.get("drift_detected")),
        "confidence_score": confidence,
        "operator_summary": _operator_summary(
            state=state,
            relationship=row,
            topology_risk=topology_risk,
            spread_potential=spread_potential,
        ),
        "source_mode": row.get("source_mode") or "unknown",
        "threat_verdict": "not_assessed",
        "enforcement_action": "none",
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def build_lateral_analysis_report(
    relationships: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    try:
        analyses = [
            build_lateral_relationship_analysis(row, generated_at=timestamp)
            for row in relationships or []
            if isinstance(row, dict)
        ]
    except TypeError as exc:
        raise LateralAnalysisError("relationships must be iterable") from exc
    summary = summarize_lateral_analysis(analyses, generated_at=timestamp)
    return {
        "record_type": "lateral_analysis_report",
        "record_version": LATERAL_ANALYSIS_RECORD_VERSION,
        "report_id": "lateral-analysis-report-"
        + _digest({"generated_at": timestamp, "analyses": [row["analysis_id"] for row in analyses]})[:16],
        "generated_at": timestamp,
        "analyses": sorted(analyses, key=lambda item: str(item.get("analysis_id") or "")),
        "summary": summary,
        "dashboard_status": build_lateral_analysis_dashboard(summary=summary, analyses=analyses, generated_at=timestamp),
        "api_status": build_lateral_analysis_api(summary=summary, analyses=analyses, generated_at=timestamp),
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def summarize_lateral_analysis(
    analyses: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in analyses or [] if isinstance(row, dict)]
    return {
        "record_type": "lateral_analysis_summary",
        "record_version": LATERAL_ANALYSIS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "analysis_count": len(rows),
        "expected_count": _count_state(rows, "expected"),
        "unusual_count": _count_state(rows, "unusual"),
        "suspicious_count": _count_state(rows, "suspicious"),
        "isolated_count": _count_state(rows, "isolated"),
        "unknown_count": _count_state(rows, "unknown"),
        "unusual_peer_count": sum(1 for row in rows if row.get("unusual_peer_detected")),
        "drift_detected_count": sum(1 for row in rows if row.get("drift_detected")),
        "average_topology_risk": _average(rows, "topology_risk"),
        "average_spread_potential": _average(rows, "spread_potential"),
        "average_confidence_score": _average(rows, "confidence_score"),
        "source_modes": sorted({str(row.get("source_mode") or "unknown") for row in rows}) or ["unknown"],
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def build_lateral_analysis_dashboard(
    *,
    summary: dict[str, Any],
    analyses: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in analyses or [] if isinstance(row, dict)]
    status = "review_required" if int(summary.get("suspicious_count") or 0) else "degraded" if int(summary.get("unusual_count") or 0) else "ok"
    return {
        "record_type": "lateral_analysis_dashboard",
        "panel": "lateral_relationship_analysis",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "analysis_count": int(summary.get("analysis_count") or 0),
            "expected_count": int(summary.get("expected_count") or 0),
            "unusual_count": int(summary.get("unusual_count") or 0),
            "suspicious_count": int(summary.get("suspicious_count") or 0),
            "average_spread_potential": float(summary.get("average_spread_potential") or 0.0),
        },
        "rows": [
            {
                "analysis_id": row.get("analysis_id"),
                "relationship_reference": row.get("relationship_reference"),
                "lateral_relationship_state": row.get("lateral_relationship_state"),
                "topology_risk": row.get("topology_risk"),
                "spread_potential": row.get("spread_potential"),
                "source_mode": row.get("source_mode"),
            }
            for row in rows
        ],
        "recommended_review": status != "ok",
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def build_lateral_analysis_api(
    *,
    summary: dict[str, Any],
    analyses: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in analyses or [] if isinstance(row, dict)]
    return {
        "record_type": "lateral_analysis_api",
        "status": "review_required" if int(summary.get("suspicious_count") or 0) else "ok",
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "analyses": rows,
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def classify_lateral_relationship(
    relationship: dict[str, Any],
    *,
    topology_risk: float,
    spread_potential: float,
    unusual_peer_detected: bool,
) -> str:
    if relationship.get("source_node_class") == "unknown" or relationship.get("target_node_class") == "unknown":
        return "unknown"
    if relationship.get("target_node_class") == "external" and float(relationship.get("recurring_interaction_score") or 0.0) < 0.25:
        return "isolated"
    if unusual_peer_detected and (topology_risk >= 0.65 or spread_potential >= 0.65 or relationship.get("drift_detected")):
        return "suspicious"
    if unusual_peer_detected or topology_risk >= 0.55:
        return "unusual"
    return "expected"


def detect_unusual_peer(relationship: dict[str, Any]) -> bool:
    source = str(relationship.get("source_node_class") or "unknown")
    target = str(relationship.get("target_node_class") or "unknown")
    state = str(relationship.get("relationship_state") or "unknown")
    if relationship.get("drift_detected"):
        return True
    if source == "worker" and target == "worker" and state in {"active", "recurring"}:
        return True
    if source == "edge" and target == "master" and float(relationship.get("recurring_interaction_score") or 0.0) > 0.75:
        return True
    return False


def score_topology_risk(relationship: dict[str, Any]) -> float:
    source = str(relationship.get("source_node_class") or "unknown")
    target = str(relationship.get("target_node_class") or "unknown")
    distance = int(relationship.get("topology_distance") or 0)
    score = 0.15
    if source == target and source in {"worker", "edge"}:
        score += 0.25
    if source == "worker" and target in {"master", "orchestrator"}:
        score += 0.08
    if target == "external":
        score += 0.12
    if distance > 2:
        score += min(distance * 0.06, 0.3)
    if relationship.get("drift_detected"):
        score += 0.25
    return round(min(1.0, score), 3)


def score_spread_potential(
    relationship: dict[str, Any],
    *,
    topology_risk: float,
    recurrence_score: float,
) -> float:
    score = topology_risk * 0.45 + recurrence_score * 0.35
    if relationship.get("shared_service_state") == "shared":
        score += 0.15
    if relationship.get("relationship_state") == "recurring":
        score += 0.05
    return round(min(1.0, score), 3)


def score_lateral_confidence(
    relationship: dict[str, Any],
    *,
    lateral_relationship_state: str,
    topology_risk: float,
    spread_potential: float,
) -> float:
    score = float(relationship.get("relationship_confidence") or 0.0) * 0.5
    score += topology_risk * 0.2
    score += spread_potential * 0.2
    if lateral_relationship_state in {"expected", "unusual", "suspicious", "isolated"}:
        score += 0.1
    return round(min(1.0, score), 3)


def deterministic_lateral_analysis_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _operator_summary(
    *,
    state: str,
    relationship: dict[str, Any],
    topology_risk: float,
    spread_potential: float,
) -> str:
    if state == "suspicious":
        return "Review unusual cross-node relationship; this is advisory metadata, not a threat verdict."
    if state == "unusual":
        return "Relationship differs from expected topology or recurrence patterns and should be reviewed."
    if state == "isolated":
        return "Relationship appears isolated based on current metadata."
    if state == "expected":
        return "Relationship matches expected metadata patterns."
    return f"Relationship state is unknown with topology risk {topology_risk} and spread potential {spread_potential}."


def _count_state(rows: list[dict[str, Any]], state: str) -> int:
    return sum(1 for row in rows if row.get("lateral_relationship_state") == state)


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
