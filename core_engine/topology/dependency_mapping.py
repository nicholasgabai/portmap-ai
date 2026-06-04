from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.topology.relationship_graphs import (
    RELATIONSHIP_SAFETY_FLAGS,
    build_node_relationship_record,
    normalize_source_mode,
)


DEPENDENCY_RECORD_VERSION = 1
DEPENDENCY_TYPES = {
    "service_dependency",
    "communication_chain",
    "node_dependency",
    "topology_adjacency",
    "management_dependency",
    "external_dependency",
    "unknown",
}


class DependencyMappingError(ValueError):
    """Raised when dependency mapping inputs are malformed."""


def build_dependency_record(
    relationship: dict[str, Any],
    *,
    dependency_type: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(relationship, dict):
        raise DependencyMappingError("relationship must be an object")
    timestamp = generated_at or _now()
    row = relationship if relationship.get("record_type") == "cross_node_relationship" else build_node_relationship_record(relationship, generated_at=timestamp)
    normalized_type = normalize_dependency_type(dependency_type or row.get("dependency_type") or _infer_dependency_type(row))
    strength = score_dependency_relationship_strength(row, dependency_type=normalized_type)
    recurrence = _clamp(row.get("recurring_interaction_score"))
    confidence = score_dependency_confidence(
        row,
        dependency_type=normalized_type,
        relationship_strength=strength,
        recurrence_score=recurrence,
    )
    distance = int(row.get("topology_distance") or 0)
    mode = normalize_source_mode(row.get("source_mode") or row.get("data_source") or "unknown")
    return {
        "record_type": "topology_dependency",
        "record_version": DEPENDENCY_RECORD_VERSION,
        "dependency_id": "dependency-"
        + _digest(
            {
                "relationship_reference": row.get("relationship_id"),
                "dependency_type": normalized_type,
                "source_mode": mode,
            }
        )[:16],
        "generated_at": timestamp,
        "dependency_type": normalized_type,
        "relationship_reference": str(row.get("relationship_id") or ""),
        "source_node_class": str(row.get("source_node_class") or "unknown"),
        "target_node_class": str(row.get("target_node_class") or "unknown"),
        "flow_reference": str(row.get("flow_reference") or ""),
        "session_reference": str(row.get("session_reference") or ""),
        "relationship_strength": strength,
        "recurrence_score": recurrence,
        "confidence_score": confidence,
        "topology_distance": distance,
        "topology_adjacency": distance <= 1 and distance >= 0,
        "drift_detected": bool(row.get("drift_detected")),
        "source_mode": mode,
        "data_source": mode,
        "advisory_notes": _dependency_advisory_notes(normalized_type, topology_distance=distance),
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def build_dependency_map(
    relationships: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    try:
        dependencies = [
            build_dependency_record(row, generated_at=timestamp)
            for row in relationships or []
            if isinstance(row, dict)
        ]
    except TypeError as exc:
        raise DependencyMappingError("relationships must be iterable") from exc
    dependencies = sorted(dependencies, key=lambda item: str(item.get("dependency_id") or ""))
    summary = summarize_dependencies(dependencies, generated_at=timestamp)
    return {
        "record_type": "topology_dependency_map",
        "record_version": DEPENDENCY_RECORD_VERSION,
        "dependency_map_id": "dependency-map-"
        + _digest({"generated_at": timestamp, "dependencies": [row["dependency_id"] for row in dependencies]})[:16],
        "generated_at": timestamp,
        "dependencies": dependencies,
        "summary": summary,
        "dashboard_status": build_dependency_dashboard(summary=summary, dependencies=dependencies, generated_at=timestamp),
        "api_status": build_dependency_api(summary=summary, dependencies=dependencies, generated_at=timestamp),
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def summarize_dependencies(
    dependencies: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in dependencies or [] if isinstance(row, dict)]
    return {
        "record_type": "topology_dependency_summary",
        "record_version": DEPENDENCY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "dependency_count": len(rows),
        "service_dependency_count": _count_type(rows, "service_dependency"),
        "communication_chain_count": _count_type(rows, "communication_chain"),
        "node_dependency_count": _count_type(rows, "node_dependency"),
        "topology_adjacency_count": sum(1 for row in rows if row.get("topology_adjacency")),
        "management_dependency_count": _count_type(rows, "management_dependency"),
        "external_dependency_count": _count_type(rows, "external_dependency"),
        "unknown_count": _count_type(rows, "unknown"),
        "drift_detected_count": sum(1 for row in rows if row.get("drift_detected")),
        "average_relationship_strength": _average(rows, "relationship_strength"),
        "average_recurrence_score": _average(rows, "recurrence_score"),
        "average_confidence_score": _average(rows, "confidence_score"),
        "source_modes": sorted({str(row.get("source_mode") or "unknown") for row in rows}) or ["unknown"],
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def build_dependency_dashboard(
    *,
    summary: dict[str, Any],
    dependencies: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in dependencies or [] if isinstance(row, dict)]
    status = "review_required" if int(summary.get("drift_detected_count") or 0) else "ok"
    return {
        "record_type": "topology_dependency_dashboard",
        "panel": "network_dependencies",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "dependency_count": int(summary.get("dependency_count") or 0),
            "topology_adjacency_count": int(summary.get("topology_adjacency_count") or 0),
            "average_relationship_strength": float(summary.get("average_relationship_strength") or 0.0),
            "average_confidence_score": float(summary.get("average_confidence_score") or 0.0),
        },
        "rows": [
            {
                "dependency_id": row.get("dependency_id"),
                "dependency_type": row.get("dependency_type"),
                "relationship_strength": row.get("relationship_strength"),
                "recurrence_score": row.get("recurrence_score"),
                "confidence_score": row.get("confidence_score"),
                "topology_distance": row.get("topology_distance"),
                "source_mode": row.get("source_mode"),
            }
            for row in rows
        ],
        "recommended_review": status != "ok",
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def build_dependency_api(
    *,
    summary: dict[str, Any],
    dependencies: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in dependencies or [] if isinstance(row, dict)]
    return {
        "record_type": "topology_dependency_api",
        "status": "review_required" if int(summary.get("drift_detected_count") or 0) else "ok",
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "dependencies": rows,
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def score_dependency_relationship_strength(
    relationship: dict[str, Any],
    *,
    dependency_type: str,
) -> float:
    score = float(relationship.get("relationship_strength") or 0.0) * 0.55
    score += float(relationship.get("recurring_interaction_score") or 0.0) * 0.25
    if dependency_type in {"service_dependency", "communication_chain"}:
        score += 0.08
    if int(relationship.get("topology_distance") or 0) <= 1:
        score += 0.08
    if relationship.get("drift_detected"):
        score += 0.04
    return round(min(1.0, score), 3)


def score_dependency_confidence(
    relationship: dict[str, Any],
    *,
    dependency_type: str,
    relationship_strength: float,
    recurrence_score: float,
) -> float:
    score = float(relationship.get("relationship_confidence") or 0.0) * 0.45
    score += relationship_strength * 0.25
    score += recurrence_score * 0.15
    if dependency_type != "unknown":
        score += 0.1
    if relationship.get("flow_reference") or relationship.get("session_reference"):
        score += 0.05
    return round(min(1.0, score), 3)


def normalize_dependency_type(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace("-", "_")
    return text if text in DEPENDENCY_TYPES else "unknown"


def deterministic_dependency_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _infer_dependency_type(relationship: dict[str, Any]) -> str:
    source = str(relationship.get("source_node_class") or "unknown")
    target = str(relationship.get("target_node_class") or "unknown")
    relation_type = str(relationship.get("relationship_type") or "").lower()
    shared = str(relationship.get("shared_service_state") or "unknown")
    distance = int(relationship.get("topology_distance") or 0)
    if target == "external" or source == "external":
        return "external_dependency"
    if source in {"orchestrator", "master"} or target in {"orchestrator", "master"} or any(token in relation_type for token in ("control", "management", "heartbeat")):
        return "management_dependency"
    if shared == "shared" or "service" in relation_type:
        return "service_dependency"
    if float(relationship.get("recurring_interaction_score") or 0.0) >= 0.65:
        return "communication_chain"
    if distance <= 1 and source != "unknown" and target != "unknown":
        return "topology_adjacency"
    if source != "unknown" or target != "unknown":
        return "node_dependency"
    return "unknown"


def _dependency_advisory_notes(dependency_type: str, *, topology_distance: int) -> list[str]:
    return [
        f"{dependency_type} inferred with topology distance {topology_distance}",
        "metadata-only dependency record; no payload inspection, active probing, graph database, or enforcement",
    ]


def _count_type(rows: list[dict[str, Any]], dependency_type: str) -> int:
    return sum(1 for row in rows if row.get("dependency_type") == dependency_type)


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
