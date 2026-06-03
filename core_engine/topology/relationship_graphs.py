from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.process_attribution import normalize_source_mode
from core_engine.topology.node_merge import SAFETY_FLAGS


NODE_RELATIONSHIP_RECORD_VERSION = 1
NODE_CLASSES = {"orchestrator", "master", "worker", "edge", "external", "unknown"}
RELATIONSHIP_STATES = {"active", "recurring", "transient", "dormant", "unknown"}
RELATIONSHIP_SAFETY_FLAGS = {
    **SAFETY_FLAGS,
    "metadata_only": True,
    "raw_packet_stored": False,
    "packet_payload_inspected": False,
    "pcap_generated": False,
    "graph_db_dependency": False,
    "credential_material_stored": False,
    "enforcement_enabled": False,
}


class RelationshipGraphError(ValueError):
    """Raised when cross-node relationship graph inputs are malformed."""


def build_node_relationship_record(
    relationship: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(relationship, dict):
        raise RelationshipGraphError("relationship must be an object")
    timestamp = generated_at or _now()
    source_class = normalize_node_class(
        relationship.get("source_node_class")
        or relationship.get("source_class")
        or relationship.get("source_role")
    )
    target_class = normalize_node_class(
        relationship.get("target_node_class")
        or relationship.get("target_class")
        or relationship.get("target_role")
    )
    relationship_type = _safe_token(
        relationship.get("relationship_type")
        or relationship.get("type")
        or _infer_relationship_type(relationship)
    )
    flow_ref = str(
        relationship.get("flow_reference")
        or relationship.get("flow_ref")
        or relationship.get("flow_pair_id")
        or ""
    )
    session_ref = str(
        relationship.get("session_reference")
        or relationship.get("session_ref")
        or relationship.get("session_id")
        or ""
    )
    recurring_score = score_recurring_interaction(relationship)
    topology_distance = normalize_topology_distance(relationship.get("topology_distance"))
    state = classify_relationship_state(relationship, recurring_interaction_score=recurring_score)
    strength = score_relationship_strength(
        relationship,
        recurring_interaction_score=recurring_score,
        topology_distance=topology_distance,
        relationship_state=state,
    )
    confidence = score_relationship_confidence(
        relationship,
        source_node_class=source_class,
        target_node_class=target_class,
        relationship_strength=strength,
        topology_distance=topology_distance,
    )
    mode = normalize_source_mode(
        relationship.get("source_mode")
        or relationship.get("data_source")
        or "unknown"
    )
    record = {
        "record_type": "cross_node_relationship",
        "record_version": NODE_RELATIONSHIP_RECORD_VERSION,
        "relationship_id": "",
        "generated_at": timestamp,
        "source_node_class": source_class,
        "target_node_class": target_class,
        "relationship_type": relationship_type,
        "relationship_state": state,
        "flow_reference": flow_ref,
        "session_reference": session_ref,
        "shared_service_state": normalize_shared_service_state(
            relationship.get("shared_service_state")
            or relationship.get("service_state")
            or relationship.get("service_attribution")
        ),
        "recurring_interaction_score": recurring_score,
        "topology_distance": topology_distance,
        "relationship_strength": strength,
        "relationship_confidence": confidence,
        "drift_detected": bool(relationship.get("drift_detected")),
        "source_mode": mode,
        "data_source": mode,
        "source_node_reference": str(relationship.get("source_node_reference") or ""),
        "target_node_reference": str(relationship.get("target_node_reference") or ""),
        "advisory_notes": _advisory_notes(
            state=state,
            source_node_class=source_class,
            target_node_class=target_class,
            relationship_type=relationship_type,
        ),
        **RELATIONSHIP_SAFETY_FLAGS,
    }
    record["relationship_id"] = "node-rel-" + _digest(
        {
            "source_node_class": record["source_node_class"],
            "target_node_class": record["target_node_class"],
            "relationship_type": record["relationship_type"],
            "flow_reference": record["flow_reference"],
            "session_reference": record["session_reference"],
            "shared_service_state": record["shared_service_state"],
            "source_mode": record["source_mode"],
        }
    )[:16]
    return record


def build_node_relationship_graph(
    relationships: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
    label: str = "cross-node-relationship-graph",
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    try:
        rows = [
            build_node_relationship_record(row, generated_at=timestamp)
            for row in relationships or []
            if isinstance(row, dict)
        ]
    except TypeError as exc:
        raise RelationshipGraphError("relationships must be iterable") from exc
    deduped = dedupe_relationship_records(rows)
    summary = summarize_node_relationships(deduped, generated_at=timestamp)
    return {
        "record_type": "cross_node_relationship_graph",
        "record_version": NODE_RELATIONSHIP_RECORD_VERSION,
        "graph_id": "relationship-graph-"
        + _digest({"label": label, "generated_at": timestamp, "relationships": [row["relationship_id"] for row in deduped]})[:16],
        "label": str(label or "cross-node-relationship-graph"),
        "generated_at": timestamp,
        "relationships": deduped,
        "summary": summary,
        "dashboard_status": build_relationship_graph_dashboard(summary=summary, relationships=deduped, generated_at=timestamp),
        "api_status": build_relationship_graph_api(summary=summary, relationships=deduped, generated_at=timestamp),
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def dedupe_relationship_records(relationships: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in relationships or []:
        if not isinstance(row, dict):
            continue
        existing = grouped.get(str(row.get("relationship_id") or ""))
        if existing is None:
            grouped[str(row.get("relationship_id") or "")] = dict(row)
            continue
        merged = dict(existing)
        merged["recurring_interaction_score"] = max(
            float(existing.get("recurring_interaction_score") or 0.0),
            float(row.get("recurring_interaction_score") or 0.0),
        )
        merged["relationship_strength"] = max(
            float(existing.get("relationship_strength") or 0.0),
            float(row.get("relationship_strength") or 0.0),
        )
        merged["relationship_confidence"] = max(
            float(existing.get("relationship_confidence") or 0.0),
            float(row.get("relationship_confidence") or 0.0),
        )
        merged["drift_detected"] = bool(existing.get("drift_detected") or row.get("drift_detected"))
        grouped[str(row.get("relationship_id") or "")] = merged
    return sorted(grouped.values(), key=lambda item: str(item.get("relationship_id") or ""))


def summarize_node_relationships(
    relationships: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in relationships or [] if isinstance(row, dict)]
    return {
        "record_type": "cross_node_relationship_summary",
        "record_version": NODE_RELATIONSHIP_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "relationship_count": len(rows),
        "active_count": _count_state(rows, "active"),
        "recurring_count": _count_state(rows, "recurring"),
        "transient_count": _count_state(rows, "transient"),
        "dormant_count": _count_state(rows, "dormant"),
        "unknown_count": _count_state(rows, "unknown"),
        "shared_service_count": sum(1 for row in rows if row.get("shared_service_state") == "shared"),
        "drift_detected_count": sum(1 for row in rows if row.get("drift_detected")),
        "average_relationship_strength": _average(rows, "relationship_strength"),
        "average_relationship_confidence": _average(rows, "relationship_confidence"),
        "source_node_classes": sorted({str(row.get("source_node_class") or "unknown") for row in rows}) or ["unknown"],
        "target_node_classes": sorted({str(row.get("target_node_class") or "unknown") for row in rows}) or ["unknown"],
        "source_modes": sorted({str(row.get("source_mode") or "unknown") for row in rows}) or ["unknown"],
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def build_relationship_graph_dashboard(
    *,
    summary: dict[str, Any],
    relationships: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in relationships or [] if isinstance(row, dict)]
    status = "review_required" if int(summary.get("drift_detected_count") or 0) else "ok"
    return {
        "record_type": "cross_node_relationship_dashboard",
        "panel": "cross_node_relationships",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "relationship_count": int(summary.get("relationship_count") or 0),
            "recurring_count": int(summary.get("recurring_count") or 0),
            "shared_service_count": int(summary.get("shared_service_count") or 0),
            "average_relationship_strength": float(summary.get("average_relationship_strength") or 0.0),
        },
        "rows": [
            {
                "relationship_id": row.get("relationship_id"),
                "source_node_class": row.get("source_node_class"),
                "target_node_class": row.get("target_node_class"),
                "relationship_state": row.get("relationship_state"),
                "relationship_strength": row.get("relationship_strength"),
                "source_mode": row.get("source_mode"),
            }
            for row in rows
        ],
        "recommended_review": status != "ok",
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def build_relationship_graph_api(
    *,
    summary: dict[str, Any],
    relationships: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in relationships or [] if isinstance(row, dict)]
    return {
        "record_type": "cross_node_relationship_api",
        "status": "ok",
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "relationships": rows,
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def classify_relationship_state(
    relationship: dict[str, Any],
    *,
    recurring_interaction_score: float | None = None,
) -> str:
    explicit = str(relationship.get("relationship_state") or relationship.get("state") or "").strip().lower()
    if explicit in RELATIONSHIP_STATES:
        return explicit
    score = recurring_interaction_score if recurring_interaction_score is not None else score_recurring_interaction(relationship)
    transport_state = str(relationship.get("transport_state") or relationship.get("status") or "").lower()
    if transport_state in {"closed", "time_wait", "dormant"}:
        return "dormant"
    if score >= 0.65:
        return "recurring"
    if transport_state in {"established", "listen", "listening", "active"}:
        return "active"
    if int(relationship.get("observation_count") or 0) == 1:
        return "transient"
    return "unknown"


def score_recurring_interaction(relationship: dict[str, Any]) -> float:
    if relationship.get("recurring_interaction_score") not in {None, ""}:
        return _clamp(relationship.get("recurring_interaction_score"))
    score = 0.0
    count = int(relationship.get("observation_count") or relationship.get("flow_count") or 1)
    score += min(count / 6, 0.5)
    if relationship.get("session_classification") == "recurring" or relationship.get("relationship_state") == "recurring":
        score += 0.25
    if relationship.get("shared_service_state") in {"shared", "same_service"} or relationship.get("service_attribution") not in {None, "", "Unknown", "Unattributed"}:
        score += 0.15
    if relationship.get("drift_detected"):
        score += 0.1
    return round(min(1.0, score), 3)


def normalize_topology_distance(value: Any) -> int:
    try:
        distance = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, min(distance, 12))


def score_relationship_strength(
    relationship: dict[str, Any],
    *,
    recurring_interaction_score: float,
    topology_distance: int,
    relationship_state: str,
) -> float:
    score = 0.2
    score += min(recurring_interaction_score * 0.35, 0.35)
    if relationship.get("flow_reference") or relationship.get("flow_ref") or relationship.get("flow_pair_id"):
        score += 0.12
    if relationship.get("session_reference") or relationship.get("session_ref") or relationship.get("session_id"):
        score += 0.12
    if normalize_shared_service_state(relationship.get("shared_service_state") or relationship.get("service_attribution")) == "shared":
        score += 0.12
    if topology_distance == 1:
        score += 0.12
    elif topology_distance > 1:
        score += max(0.0, 0.1 - topology_distance * 0.015)
    if relationship_state == "recurring":
        score += 0.08
    return round(min(1.0, score), 3)


def score_relationship_confidence(
    relationship: dict[str, Any],
    *,
    source_node_class: str,
    target_node_class: str,
    relationship_strength: float,
    topology_distance: int,
) -> float:
    score = min(float(relationship_strength) * 0.65, 0.65)
    if source_node_class != "unknown":
        score += 0.08
    if target_node_class != "unknown":
        score += 0.08
    if topology_distance >= 0:
        score += 0.06
    if relationship.get("flow_reference") or relationship.get("flow_ref") or relationship.get("flow_pair_id"):
        score += 0.06
    if relationship.get("session_reference") or relationship.get("session_ref") or relationship.get("session_id"):
        score += 0.06
    return round(min(1.0, score), 3)


def normalize_node_class(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace("-", "_")
    return text if text in NODE_CLASSES else "unknown"


def normalize_shared_service_state(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    if text in {"shared", "same_service", "common_service"}:
        return "shared"
    if text in {"not_shared", "different", "none"}:
        return "not_shared"
    if text in {"unknown", ""}:
        return "unknown"
    return "shared"


def deterministic_relationship_graph_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _infer_relationship_type(relationship: dict[str, Any]) -> str:
    source = normalize_node_class(relationship.get("source_node_class") or relationship.get("source_role"))
    target = normalize_node_class(relationship.get("target_node_class") or relationship.get("target_role"))
    if source == "master" and target == "worker":
        return "master_worker_runtime"
    if source == "orchestrator" and target in {"master", "worker"}:
        return "orchestrator_control_plane"
    if target == "external":
        return "external_service_adjacency"
    return "peer_relationship"


def _advisory_notes(
    *,
    state: str,
    source_node_class: str,
    target_node_class: str,
    relationship_type: str,
) -> list[str]:
    return [
        f"{source_node_class} to {target_node_class} relationship is {state}",
        f"relationship type is {relationship_type}",
        "metadata-only relationship record; no payload inspection, packet storage, or graph database dependency",
    ]


def _count_state(rows: list[dict[str, Any]], state: str) -> int:
    return sum(1 for row in rows if row.get("relationship_state") == state)


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


def _safe_token(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace(" ", "_").replace("-", "_")
    return text[:80] if text else "unknown"


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
