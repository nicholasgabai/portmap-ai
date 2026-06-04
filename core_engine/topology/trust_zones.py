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


TRUST_ZONE_RECORD_VERSION = 1
TRUST_ZONE_CLASSES = {"internal", "management", "service", "external", "unknown"}


class TrustZoneError(ValueError):
    """Raised when trust-zone inputs are malformed."""


def build_trust_zone_record(
    relationships: Iterable[dict[str, Any]] | None = None,
    *,
    zone_class: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = _normalize_relationships(relationships, generated_at=timestamp)
    normalized_zone = normalize_trust_zone_class(zone_class or _infer_zone_from_relationships(rows))
    confidence = score_trust_zone_confidence(rows, zone_class=normalized_zone)
    record = {
        "record_type": "trust_zone",
        "record_version": TRUST_ZONE_RECORD_VERSION,
        "trust_zone_id": "trust-zone-"
        + _digest(
            {
                "zone_class": normalized_zone,
                "relationships": [row.get("relationship_id") for row in rows],
                "source_modes": sorted({row.get("source_mode") for row in rows}),
            }
        )[:16],
        "generated_at": timestamp,
        "zone_class": normalized_zone,
        "relationship_count": len(rows),
        "confidence_score": confidence,
        "drift_detected": any(bool(row.get("drift_detected")) for row in rows),
        "relationship_references": sorted(str(row.get("relationship_id") or "") for row in rows if row.get("relationship_id")),
        "source_modes": sorted({str(row.get("source_mode") or "unknown") for row in rows}) or ["unknown"],
        "advisory_notes": _zone_advisory_notes(normalized_zone, relationship_count=len(rows)),
        **RELATIONSHIP_SAFETY_FLAGS,
    }
    return record


def infer_trust_zones(
    relationships: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    rows = _normalize_relationships(relationships, generated_at=timestamp)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        zone = classify_relationship_trust_zone(row)
        grouped.setdefault(zone, []).append(row)
    if not grouped:
        grouped["unknown"] = []
    return sorted(
        [
            build_trust_zone_record(zone_rows, zone_class=zone, generated_at=timestamp)
            for zone, zone_rows in grouped.items()
        ],
        key=lambda item: (str(item.get("zone_class") or ""), str(item.get("trust_zone_id") or "")),
    )


def build_trust_zone_summary(
    trust_zones: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in trust_zones or [] if isinstance(row, dict)]
    return {
        "record_type": "trust_zone_summary",
        "record_version": TRUST_ZONE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "zone_count": len(rows),
        "internal_count": _count_zone(rows, "internal"),
        "management_count": _count_zone(rows, "management"),
        "service_count": _count_zone(rows, "service"),
        "external_count": _count_zone(rows, "external"),
        "unknown_count": _count_zone(rows, "unknown"),
        "relationship_count": sum(int(row.get("relationship_count") or 0) for row in rows),
        "drift_detected_count": sum(1 for row in rows if row.get("drift_detected")),
        "average_confidence_score": _average(rows, "confidence_score"),
        "source_modes": sorted({mode for row in rows for mode in row.get("source_modes", ["unknown"])}) or ["unknown"],
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def build_trust_zone_report(
    relationships: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    zones = infer_trust_zones(relationships, generated_at=timestamp)
    summary = build_trust_zone_summary(zones, generated_at=timestamp)
    return {
        "record_type": "trust_zone_report",
        "record_version": TRUST_ZONE_RECORD_VERSION,
        "report_id": "trust-zone-report-"
        + _digest({"generated_at": timestamp, "zones": [row["trust_zone_id"] for row in zones]})[:16],
        "generated_at": timestamp,
        "trust_zones": zones,
        "summary": summary,
        "dashboard_status": build_trust_zone_dashboard(summary=summary, trust_zones=zones, generated_at=timestamp),
        "api_status": build_trust_zone_api(summary=summary, trust_zones=zones, generated_at=timestamp),
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def build_trust_zone_dashboard(
    *,
    summary: dict[str, Any],
    trust_zones: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in trust_zones or [] if isinstance(row, dict)]
    status = "review_required" if int(summary.get("drift_detected_count") or 0) else "ok"
    return {
        "record_type": "trust_zone_dashboard",
        "panel": "network_trust_zones",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "zone_count": int(summary.get("zone_count") or 0),
            "relationship_count": int(summary.get("relationship_count") or 0),
            "average_confidence_score": float(summary.get("average_confidence_score") or 0.0),
        },
        "rows": [
            {
                "trust_zone_id": row.get("trust_zone_id"),
                "zone_class": row.get("zone_class"),
                "relationship_count": row.get("relationship_count"),
                "confidence_score": row.get("confidence_score"),
                "drift_detected": row.get("drift_detected"),
                "source_modes": row.get("source_modes"),
            }
            for row in rows
        ],
        "recommended_review": status != "ok",
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def build_trust_zone_api(
    *,
    summary: dict[str, Any],
    trust_zones: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in trust_zones or [] if isinstance(row, dict)]
    return {
        "record_type": "trust_zone_api",
        "status": "review_required" if int(summary.get("drift_detected_count") or 0) else "ok",
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "trust_zones": rows,
        **RELATIONSHIP_SAFETY_FLAGS,
    }


def classify_relationship_trust_zone(relationship: dict[str, Any]) -> str:
    explicit = normalize_trust_zone_class(relationship.get("zone_class") or relationship.get("trust_zone"))
    if explicit != "unknown":
        return explicit
    source = str(relationship.get("source_node_class") or "unknown")
    target = str(relationship.get("target_node_class") or "unknown")
    relation_type = str(relationship.get("relationship_type") or "").lower()
    shared = str(relationship.get("shared_service_state") or "unknown")
    if target == "external" or source == "external" or "external" in relation_type:
        return "external"
    if source in {"orchestrator", "master"} or target in {"orchestrator", "master"} or any(token in relation_type for token in ("control", "management", "heartbeat")):
        return "management"
    if shared == "shared" or any(token in relation_type for token in ("service", "dependency")):
        return "service"
    if source in {"worker", "edge"} or target in {"worker", "edge"}:
        return "internal"
    return "unknown"


def score_trust_zone_confidence(
    relationships: Iterable[dict[str, Any]],
    *,
    zone_class: str,
) -> float:
    rows = [dict(row) for row in relationships or [] if isinstance(row, dict)]
    if not rows:
        return 0.35 if zone_class == "unknown" else 0.45
    average_relationship_confidence = _average(rows, "relationship_confidence")
    average_relationship_strength = _average(rows, "relationship_strength")
    coverage = min(len(rows) / 5, 0.2)
    known_zone_bonus = 0.08 if zone_class != "unknown" else 0.0
    return round(min(1.0, average_relationship_confidence * 0.45 + average_relationship_strength * 0.25 + coverage + known_zone_bonus), 3)


def normalize_trust_zone_class(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace("-", "_")
    return text if text in TRUST_ZONE_CLASSES else "unknown"


def deterministic_trust_zone_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _normalize_relationships(
    relationships: Iterable[dict[str, Any]] | None,
    *,
    generated_at: str,
) -> list[dict[str, Any]]:
    try:
        rows = [
            dict(row) if row.get("record_type") == "cross_node_relationship" else build_node_relationship_record(row, generated_at=generated_at)
            for row in relationships or []
            if isinstance(row, dict)
        ]
    except TypeError as exc:
        raise TrustZoneError("relationships must be iterable") from exc
    for row in rows:
        row["source_mode"] = normalize_source_mode(row.get("source_mode"))
    return sorted(rows, key=lambda item: str(item.get("relationship_id") or ""))


def _infer_zone_from_relationships(relationships: list[dict[str, Any]]) -> str:
    if not relationships:
        return "unknown"
    counts: dict[str, int] = {}
    for row in relationships:
        zone = classify_relationship_trust_zone(row)
        counts[zone] = counts.get(zone, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _zone_advisory_notes(zone_class: str, *, relationship_count: int) -> list[str]:
    return [
        f"{zone_class} trust zone inferred from {relationship_count} relationship records",
        "metadata-only topology intelligence; no scanning, payload inspection, or enforcement",
    ]


def _count_zone(rows: list[dict[str, Any]], zone_class: str) -> int:
    return sum(1 for row in rows if row.get("zone_class") == zone_class)


def _average(rows: list[dict[str, Any]], field_name: str) -> float:
    if not rows:
        return 0.0
    return round(sum(float(row.get(field_name) or 0.0) for row in rows) / len(rows), 3)


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
