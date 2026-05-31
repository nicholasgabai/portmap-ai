from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.export.node_manifest import digest_payload
from core_engine.history.baseline_decay import BASELINE_DECAY_SAFETY_FLAGS


RELATIONSHIP_HISTORY_RECORD_VERSION = 1
DEFAULT_MAX_RELATIONSHIP_HISTORY = 500
DEFAULT_STABLE_RECURRENCE_THRESHOLD = 3

RELATIONSHIP_HISTORY_SAFETY_FLAGS = {
    **BASELINE_DECAY_SAFETY_FLAGS,
    "relationship_history_only": True,
    "metadata_only": True,
    "local_first": True,
    "bounded_retention": True,
    "advisory_only": True,
    "dry_run_safe": True,
    "payload_bytes_stored": 0,
    "credentials_stored": False,
    "external_services_used": False,
    "automatic_enforcement": False,
    "firewall_changes": False,
}


def build_relationship_history_records(
    topology_records: Iterable[dict[str, Any]] | None = None,
    *,
    previous_relationships: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_relationships: int = DEFAULT_MAX_RELATIONSHIP_HISTORY,
    stable_recurrence_threshold: int = DEFAULT_STABLE_RECURRENCE_THRESHOLD,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    current_edges = _collect_edges(topology_records, generated_at=timestamp)
    previous = {str(row.get("relationship_key") or ""): dict(row) for row in _rows(previous_relationships) if row.get("relationship_key")}
    grouped: dict[str, list[dict[str, Any]]] = {}
    malformed: list[dict[str, Any]] = []
    for edge in current_edges:
        if edge.get("malformed"):
            malformed.append(_malformed_relationship(edge, generated_at=timestamp))
            continue
        grouped.setdefault(str(edge["relationship_key"]), []).append(edge)
    records = [
        _build_relationship_record(
            relationship_key=key,
            edges=edges,
            previous=previous.get(key),
            generated_at=timestamp,
            stable_recurrence_threshold=stable_recurrence_threshold,
        )
        for key, edges in grouped.items()
    ]
    for key, previous_row in previous.items():
        if key not in grouped:
            records.append(_build_dormant_relationship(previous_row, generated_at=timestamp))
    records.extend(malformed)
    records = sorted(records, key=lambda item: (str(item.get("source_asset") or ""), str(item.get("target_asset") or ""), str(item.get("protocol") or "")))
    dropped = max(0, len(records) - int(max_relationships))
    selected = records[: max(0, int(max_relationships))]
    for row in selected:
        row["bounded_retention_applied"] = dropped > 0
        row["dropped_relationship_count"] = dropped
    return selected


def summarize_relationship_history(records: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = _rows(records)
    valid = [row for row in rows if row.get("classification") != "malformed"]
    return {
        "record_type": "relationship_history_summary",
        "record_version": RELATIONSHIP_HISTORY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "relationship_count": len(rows),
        "valid_relationship_count": len(valid),
        "malformed_relationship_count": len(rows) - len(valid),
        "stable_relationship_count": sum(1 for row in valid if row.get("stable_relationship")),
        "transient_relationship_count": sum(1 for row in valid if row.get("transient_relationship")),
        "dormant_relationship_count": sum(1 for row in valid if row.get("dormant_relationship")),
        "dormant_return_count": sum(1 for row in valid if row.get("dormant_returned")),
        "average_confidence": _average(valid, "confidence"),
        "average_maturity_score": _average(valid, "topology_maturity_score"),
        "by_classification": _count_by(valid, "classification"),
        "by_protocol": _count_by(valid, "protocol"),
        **RELATIONSHIP_HISTORY_SAFETY_FLAGS,
    }


def score_relationship_confidence(
    *,
    observation_count: int,
    recurrence_count: int,
    source_count: int,
    previous_confidence: float = 0.0,
) -> float:
    observation_score = min(0.35, int(observation_count) * 0.08)
    recurrence_score = min(0.3, int(recurrence_count) * 0.1)
    source_score = min(0.15, int(source_count) * 0.05)
    previous_score = min(0.15, max(0.0, float(previous_confidence)) * 0.15)
    return round(min(1.0, 0.1 + observation_score + recurrence_score + source_score + previous_score), 3)


def score_topology_maturity(
    *,
    recurrence_count: int,
    age_days: int,
    stable_recurrence_threshold: int = DEFAULT_STABLE_RECURRENCE_THRESHOLD,
) -> float:
    recurrence_score = min(0.6, int(recurrence_count) / max(1, int(stable_recurrence_threshold)) * 0.6)
    age_score = min(0.3, int(age_days) / 30 * 0.3)
    return round(min(1.0, recurrence_score + age_score + 0.1), 3)


def deterministic_relationship_history_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _collect_edges(topology_records: Iterable[dict[str, Any]] | None, *, generated_at: str) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for topology in _rows(topology_records):
        observed_at = str(topology.get("generated_at") or topology.get("snapshot_timestamp") or generated_at)
        source_ref = str(topology.get("topology_update", {}).get("update_digest") if isinstance(topology.get("topology_update"), dict) else topology.get("snapshot_id") or topology.get("report_id") or "")
        raw_edges = []
        if isinstance(topology.get("graph"), dict):
            raw_edges.extend(_rows(topology["graph"].get("edges")))
        raw_edges.extend(_rows(topology.get("topology_edges")))
        raw_edges.extend(_rows(topology.get("edges")))
        if not raw_edges and topology.get("record_type"):
            edges.append({"malformed": True, "error": "topology record contains no edges", "source_ref": source_ref})
        for edge in raw_edges:
            edges.append(_normalize_edge(edge, observed_at=observed_at, source_ref=source_ref))
    return edges


def _normalize_edge(edge: dict[str, Any], *, observed_at: str, source_ref: str) -> dict[str, Any]:
    source = str(edge.get("source_asset") or edge.get("src") or "")
    target = str(edge.get("target_asset") or edge.get("dst") or "")
    relationship_type = str(edge.get("relationship_type") or "observed_flow")
    protocol = str(edge.get("protocol_service_label") or edge.get("protocol") or "unknown")
    if not source or not target:
        return {"malformed": True, "error": "edge requires source and target", "source_ref": source_ref}
    key = _relationship_key(source=source, target=target, relationship_type=relationship_type, protocol=protocol)
    refs = sorted({str(ref) for ref in edge.get("source_refs") or [] if ref} | ({source_ref} if source_ref else set()))
    return {
        "relationship_key": key,
        "source_asset": source,
        "target_asset": target,
        "relationship_type": relationship_type,
        "protocol": protocol,
        "observed_at": observed_at,
        "observation_count": int(edge.get("observation_count") or edge.get("flow_count") or 1),
        "byte_count": int(edge.get("byte_count") or 0),
        "confidence": float(edge.get("confidence") or 0.0),
        "source_refs": refs,
        "source_node_ids": sorted(str(node) for node in edge.get("source_node_ids") or [] if node),
        "edge_id": str(edge.get("edge_id") or "edge-" + _digest(key)[:16]),
    }


def _build_relationship_record(
    *,
    relationship_key: str,
    edges: list[dict[str, Any]],
    previous: dict[str, Any] | None,
    generated_at: str,
    stable_recurrence_threshold: int,
) -> dict[str, Any]:
    rows = sorted(edges, key=lambda item: str(item.get("observed_at") or ""))
    first_seen_values = [str(row.get("observed_at") or "") for row in rows if row.get("observed_at")]
    if (previous or {}).get("first_seen"):
        first_seen_values.append(str((previous or {}).get("first_seen")))
    first_seen = min(first_seen_values) if first_seen_values else generated_at
    last_seen = max(str(row.get("observed_at") or "") for row in rows)
    previous_recurrence = int((previous or {}).get("recurrence_count") or 0)
    recurrence_count = previous_recurrence + len({str(row.get("observed_at") or "") for row in rows if row.get("observed_at")})
    observation_count = sum(int(row.get("observation_count") or 0) for row in rows) + int((previous or {}).get("observation_count") or 0)
    age_days = _days_between(first_seen, generated_at)
    maturity = score_topology_maturity(recurrence_count=recurrence_count, age_days=age_days, stable_recurrence_threshold=stable_recurrence_threshold)
    source_refs = sorted({str(ref) for row in rows for ref in row.get("source_refs") or [] if ref} | {str(ref) for ref in (previous or {}).get("source_refs") or [] if ref})
    confidence = score_relationship_confidence(
        observation_count=observation_count,
        recurrence_count=recurrence_count,
        source_count=len(source_refs),
        previous_confidence=float((previous or {}).get("confidence") or 0.0),
    )
    previous_dormant = bool((previous or {}).get("dormant_relationship") or (previous or {}).get("classification") == "dormant")
    stable = recurrence_count >= int(stable_recurrence_threshold) and maturity >= 0.75
    classification = "dormant_returned" if previous_dormant else "stable" if stable else "transient"
    row0 = rows[0]
    record = {
        "record_type": "long_term_topology_relationship",
        "record_version": RELATIONSHIP_HISTORY_RECORD_VERSION,
        "generated_at": generated_at,
        "relationship_key": relationship_key,
        "source_asset": str(row0.get("source_asset") or ""),
        "target_asset": str(row0.get("target_asset") or ""),
        "relationship_type": str(row0.get("relationship_type") or "observed_flow"),
        "protocol": str(row0.get("protocol") or "unknown"),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "observation_count": observation_count,
        "recurrence_count": recurrence_count,
        "seen_in_snapshot_count": len({str(row.get("observed_at") or "") for row in rows if row.get("observed_at")}),
        "source_refs": source_refs,
        "source_node_ids": sorted({str(node) for row in rows for node in row.get("source_node_ids") or [] if node}),
        "edge_refs": sorted({str(row.get("edge_id") or "") for row in rows if row.get("edge_id")}),
        "classification": classification,
        "stable_relationship": classification == "stable",
        "transient_relationship": classification == "transient",
        "dormant_relationship": False,
        "dormant_returned": classification == "dormant_returned",
        "topology_maturity_score": maturity,
        "confidence": confidence,
        "bounded_retention_applied": False,
        "dropped_relationship_count": 0,
        **RELATIONSHIP_HISTORY_SAFETY_FLAGS,
    }
    record["relationship_id"] = "topology-relationship-" + _digest({"relationship_key": relationship_key})[:16]
    return record


def _build_dormant_relationship(previous: dict[str, Any], *, generated_at: str) -> dict[str, Any]:
    record = {
        **dict(previous),
        "record_type": "long_term_topology_relationship",
        "record_version": RELATIONSHIP_HISTORY_RECORD_VERSION,
        "generated_at": generated_at,
        "classification": "dormant",
        "stable_relationship": False,
        "transient_relationship": False,
        "dormant_relationship": True,
        "dormant_returned": False,
        "confidence": round(max(0.1, float(previous.get("confidence") or 0.2) * 0.5), 3),
        **RELATIONSHIP_HISTORY_SAFETY_FLAGS,
    }
    record["relationship_id"] = str(previous.get("relationship_id") or "topology-relationship-" + _digest(record.get("relationship_key"))[:16])
    return record


def _malformed_relationship(edge: dict[str, Any], *, generated_at: str) -> dict[str, Any]:
    record = {
        "record_type": "long_term_topology_relationship",
        "record_version": RELATIONSHIP_HISTORY_RECORD_VERSION,
        "generated_at": generated_at,
        "relationship_key": "",
        "source_asset": "",
        "target_asset": "",
        "relationship_type": "unknown",
        "protocol": "unknown",
        "classification": "malformed",
        "stable_relationship": False,
        "transient_relationship": False,
        "dormant_relationship": False,
        "dormant_returned": False,
        "confidence": 0.0,
        "topology_maturity_score": 0.0,
        "errors": [str(edge.get("error") or "malformed relationship input")],
        "raw_record_stored": False,
        "source_refs": sorted({str(edge.get("source_ref") or "")} - {""}),
        **RELATIONSHIP_HISTORY_SAFETY_FLAGS,
    }
    record["relationship_id"] = "topology-relationship-malformed-" + _digest(edge)[:16]
    return record


def _relationship_key(*, source: str, target: str, relationship_type: str, protocol: str) -> str:
    return "|".join([str(source), str(target), str(relationship_type), str(protocol)])


def _days_between(start: str, end: str) -> int:
    start_dt = _parse_time(start)
    end_dt = _parse_time(end)
    if not start_dt or not end_dt:
        return 0
    return max(0, int((end_dt - start_dt).total_seconds() // 86400))


def _parse_time(value: str) -> datetime | None:
    text = str(value or "")
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _average(rows: list[dict[str, Any]], key: str) -> float:
    values = [float(row.get(key) or 0.0) for row in rows]
    return round(sum(values) / len(values), 3) if values else 0.0


def _count_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
