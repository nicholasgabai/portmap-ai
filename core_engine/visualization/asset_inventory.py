from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Iterable

from core_engine.visualization.asset_roles import (
    build_role_evidence,
    classify_asset_role,
    normalize_asset_role,
    score_asset_role_confidence,
)
from core_engine.visualization.timeline_models import sanitize_reference, sanitize_references, sanitize_summary
from core_engine.visualization.topology_models import (
    TOPOLOGY_VISUAL_SAFETY_FLAGS,
    clamp_score,
    normalize_source_mode,
    now_timestamp,
)


ASSET_INVENTORY_RECORD_VERSION = 1
ASSET_STATES = {"active", "new", "recurring", "dormant", "stale", "unknown"}
ASSET_INVENTORY_SAFETY_FLAGS = {
    **TOPOLOGY_VISUAL_SAFETY_FLAGS,
    "inventory_database_written": False,
    "export_safe": True,
    "bounded": True,
    "preview_only": True,
    "destructive_action": False,
    "raw_dns_history_stored": False,
}
DEFAULT_MAX_ASSETS = 256


class AssetInventoryError(ValueError):
    """Raised when visual asset inventory inputs are malformed."""


@dataclass(frozen=True)
class AssetInventoryRecord:
    asset_id: str
    asset_label: str
    asset_role: str
    asset_state: str
    confidence_score: float
    first_seen: str
    last_seen: str
    observed_service_count: int = 0
    observed_flow_count: int = 0
    related_node_references: list[str] = field(default_factory=list)
    related_flow_references: list[str] = field(default_factory=list)
    related_timeline_references: list[str] = field(default_factory=list)
    source_modes: list[str] = field(default_factory=list)
    role_evidence: dict[str, Any] = field(default_factory=dict)
    risk_summary: dict[str, Any] = field(default_factory=dict)
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "visual_asset_inventory_record",
            "record_version": ASSET_INVENTORY_RECORD_VERSION,
            "asset_id": sanitize_reference(self.asset_id),
            "asset_label": sanitize_summary(self.asset_label),
            "asset_role": normalize_asset_role(self.asset_role),
            "asset_state": normalize_asset_state(self.asset_state),
            "confidence_score": clamp_score(self.confidence_score),
            "first_seen": str(self.first_seen or ""),
            "last_seen": str(self.last_seen or ""),
            "observed_service_count": max(0, int(self.observed_service_count or 0)),
            "observed_flow_count": max(0, int(self.observed_flow_count or 0)),
            "related_node_references": sanitize_references(self.related_node_references),
            "related_flow_references": sanitize_references(self.related_flow_references),
            "related_timeline_references": sanitize_references(self.related_timeline_references),
            "source_modes": sorted({normalize_source_mode(mode) for mode in self.source_modes}) or ["unknown"],
            "role_evidence": dict(self.role_evidence),
            "risk_summary": dict(self.risk_summary),
            "advisory_notes": [sanitize_summary(note) for note in self.advisory_notes],
            **ASSET_INVENTORY_SAFETY_FLAGS,
        }


@dataclass(frozen=True)
class AssetInventorySummary:
    inventory_id: str
    asset_count: int
    role_counts: dict[str, int]
    state_counts: dict[str, int]
    confidence_summary: dict[str, float]
    assets: list[AssetInventoryRecord] = field(default_factory=list)
    bounded: bool = True
    max_assets: int = DEFAULT_MAX_ASSETS
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        rows = [asset.to_dict() for asset in self.assets]
        return {
            "record_type": "visual_asset_inventory_summary",
            "record_version": ASSET_INVENTORY_RECORD_VERSION,
            "inventory_id": sanitize_reference(self.inventory_id),
            "asset_count": max(0, int(self.asset_count or 0)),
            "role_counts": dict(self.role_counts),
            "state_counts": dict(self.state_counts),
            "confidence_summary": dict(self.confidence_summary),
            "assets": rows,
            "bounded": True,
            "max_assets": max(0, int(self.max_assets or 0)),
            "export_safe": True,
            **ASSET_INVENTORY_SAFETY_FLAGS,
        }


def build_asset_inventory_record(
    asset: dict[str, Any],
    *,
    related_flows: Iterable[dict[str, Any]] | None = None,
    related_timeline_events: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> AssetInventoryRecord:
    if not isinstance(asset, dict):
        raise AssetInventoryError("asset must be an object")
    timestamp = generated_at or now_timestamp()
    flows = [dict(row) for row in related_flows or [] if isinstance(row, dict)]
    timeline = [dict(row) for row in related_timeline_events or [] if isinstance(row, dict)]
    role = classify_asset_role(asset)
    source_modes = _source_modes(asset, flows=flows, timeline=timeline)
    related_node_refs = sanitize_references([asset.get("node_id"), asset.get("asset_id"), asset.get("asset_reference")])
    related_flow_refs = sanitize_references([flow.get("flow_reference") or flow.get("flow_id") or flow.get("session_id") for flow in flows])
    related_timeline_refs = sanitize_references([event.get("event_id") for event in timeline])
    first_seen = _min_timestamp([asset.get("first_seen"), asset.get("timestamp"), *(flow.get("first_seen") or flow.get("timestamp") for flow in flows), *(event.get("timestamp") for event in timeline)], fallback=timestamp)
    last_seen = _max_timestamp([asset.get("last_seen"), asset.get("timestamp"), *(flow.get("last_seen") or flow.get("timestamp") for flow in flows), *(event.get("timestamp") for event in timeline)], fallback=timestamp)
    service_count = _service_count(asset, flows)
    flow_count = len(related_flow_refs)
    state = infer_asset_state(asset, flow_count=flow_count, timeline_count=len(related_timeline_refs))
    role_confidence = score_asset_role_confidence(asset, role=role)
    confidence = score_inventory_confidence(asset, role_confidence=role_confidence, flow_count=flow_count, service_count=service_count, timeline_count=len(related_timeline_refs))
    asset_id = "visual-asset-" + _digest(
        {
            "refs": related_node_refs,
            "role": role,
            "source_modes": source_modes,
            "class": asset.get("node_class") or asset.get("endpoint_class") or asset.get("asset_category"),
        }
    )[:16]
    return AssetInventoryRecord(
        asset_id=asset_id,
        asset_label=_asset_label(role, asset),
        asset_role=role,
        asset_state=state,
        confidence_score=confidence,
        first_seen=first_seen,
        last_seen=last_seen,
        observed_service_count=service_count,
        observed_flow_count=flow_count,
        related_node_references=related_node_refs,
        related_flow_references=related_flow_refs,
        related_timeline_references=related_timeline_refs,
        source_modes=source_modes,
        role_evidence=build_role_evidence(asset, role=role),
        risk_summary=_risk_summary(asset, flows=flows, timeline=timeline),
        advisory_notes=_advisory_notes(role=role, state=state, source_modes=source_modes),
    )


def build_asset_inventory(
    *,
    topology_nodes: Iterable[dict[str, Any]] | None = None,
    flows: Iterable[dict[str, Any]] | None = None,
    services: Iterable[dict[str, Any]] | None = None,
    timeline_events: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_assets: int = DEFAULT_MAX_ASSETS,
) -> AssetInventorySummary:
    if topology_nodes is not None and not _is_iterable(topology_nodes):
        raise AssetInventoryError("topology_nodes must be iterable")
    if flows is not None and not _is_iterable(flows):
        raise AssetInventoryError("flows must be iterable")
    if services is not None and not _is_iterable(services):
        raise AssetInventoryError("services must be iterable")
    if timeline_events is not None and not _is_iterable(timeline_events):
        raise AssetInventoryError("timeline_events must be iterable")
    timestamp = generated_at or now_timestamp()
    flow_rows = [dict(row) for row in flows or [] if isinstance(row, dict)]
    service_rows = [dict(row) for row in services or [] if isinstance(row, dict)]
    timeline_rows = [dict(row) for row in timeline_events or [] if isinstance(row, dict)]
    asset_seeds = [dict(row) for row in topology_nodes or [] if isinstance(row, dict)]
    asset_seeds.extend(_asset_seeds_from_flows(flow_rows))
    asset_seeds.extend(_asset_seeds_from_services(service_rows))
    records = [
        build_asset_inventory_record(
            seed,
            related_flows=_matching_flows(seed, flow_rows),
            related_timeline_events=_matching_timeline_events(seed, timeline_rows),
            generated_at=timestamp,
        )
        for seed in asset_seeds
    ]
    deduped = deduplicate_assets(records)
    bounded = deduped[: max(0, int(max_assets))]
    return summarize_asset_inventory(bounded, generated_at=timestamp, max_assets=max_assets)


def deduplicate_assets(records: Iterable[AssetInventoryRecord]) -> list[AssetInventoryRecord]:
    grouped: dict[str, AssetInventoryRecord] = {}
    for record in records or []:
        if not isinstance(record, AssetInventoryRecord):
            continue
        existing = grouped.get(record.asset_id)
        if existing is None:
            grouped[record.asset_id] = record
            continue
        grouped[record.asset_id] = _merge_asset_records(existing, record)
    return sorted(grouped.values(), key=lambda item: item.asset_id)


def summarize_asset_inventory(
    assets: Iterable[AssetInventoryRecord],
    *,
    generated_at: str | None = None,
    max_assets: int = DEFAULT_MAX_ASSETS,
) -> AssetInventorySummary:
    rows = [asset for asset in assets or [] if isinstance(asset, AssetInventoryRecord)]
    role_counts = Counter(asset.asset_role for asset in rows)
    state_counts = Counter(asset.asset_state for asset in rows)
    confidence_values = [asset.confidence_score for asset in rows]
    confidence_summary = {
        "min": clamp_score(min(confidence_values) if confidence_values else 0.0),
        "max": clamp_score(max(confidence_values) if confidence_values else 0.0),
        "average": clamp_score(sum(confidence_values) / len(confidence_values) if confidence_values else 0.0),
    }
    timestamp = generated_at or now_timestamp()
    return AssetInventorySummary(
        inventory_id="visual-inventory-" + _digest({"generated_at": timestamp, "assets": [asset.asset_id for asset in rows], "max_assets": max_assets})[:16],
        asset_count=len(rows),
        role_counts={key: int(role_counts[key]) for key in sorted(role_counts)},
        state_counts={key: int(state_counts[key]) for key in sorted(state_counts)},
        confidence_summary=confidence_summary,
        assets=rows,
        bounded=True,
        max_assets=max_assets,
        export_safe=True,
    )


def empty_asset_inventory(*, generated_at: str | None = None, max_assets: int = DEFAULT_MAX_ASSETS) -> AssetInventorySummary:
    return summarize_asset_inventory([], generated_at=generated_at or now_timestamp(), max_assets=max_assets)


def deterministic_asset_inventory_json(record: AssetInventorySummary | AssetInventoryRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, (AssetInventorySummary, AssetInventoryRecord)) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def infer_asset_state(asset: dict[str, Any], *, flow_count: int = 0, timeline_count: int = 0) -> str:
    explicit = normalize_asset_state(asset.get("asset_state") or asset.get("state"))
    if explicit != "unknown":
        return explicit
    observation_count = int(asset.get("observation_count") or 0)
    if str(asset.get("status") or "").lower() in {"missing", "offline", "stale"}:
        return "stale"
    if str(asset.get("session_state") or "").lower() == "dormant":
        return "dormant"
    if observation_count >= 3 or flow_count >= 2 or timeline_count >= 3:
        return "recurring"
    if observation_count == 1 or flow_count == 1 or timeline_count == 1:
        return "new"
    if asset.get("last_seen"):
        return "active"
    return "unknown"


def normalize_asset_state(value: Any) -> str:
    state = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return state if state in ASSET_STATES else "unknown"


def score_inventory_confidence(asset: dict[str, Any], *, role_confidence: float, flow_count: int, service_count: int, timeline_count: int) -> float:
    score = role_confidence * 0.55
    if asset.get("node_id") or asset.get("asset_id") or asset.get("asset_reference"):
        score += 0.12
    score += min(0.12, flow_count * 0.04)
    score += min(0.1, service_count * 0.04)
    score += min(0.08, timeline_count * 0.02)
    if asset.get("first_seen") or asset.get("last_seen"):
        score += 0.06
    return clamp_score(score)


def _asset_seeds_from_flows(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seeds = []
    for flow in flows:
        base = {
            "source_mode": flow.get("source_mode") or flow.get("data_source"),
            "first_seen": flow.get("first_seen") or flow.get("timestamp"),
            "last_seen": flow.get("last_seen") or flow.get("timestamp"),
            "service_hint": flow.get("service_hint") or flow.get("service"),
            "flow_direction": flow.get("flow_direction") or flow.get("direction"),
            "observation_count": flow.get("observation_count") or 1,
        }
        seeds.append({**base, "node_id": flow.get("local_node_id") or flow.get("source_node_id") or "local-flow-node", "endpoint_class": flow.get("local_endpoint_class") or "unknown", "local_port": flow.get("local_port")})
        if flow.get("remote_endpoint_class") or flow.get("target_node_id") or flow.get("remote_node_id"):
            seeds.append({**base, "node_id": flow.get("remote_node_id") or flow.get("target_node_id") or "remote-flow-node", "endpoint_class": flow.get("remote_endpoint_class") or "unknown", "remote_port": flow.get("remote_port")})
    return seeds


def _asset_seeds_from_services(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "node_id": row.get("node_id") or row.get("asset_reference") or "service-node",
            "endpoint_class": row.get("endpoint_class") or row.get("node_class") or "unknown",
            "service_hint": row.get("service_hint") or row.get("service_name") or row.get("service"),
            "local_port": row.get("port") or row.get("local_port"),
            "source_mode": row.get("source_mode") or row.get("data_source"),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
        }
        for row in services
    ]


def _matching_flows(seed: dict[str, Any], flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    node_ref = sanitize_reference(seed.get("node_id") or seed.get("asset_id") or seed.get("asset_reference"))
    endpoint = str(seed.get("endpoint_class") or "").lower()
    matches = []
    for flow in flows:
        refs = {
            sanitize_reference(flow.get("local_node_id")),
            sanitize_reference(flow.get("source_node_id")),
            sanitize_reference(flow.get("remote_node_id")),
            sanitize_reference(flow.get("target_node_id")),
        }
        classes = {str(flow.get("local_endpoint_class") or "").lower(), str(flow.get("remote_endpoint_class") or "").lower()}
        if node_ref and node_ref in refs:
            matches.append(flow)
        elif endpoint and endpoint in classes:
            matches.append(flow)
    return matches


def _matching_timeline_events(seed: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    refs = {
        sanitize_reference(seed.get("node_id")),
        sanitize_reference(seed.get("asset_id")),
        sanitize_reference(seed.get("asset_reference")),
    }
    return [
        event
        for event in events
        if refs
        and (
            sanitize_reference(event.get("source_reference")) in refs
            or sanitize_reference(event.get("target_reference")) in refs
            or bool(refs & set(event.get("related_asset_references") or []))
        )
    ]


def _merge_asset_records(left: AssetInventoryRecord, right: AssetInventoryRecord) -> AssetInventoryRecord:
    return AssetInventoryRecord(
        asset_id=left.asset_id,
        asset_label=left.asset_label,
        asset_role=left.asset_role if left.asset_role != "unknown" else right.asset_role,
        asset_state=_preferred_state(left.asset_state, right.asset_state),
        confidence_score=max(left.confidence_score, right.confidence_score),
        first_seen=min(left.first_seen, right.first_seen),
        last_seen=max(left.last_seen, right.last_seen),
        observed_service_count=max(left.observed_service_count, right.observed_service_count),
        observed_flow_count=max(left.observed_flow_count, right.observed_flow_count),
        related_node_references=sorted(set(left.related_node_references + right.related_node_references)),
        related_flow_references=sorted(set(left.related_flow_references + right.related_flow_references)),
        related_timeline_references=sorted(set(left.related_timeline_references + right.related_timeline_references)),
        source_modes=sorted(set(left.source_modes + right.source_modes)),
        role_evidence=left.role_evidence if left.confidence_score >= right.confidence_score else right.role_evidence,
        risk_summary=_merge_risk(left.risk_summary, right.risk_summary),
        advisory_notes=sorted(set(left.advisory_notes + right.advisory_notes)),
    )


def _source_modes(asset: dict[str, Any], *, flows: list[dict[str, Any]], timeline: list[dict[str, Any]]) -> list[str]:
    modes = [asset.get("source_mode") or asset.get("data_source")]
    modes.extend(flow.get("source_mode") or flow.get("data_source") for flow in flows)
    modes.extend(event.get("source_mode") or event.get("data_source") for event in timeline)
    return sorted({normalize_source_mode(mode) for mode in modes if mode}) or ["unknown"]


def _service_count(asset: dict[str, Any], flows: list[dict[str, Any]]) -> int:
    services = {sanitize_reference(asset.get("service_hint") or asset.get("service") or asset.get("service_attribution"))}
    services.update(sanitize_reference(flow.get("service_hint") or flow.get("service") or flow.get("service_attribution")) for flow in flows)
    return len({service for service in services if service})


def _risk_summary(asset: dict[str, Any], *, flows: list[dict[str, Any]], timeline: list[dict[str, Any]]) -> dict[str, Any]:
    risk_scores = [_safe_float(asset.get("risk_score"))]
    risk_scores.extend(_safe_float(flow.get("risk_score")) for flow in flows)
    severity_values = [str(event.get("severity_level") or "").lower() for event in timeline]
    max_risk = clamp_score(max(risk_scores) if risk_scores else 0.0)
    return {
        "max_risk_score": max_risk,
        "severity_levels": sorted({value for value in severity_values if value}) or ["info"],
        "recommended_review": max_risk >= 0.6 or any(value in {"high", "critical"} for value in severity_values),
        "preview_only": True,
        "destructive_action": False,
    }


def _merge_risk(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    severities = set(left.get("severity_levels") or []) | set(right.get("severity_levels") or [])
    return {
        "max_risk_score": clamp_score(max(_safe_float(left.get("max_risk_score")), _safe_float(right.get("max_risk_score")))),
        "severity_levels": sorted(severities) or ["info"],
        "recommended_review": bool(left.get("recommended_review") or right.get("recommended_review")),
        "preview_only": True,
        "destructive_action": False,
    }


def _asset_label(role: str, asset: dict[str, Any]) -> str:
    endpoint = str(asset.get("endpoint_class") or asset.get("node_class") or "unknown").lower().replace("-", "_")
    return sanitize_summary(f"{normalize_asset_role(role)} asset ({endpoint})")


def _advisory_notes(*, role: str, state: str, source_modes: list[str]) -> list[str]:
    notes = ["visual asset inventory record uses sanitized metadata only", f"source modes: {', '.join(source_modes)}"]
    if role == "unknown":
        notes.append("role inference is unavailable or low confidence")
    if state in {"stale", "dormant", "unknown"}:
        notes.append(f"asset state is {state}")
    return notes


def _preferred_state(left: str, right: str) -> str:
    order = {"active": 5, "recurring": 4, "new": 3, "dormant": 2, "stale": 1, "unknown": 0}
    return left if order.get(left, 0) >= order.get(right, 0) else right


def _min_timestamp(values: Iterable[Any], *, fallback: str) -> str:
    valid = sorted(str(value) for value in values if value)
    return valid[0] if valid else fallback


def _max_timestamp(values: Iterable[Any], *, fallback: str) -> str:
    valid = sorted(str(value) for value in values if value)
    return valid[-1] if valid else fallback


def _digest(value: Any) -> str:
    return sha256(str(value).encode("utf-8")).hexdigest()


def _is_iterable(value: Any) -> bool:
    try:
        iter(value)
    except TypeError:
        return False
    return not isinstance(value, (str, bytes))


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
