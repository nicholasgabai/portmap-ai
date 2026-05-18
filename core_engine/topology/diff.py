from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.topology.drift import build_drift_report
from core_engine.topology.snapshots import SAFETY_FLAGS, validate_topology_snapshot


def compare_topology_snapshots(
    baseline: dict[str, Any],
    current: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    baseline_validation = validate_topology_snapshot(baseline)
    current_validation = validate_topology_snapshot(current)
    errors = [f"baseline: {error}" for error in baseline_validation["errors"]]
    errors.extend(f"current: {error}" for error in current_validation["errors"])
    if errors:
        return build_drift_report(
            baseline,
            current,
            [],
            generated_at=generated_at,
            errors=errors,
            status="invalid",
        )

    drifts: list[dict[str, Any]] = []
    drifts.extend(compare_asset_drift(_assets(baseline), _assets(current), baseline_ref=_snapshot_ref(baseline), current_ref=_snapshot_ref(current)))
    drifts.extend(compare_service_drift(_services(baseline), _services(current), baseline_ref=_snapshot_ref(baseline), current_ref=_snapshot_ref(current)))
    drifts.extend(compare_topology_edge_drift(_edges(baseline), _edges(current), baseline_ref=_snapshot_ref(baseline), current_ref=_snapshot_ref(current)))
    drifts.extend(compare_finding_drift(_findings(baseline), _findings(current), baseline_ref=_snapshot_ref(baseline), current_ref=_snapshot_ref(current)))
    return build_drift_report(baseline, current, drifts, generated_at=generated_at)


def compare_asset_drift(
    baseline_assets: Iterable[dict[str, Any]],
    current_assets: Iterable[dict[str, Any]],
    *,
    baseline_ref: str = "baseline",
    current_ref: str = "current",
) -> list[dict[str, Any]]:
    baseline = _index(_rows(baseline_assets), _asset_key)
    current = _index(_rows(current_assets), _asset_key)
    drifts: list[dict[str, Any]] = []
    for key in sorted(set(current) - set(baseline)):
        drifts.append(_drift("asset_added", "asset", "medium", key, "Asset added", f"Asset {key} appears in the current topology snapshot.", current[key], baseline_ref, current_ref))
    for key in sorted(set(baseline) - set(current)):
        drifts.append(_drift("asset_removed", "asset", "low", key, "Asset removed", f"Asset {key} was present in the baseline topology snapshot.", baseline[key], baseline_ref, current_ref))
    for key in sorted(set(baseline) & set(current)):
        before = baseline[key]
        after = current[key]
        if _first(before, "label") != _first(after, "label"):
            drifts.append(_drift("asset_label_changed", "asset", "low", key, "Asset label changed", f"Asset {key} label changed.", {"before": _first(before, "label"), "after": _first(after, "label")}, baseline_ref, current_ref))
        if _first(before, "category") != _first(after, "category"):
            drifts.append(_drift("asset_category_changed", "asset", "medium", key, "Asset category changed", f"Asset {key} category changed.", {"before": _first(before, "category"), "after": _first(after, "category")}, baseline_ref, current_ref))
        confidence = min(_confidence(before), _confidence(after))
        if 0 < confidence < 0.5:
            drifts.append(_drift("asset_low_confidence_match", "asset", "low", key, "Low confidence asset match", f"Asset {key} matched with low confidence.", {"confidence": confidence}, baseline_ref, current_ref, confidence=confidence))
    return drifts


def compare_service_drift(
    baseline_services: Iterable[dict[str, Any]],
    current_services: Iterable[dict[str, Any]],
    *,
    baseline_ref: str = "baseline",
    current_ref: str = "current",
) -> list[dict[str, Any]]:
    baseline = _index(_rows(baseline_services), _service_key)
    current = _index(_rows(current_services), _service_key)
    drifts: list[dict[str, Any]] = []
    for key in sorted(set(current) - set(baseline)):
        drifts.append(_drift("service_added", "service", "medium", key, "Service added", f"Service {key} appears in the current topology snapshot.", current[key], baseline_ref, current_ref))
    for key in sorted(set(baseline) - set(current)):
        drifts.append(_drift("service_removed", "service", "low", key, "Service removed", f"Service {key} was present in the baseline topology snapshot.", baseline[key], baseline_ref, current_ref))
    for key in sorted(set(baseline) & set(current)):
        before = _service_label(baseline[key])
        after = _service_label(current[key])
        if before != after:
            drifts.append(_drift("service_label_changed", "service", "medium", key, "Service label changed", f"Service {key} changed label from {before} to {after}.", {"before": before, "after": after}, baseline_ref, current_ref))
    return drifts


def compare_topology_edge_drift(
    baseline_edges: Iterable[dict[str, Any]],
    current_edges: Iterable[dict[str, Any]],
    *,
    baseline_ref: str = "baseline",
    current_ref: str = "current",
) -> list[dict[str, Any]]:
    baseline = _index(_rows(baseline_edges), _edge_key)
    current = _index(_rows(current_edges), _edge_key)
    drifts: list[dict[str, Any]] = []
    for key in sorted(set(current) - set(baseline)):
        drifts.append(_drift("topology_edge_added", "topology", "medium", key, "Topology edge added", f"Topology edge {key} appears in the current topology snapshot.", current[key], baseline_ref, current_ref))
    for key in sorted(set(baseline) - set(current)):
        drifts.append(_drift("topology_edge_removed", "topology", "low", key, "Topology edge removed", f"Topology edge {key} was present in the baseline topology snapshot.", baseline[key], baseline_ref, current_ref))
    for key in sorted(set(baseline) & set(current)):
        before_count = int(baseline[key].get("observation_count") or 0)
        after_count = int(current[key].get("observation_count") or 0)
        if before_count != after_count:
            drifts.append(_drift("topology_edge_observation_changed", "topology", "low", key, "Topology edge observation count changed", f"Topology edge {key} observation count changed.", {"before": before_count, "after": after_count}, baseline_ref, current_ref))
    return drifts


def compare_finding_drift(
    baseline_findings: Iterable[dict[str, Any]],
    current_findings: Iterable[dict[str, Any]],
    *,
    baseline_ref: str = "baseline",
    current_ref: str = "current",
) -> list[dict[str, Any]]:
    baseline = _index(_rows(baseline_findings), _finding_key)
    current = _index(_rows(current_findings), _finding_key)
    drifts: list[dict[str, Any]] = []
    for key in sorted(set(current) - set(baseline)):
        drifts.append(_drift("finding_added", "finding", _severity(current[key]), key, "Finding added", f"Finding {key} appears in the current topology snapshot.", current[key], baseline_ref, current_ref))
    for key in sorted(set(baseline) - set(current)):
        drifts.append(_drift("finding_removed", "finding", "low", key, "Finding removed", f"Finding {key} was present in the baseline topology snapshot.", baseline[key], baseline_ref, current_ref))
    baseline_categories = _categories(baseline.values())
    current_categories = _categories(current.values())
    for category, rows in sorted(current_categories.items()):
        if len(rows) > 1:
            drifts.append(_drift("finding_category_repeated", "finding", _highest_severity(rows), category, "Finding category repeated", f"Finding category {category} appears {len(rows)} times in the current topology snapshot.", {"count": len(rows), "category": category}, baseline_ref, current_ref))
        before = _highest_severity(baseline_categories.get(category, []))
        after = _highest_severity(rows)
        if _severity_rank(after) > _severity_rank(before) and before != "info":
            drifts.append(_drift("finding_severity_increased", "finding", after, category, "Finding severity increased", f"Finding category {category} severity increased from {before} to {after}.", {"before": before, "after": after, "category": category}, baseline_ref, current_ref))
    return drifts


def _assets(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    topology = snapshot.get("topology") if isinstance(snapshot.get("topology"), dict) else {}
    return _rows(topology.get("nodes"))


def _services(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    explicit = _rows(snapshot.get("services"))
    topology = snapshot.get("topology") if isinstance(snapshot.get("topology"), dict) else {}
    explicit.extend(_rows(topology.get("services")))
    if explicit:
        return explicit
    services: list[dict[str, Any]] = []
    for node in _rows(topology.get("nodes")):
        count = int(node.get("service_count") or 0)
        if count:
            services.append(
                {
                    "asset_id": node.get("asset_id"),
                    "service_name": f"service-count:{count}",
                    "port": 0,
                    "confidence": node.get("confidence"),
                    "source_refs": node.get("source_refs") or [],
                }
            )
    return services


def _edges(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    topology = snapshot.get("topology") if isinstance(snapshot.get("topology"), dict) else {}
    return _rows(topology.get("edges"))


def _findings(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    return _rows(snapshot.get("findings"))


def _drift(
    drift_type: str,
    category: str,
    severity: str,
    target: str,
    title: str,
    summary: str,
    evidence: dict[str, Any],
    baseline_ref: str,
    current_ref: str,
    *,
    confidence: float | None = None,
) -> dict[str, Any]:
    source_refs = sorted(set(_source_refs(evidence) + [baseline_ref, current_ref]))
    evidence_refs = sorted({target, *_source_refs(evidence)})
    payload = {
        "drift_id": _stable_id("drift", drift_type, target, evidence, baseline_ref, current_ref),
        "drift_type": drift_type,
        "category": category,
        "severity": severity if severity in _SEVERITY_ORDER else "info",
        "title": title,
        "summary": summary,
        "target": target,
        "baseline_ref": baseline_ref,
        "current_ref": current_ref,
        "evidence": _public_evidence(evidence),
        "evidence_refs": evidence_refs,
        "source_refs": source_refs,
        "recommended_review": severity in {"medium", "high", "critical"},
        **SAFETY_FLAGS,
    }
    if confidence is not None:
        payload["confidence"] = round(confidence, 3)
    return payload


def _public_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in evidence.items() if not str(key).startswith("_")}


def _snapshot_ref(snapshot: dict[str, Any]) -> str:
    return f"snapshot:{snapshot.get('snapshot_id') or 'unknown'}"


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _index(rows: list[dict[str, Any]], key_fn) -> dict[str, dict[str, Any]]:
    return {key_fn(row): row for row in rows}


def _asset_key(row: dict[str, Any]) -> str:
    return _first(row, "asset_id", "node_id", "label") or "asset-unknown"


def _service_key(row: dict[str, Any]) -> str:
    asset = _first(row, "asset_id", "target", "host", "service_id") or "asset-unknown"
    port = str(row.get("port") if row.get("port") not in (None, "") else "0")
    return f"{asset}:{port}"


def _edge_key(row: dict[str, Any]) -> str:
    src = _first(row, "source_asset", "src", "source", "from") or "source-unknown"
    dst = _first(row, "target_asset", "dst", "target", "to") or "target-unknown"
    relation = _first(row, "relationship_type", "type", "protocol_service_label", "protocol") or "relationship"
    label = _first(row, "protocol_service_label", "service_label", "service", "protocol")
    return f"{src}>{dst}:{relation}:{label}"


def _finding_key(row: dict[str, Any]) -> str:
    return _first(row, "finding_id", "finding_type", "category", "summary") or "finding-unknown"


def _service_label(row: dict[str, Any]) -> str:
    return _first(row, "service", "service_name", "label", "protocol_service_label")


def _categories(rows: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        category = _first(row, "category", "finding_type", "type", "title") or "finding"
        grouped.setdefault(category, []).append(row)
    return grouped


def _highest_severity(rows: Iterable[dict[str, Any]]) -> str:
    severities = [_severity(row) for row in rows]
    if not severities:
        return "info"
    return max(severities, key=_severity_rank)


def _severity(row: dict[str, Any]) -> str:
    value = str(row.get("severity") or "info")
    return value if value in _SEVERITY_ORDER else "info"


def _severity_rank(value: str) -> int:
    return _SEVERITY_ORDER.get(value, 0)


def _confidence(row: dict[str, Any]) -> float:
    try:
        return min(max(float(row.get("confidence") or 0.0), 0.0), 1.0)
    except (TypeError, ValueError):
        return 0.0


def _source_refs(row: dict[str, Any]) -> list[str]:
    refs = row.get("source_refs")
    if isinstance(refs, list):
        return [str(ref) for ref in refs if ref]
    source_ref = row.get("source_ref")
    return [str(source_ref)] if source_ref else []


def _first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
