from __future__ import annotations

from hashlib import sha256
from typing import Any, Iterable

from core_engine.correlation.scoring import (
    SEVERITY_ORDER,
    assign_advisory_severity,
    highest_severity,
    score_delta_finding,
    summarize_delta_scores,
)


def compare_baselines(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    findings.extend(compare_asset_sets(baseline.get("assets"), current.get("assets")))
    findings.extend(compare_service_sets(baseline.get("services"), current.get("services")))
    findings.extend(compare_topology_sets(baseline.get("topology_edges"), current.get("topology_edges")))
    findings.extend(compare_finding_sets(baseline.get("findings"), current.get("findings")))
    scored = [_with_score(finding) for finding in findings]
    return {
        "status": "ok",
        "baseline_id": baseline.get("baseline_id", ""),
        "current_baseline_id": current.get("baseline_id", ""),
        "finding_count": len(scored),
        "findings": sorted(scored, key=lambda item: (SEVERITY_ORDER.get(item["severity"], 0), item["finding_id"]), reverse=True),
        "summary": summarize_delta_scores(scored),
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
        "local_only": True,
    }


def compare_asset_sets(baseline_assets: Iterable[dict[str, Any]] | None, current_assets: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    baseline = _index(_rows(baseline_assets), _asset_key)
    current = _index(_rows(current_assets), _asset_key)
    findings: list[dict[str, Any]] = []
    for key in sorted(set(current) - set(baseline)):
        findings.append(_finding(
            "new_asset_observed",
            "medium",
            "New asset observed",
            f"Asset {key} appears in the current baseline window.",
            [key],
            _source_refs(current[key]),
            confidence=_confidence(current[key]),
        ))
    for key in sorted(set(baseline) - set(current)):
        findings.append(_finding(
            "asset_missing_from_current_window",
            "low",
            "Asset missing from current window",
            f"Asset {key} was present in the baseline window but is not present in the current window.",
            [key],
            _source_refs(baseline[key]),
            confidence=_confidence(baseline[key]),
        ))
    for key in sorted(set(baseline) & set(current)):
        confidence = min(_confidence(baseline[key]), _confidence(current[key]))
        if 0 < confidence < 0.5:
            findings.append(_finding(
                "low_confidence_identity_match",
                "low",
                "Low confidence identity match",
                f"Asset {key} matched across windows with low identity confidence.",
                [key],
                sorted(set(_source_refs(baseline[key])) | set(_source_refs(current[key]))),
                confidence=confidence,
            ))
    return findings


def compare_service_sets(
    baseline_services: Iterable[dict[str, Any]] | None,
    current_services: Iterable[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    baseline = _index(_rows(baseline_services), _service_key)
    current = _index(_rows(current_services), _service_key)
    findings: list[dict[str, Any]] = []
    for key in sorted(set(current) - set(baseline)):
        findings.append(_finding(
            "new_service_observed",
            "medium",
            "New service observed",
            f"Service {key} appears in the current baseline window.",
            [key],
            _source_refs(current[key]),
            confidence=_confidence(current[key]),
        ))
    for key in sorted(set(baseline) - set(current)):
        findings.append(_finding(
            "service_missing_from_current_window",
            "low",
            "Service missing from current window",
            f"Service {key} was present in the baseline window but is not present in the current window.",
            [key],
            _source_refs(baseline[key]),
            confidence=_confidence(baseline[key]),
        ))
    for key in sorted(set(baseline) & set(current)):
        before = _service_label(baseline[key])
        after = _service_label(current[key])
        if before and after and before != after:
            findings.append(_finding(
                "service_label_changed",
                "medium",
                "Service label changed",
                f"Service {key} changed label from {before} to {after}.",
                [key],
                sorted(set(_source_refs(baseline[key])) | set(_source_refs(current[key]))),
                confidence=max(_confidence(baseline[key]), _confidence(current[key])),
            ))
    return findings


def compare_topology_sets(
    baseline_edges: Iterable[dict[str, Any]] | None,
    current_edges: Iterable[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    baseline = _index(_rows(baseline_edges), _topology_key)
    current = _index(_rows(current_edges), _topology_key)
    findings: list[dict[str, Any]] = []
    for key in sorted(set(current) - set(baseline)):
        findings.append(_finding(
            "topology_relationship_added",
            "medium",
            "Topology relationship added",
            f"Topology relationship {key} appears in the current baseline window.",
            [key],
            _source_refs(current[key]),
            confidence=_confidence(current[key]),
        ))
    for key in sorted(set(baseline) - set(current)):
        findings.append(_finding(
            "topology_relationship_removed",
            "low",
            "Topology relationship removed",
            f"Topology relationship {key} was present in the baseline window but is not present in the current window.",
            [key],
            _source_refs(baseline[key]),
            confidence=_confidence(baseline[key]),
        ))
    return findings


def compare_finding_sets(
    baseline_findings: Iterable[dict[str, Any]] | None,
    current_findings: Iterable[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    baseline_categories = _categories(_rows(baseline_findings))
    current_categories = _categories(_rows(current_findings))
    findings: list[dict[str, Any]] = []
    for category, rows in sorted(current_categories.items()):
        if len(rows) > 1:
            findings.append(_finding(
                "repeated_finding_category",
                highest_severity(_severity(row) for row in rows),
                "Repeated finding category",
                f"Finding category {category} appears {len(rows)} times in the current baseline window.",
                [category],
                sorted({ref for row in rows for ref in _source_refs(row)}),
            ))
        before = highest_severity(_severity(row) for row in baseline_categories.get(category, []))
        after = highest_severity(_severity(row) for row in rows)
        if SEVERITY_ORDER[after] > SEVERITY_ORDER[before] and before != "info":
            findings.append(_finding(
                "severity_increase_observed",
                after,
                "Severity increase observed",
                f"Finding category {category} increased from {before} to {after}.",
                [category],
                sorted({ref for row in rows for ref in _source_refs(row)}),
            ))
    return findings


def _with_score(finding: dict[str, Any]) -> dict[str, Any]:
    item = dict(finding)
    score = score_delta_finding(item)
    item["score"] = score
    item["severity"] = assign_advisory_severity(score)
    return item


def _finding(
    finding_type: str,
    severity: str,
    title: str,
    summary: str,
    evidence_refs: list[str],
    source_refs: list[str],
    *,
    confidence: float | None = None,
) -> dict[str, Any]:
    material = "|".join([finding_type, summary, ",".join(sorted(evidence_refs)), ",".join(sorted(source_refs))])
    payload = {
        "finding_id": "delta-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        "finding_type": finding_type,
        "severity": severity,
        "score": 0.0,
        "title": title,
        "summary": summary,
        "evidence_refs": sorted(evidence_refs),
        "recommended_review": True,
        "source_refs": sorted(source_refs),
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }
    if confidence is not None:
        payload["confidence"] = round(confidence, 3)
    return payload


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _index(rows: list[dict[str, Any]], key_fn) -> dict[str, dict[str, Any]]:
    return {key_fn(row): row for row in rows}


def _asset_key(row: dict[str, Any]) -> str:
    return _first(row, "correlation_key", "asset_id", "host", "label", "node_id") or "asset-unknown"


def _service_key(row: dict[str, Any]) -> str:
    if row.get("correlation_key"):
        return str(row["correlation_key"])
    target = _first(row, "asset_id", "target", "host", "service_id") or "target-unknown"
    port = str(row.get("port") or "0")
    return f"{target}:{port}"


def _topology_key(row: dict[str, Any]) -> str:
    if row.get("correlation_key"):
        return str(row["correlation_key"])
    source = _first(row, "source_asset", "src", "source", "from") or "source-unknown"
    target = _first(row, "target_asset", "dst", "target", "to") or "target-unknown"
    relation = _first(row, "relationship_type", "type", "protocol") or "relationship"
    return f"{source}>{target}:{relation}"


def _service_label(row: dict[str, Any]) -> str:
    return _first(row, "service", "service_name", "label")


def _categories(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        category = _first(row, "category", "finding_type", "type", "title") or "finding"
        grouped.setdefault(category, []).append(row)
    return grouped


def _severity(row: dict[str, Any]) -> str:
    value = str(row.get("severity") or "info")
    return value if value in SEVERITY_ORDER else "info"


def _source_refs(row: dict[str, Any]) -> list[str]:
    refs = row.get("source_refs")
    if isinstance(refs, list):
        return [str(ref) for ref in refs if ref]
    source_ref = row.get("source_ref")
    return [str(source_ref)] if source_ref else []


def _confidence(row: dict[str, Any]) -> float:
    identity = row.get("identity") if isinstance(row.get("identity"), dict) else {}
    value = row.get("confidence", identity.get("confidence", 0.0))
    try:
        return min(max(float(value or 0.0), 0.0), 1.0)
    except (TypeError, ValueError):
        return 0.0


def _first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return ""
