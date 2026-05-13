from __future__ import annotations

from typing import Any, Iterable


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

BASE_TYPE_SCORES = {
    "new_asset_observed": 0.45,
    "asset_missing_from_current_window": 0.40,
    "new_service_observed": 0.55,
    "service_missing_from_current_window": 0.35,
    "service_label_changed": 0.50,
    "topology_relationship_added": 0.45,
    "topology_relationship_removed": 0.35,
    "repeated_finding_category": 0.60,
    "severity_increase_observed": 0.70,
    "low_confidence_identity_match": 0.45,
}

SEVERITY_WEIGHTS = {
    "info": 0.00,
    "low": 0.05,
    "medium": 0.12,
    "high": 0.22,
    "critical": 0.30,
}


def score_delta_finding(finding: dict[str, Any]) -> float:
    finding_type = str(finding.get("finding_type") or "")
    score = BASE_TYPE_SCORES.get(finding_type, 0.30)
    score += SEVERITY_WEIGHTS.get(str(finding.get("severity") or "info"), 0.0)
    if finding.get("recommended_review", True):
        score += 0.05
    if finding.get("confidence") is not None:
        try:
            confidence = float(finding.get("confidence"))
        except (TypeError, ValueError):
            confidence = 0.0
        if confidence < 0.5:
            score += 0.08
    evidence_count = len(finding.get("evidence_refs") or [])
    if evidence_count > 1:
        score += min(0.10, evidence_count * 0.02)
    return round(min(max(score, 0.0), 1.0), 3)


def assign_advisory_severity(score: float) -> str:
    if score >= 0.85:
        return "critical"
    if score >= 0.70:
        return "high"
    if score >= 0.50:
        return "medium"
    if score >= 0.25:
        return "low"
    return "info"


def summarize_delta_scores(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(findings)
    severity_counts = {severity: 0 for severity in SEVERITY_ORDER}
    for row in rows:
        severity = str(row.get("severity") or "info")
        severity_counts[severity if severity in severity_counts else "info"] += 1
    scores = [float(row.get("score") or 0.0) for row in rows]
    return {
        "finding_count": len(rows),
        "severity_counts": severity_counts,
        "max_score": round(max(scores), 3) if scores else 0.0,
        "average_score": round(sum(scores) / len(scores), 3) if scores else 0.0,
        "recommended_review_count": sum(1 for row in rows if row.get("recommended_review", True)),
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
        "local_only": True,
    }


def highest_severity(values: Iterable[str]) -> str:
    normalized = [value if value in SEVERITY_ORDER else "info" for value in values]
    if not normalized:
        return "info"
    return max(normalized, key=lambda value: SEVERITY_ORDER[value])
