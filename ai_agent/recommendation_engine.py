from __future__ import annotations

from hashlib import sha256
from typing import Any, Iterable


DESTRUCTIVE_ACTIONS = {"block_peer", "isolate_device", "terminate_process", "close_port"}
DEFAULT_REVIEW_THRESHOLD = 0.6
DEFAULT_APPROVAL_THRESHOLD = 0.8


def generate_recommendations(
    incidents: Iterable[dict[str, Any]],
    *,
    review_threshold: float = DEFAULT_REVIEW_THRESHOLD,
    approval_threshold: float = DEFAULT_APPROVAL_THRESHOLD,
) -> dict[str, Any]:
    if review_threshold < 0 or approval_threshold < 0:
        raise ValueError("thresholds must be non-negative")
    incident_list = [incident for incident in incidents if isinstance(incident, dict)]
    recommendations: list[dict[str, Any]] = []
    for incident in incident_list:
        recommendations.extend(recommend_incident(incident, approval_threshold=approval_threshold))
    recommendations = _dedupe_recommendations(recommendations)
    return {
        "ok": True,
        "incident_count": len(incident_list),
        "recommendation_count": len(recommendations),
        "recommendations": sorted(recommendations, key=lambda item: (-item["priority"], item["action"], item["target"])),
        "review_threshold": float(review_threshold),
        "approval_threshold": float(approval_threshold),
        "raw_payload_stored": False,
        "automatic_changes": False,
        "model": "local_recommendation_engine",
    }


def recommend_incident(
    incident: dict[str, Any],
    *,
    approval_threshold: float = DEFAULT_APPROVAL_THRESHOLD,
) -> list[dict[str, Any]]:
    incident_type = str(incident.get("type") or "unknown")
    score = _score(incident)
    findings = {str(item) for item in incident.get("findings") or []}
    recommendations: list[dict[str, Any]] = []

    recommendations.append(_recommendation(
        "investigate",
        incident,
        target=str(incident.get("entity") or "unknown"),
        reason="review linked evidence and validate the incident scope",
        priority=max(score, 0.4),
        destructive=False,
    ))

    if incident_type == "suspicious_scan_behavior":
        recommendations.append(_recommendation(
            "review_scan_source",
            incident,
            target=str(incident.get("entity") or "unknown"),
            reason="verify whether the scan source is an approved scanner or unexpected host behavior",
            priority=max(score, 0.65),
            destructive=False,
        ))
    if incident_type == "lateral_movement_indicator":
        recommendations.append(_recommendation(
            "review_segmentation",
            incident,
            target=str(incident.get("entity") or "unknown"),
            reason="administrative or file-sharing access reached multiple peers",
            priority=max(score, 0.75),
            destructive=False,
        ))
    if incident_type == "chained_behavior_payload_risk":
        recommendations.append(_recommendation(
            "collect_host_evidence",
            incident,
            target=str(incident.get("entity") or "unknown"),
            reason="behavior and payload anomalies occurred in the same window",
            priority=max(score, 0.75),
            destructive=False,
        ))
    if {"credential_marker", "cleartext_sensitive_payload"} & findings:
        recommendations.append(_recommendation(
            "rotate_exposed_credentials",
            incident,
            target=str(incident.get("entity") or "unknown"),
            reason="sensitive credential-like payload markers were observed",
            priority=max(score, 0.8),
            destructive=False,
        ))
    if {"possible_exfiltration_payload", "possible_exfiltration_volume", "beaconing_candidate"} & findings:
        recommendations.append(_recommendation(
            "review_egress_policy",
            incident,
            target=str(incident.get("entity") or "unknown"),
            reason="payload or timing evidence suggests outbound activity needs review",
            priority=max(score, 0.75),
            destructive=False,
        ))

    if score >= approval_threshold:
        for peer in incident.get("peers") or []:
            recommendations.append(_recommendation(
                "block_peer",
                incident,
                target=str(peer),
                reason="high-scoring incident includes this peer; prepare a dry-run block recommendation for operator approval",
                priority=score,
                destructive=True,
            ))
        recommendations.append(_recommendation(
            "isolate_device",
            incident,
            target=str(incident.get("entity") or "unknown"),
            reason="high-scoring incident may require containment after operator validation",
            priority=score,
            destructive=True,
        ))

    return recommendations


def _recommendation(
    action: str,
    incident: dict[str, Any],
    *,
    target: str,
    reason: str,
    priority: float,
    destructive: bool,
) -> dict[str, Any]:
    approval_required = destructive
    recommendation = {
        "recommendation_id": _recommendation_id(action, target, incident),
        "incident_id": incident.get("incident_id"),
        "incident_type": incident.get("type"),
        "action": action,
        "target": target,
        "priority": round(max(0.0, min(float(priority), 1.0)), 2),
        "confidence": _confidence(incident),
        "reason": reason,
        "approval_required": approval_required,
        "dry_run": destructive,
        "destructive": destructive,
        "operator_prompt": _operator_prompt(action, target, incident),
        "supporting_evidence": _supporting_evidence(incident),
        "remediation_command": _remediation_command(action, target, incident) if destructive else None,
    }
    return recommendation


def _remediation_command(action: str, target: str, incident: dict[str, Any]) -> dict[str, Any]:
    decision = "block" if action == "block_peer" else "isolate" if action == "isolate_device" else action
    return {
        "action": "apply_remediation",
        "decision": decision,
        "target": target,
        "dry_run": True,
        "confirmed": False,
        "metadata": {
            "incident_id": incident.get("incident_id"),
            "recommendation": action,
            "requires_operator_approval": True,
        },
    }


def _operator_prompt(action: str, target: str, incident: dict[str, Any]) -> str:
    return (
        f"Review recommendation '{action}' for {target} from incident "
        f"{incident.get('incident_id') or 'unknown'} before taking action."
    )


def _supporting_evidence(incident: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = incident.get("supporting_evidence")
    if isinstance(evidence, list) and evidence:
        return [
            {
                "event_id": item.get("event_id"),
                "kind": item.get("kind"),
                "score": item.get("score"),
                "severity": item.get("severity"),
                "summary": item.get("summary"),
            }
            for item in evidence[:10]
            if isinstance(item, dict)
        ]
    return [
        {
            "incident_id": incident.get("incident_id"),
            "severity": incident.get("severity"),
            "score": incident.get("score"),
            "summary": incident.get("explanation"),
        }
    ]


def _dedupe_recommendations(recommendations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for recommendation in recommendations:
        key = recommendation["recommendation_id"]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(recommendation)
    return deduped


def _recommendation_id(action: str, target: str, incident: dict[str, Any]) -> str:
    seed = f"{action}:{target}:{incident.get('incident_id')}:{incident.get('type')}"
    return sha256(seed.encode("utf-8")).hexdigest()[:16]


def _score(incident: dict[str, Any]) -> float:
    try:
        return max(0.0, min(float(incident.get("score") or incident.get("risk_score") or 0), 1.0))
    except (TypeError, ValueError):
        return 0.0


def _confidence(incident: dict[str, Any]) -> float:
    event_count = int(incident.get("event_count") or len(incident.get("event_ids") or []))
    score = _score(incident)
    return round(min(0.95, 0.35 + min(event_count, 5) * 0.08 + score * 0.25), 2)
