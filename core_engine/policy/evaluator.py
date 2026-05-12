from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.policy.models import Policy, PolicyError, ReviewRecord, SEVERITY_ORDER


def evaluate_event_against_policies(event: dict[str, Any], policies: Iterable[Policy]) -> list[ReviewRecord]:
    category = str(event.get("event_type") or "system_notice")
    severity = _severity(event.get("severity"))
    title = category.replace("_", " ").title()
    summary = str(event.get("message") or title)
    source_ref = _source_ref("event", event, category)
    evidence_refs = _evidence_refs(event, source_ref)
    return [
        build_review_record(
            policy=policy,
            source_ref=source_ref,
            category=category,
            severity=severity,
            title=title,
            summary=summary,
            evidence_refs=evidence_refs,
            recommended_action=_recommended_action(event),
        )
        for policy in policies
        if policy.matches(category=category, severity=severity)
    ]


def evaluate_finding_against_policies(finding: dict[str, Any], policies: Iterable[Policy]) -> list[ReviewRecord]:
    category = str(finding.get("category") or finding.get("type") or finding.get("finding_type") or "finding")
    severity = _severity(finding.get("severity"))
    title = str(finding.get("title") or category.replace("_", " ").title())
    summary = str(finding.get("summary") or finding.get("message") or title)
    source_ref = _source_ref("finding", finding, category)
    evidence_refs = _evidence_refs(finding, source_ref)
    return [
        build_review_record(
            policy=policy,
            source_ref=source_ref,
            category=category,
            severity=severity,
            title=title,
            summary=summary,
            evidence_refs=evidence_refs,
            recommended_action=_recommended_action(finding),
        )
        for policy in policies
        if policy.matches(category=category, severity=severity)
    ]


def evaluate_delta_against_policies(delta: dict[str, Any], policies: Iterable[Policy]) -> list[ReviewRecord]:
    category = str(delta.get("type") or delta.get("delta_type") or "baseline_delta")
    severity = _severity(delta.get("severity"))
    target = str(delta.get("target") or "sample target")
    title = category.replace("_", " ").title()
    summary = str(delta.get("summary") or f"{category.replace('_', ' ')} observed for {target}")
    source_ref = _source_ref("delta", delta, category)
    evidence_refs = _evidence_refs(delta, source_ref)
    evidence = delta.get("evidence")
    if isinstance(evidence, dict):
        evidence_refs.extend(_evidence_refs(evidence, "evidence:" + category))
    return [
        build_review_record(
            policy=policy,
            source_ref=source_ref,
            category=category,
            severity=severity,
            title=title,
            summary=summary,
            evidence_refs=sorted(set(evidence_refs)),
            recommended_action=_recommended_action(delta),
        )
        for policy in policies
        if policy.matches(category=category, severity=severity)
    ]


def build_review_record(
    *,
    policy: Policy,
    source_ref: str,
    category: str,
    severity: str,
    title: str,
    summary: str,
    evidence_refs: list[str] | None = None,
    recommended_action: str = "operator_review",
    now: str | None = None,
) -> ReviewRecord:
    if severity not in SEVERITY_ORDER:
        raise PolicyError(f"unsupported severity: {severity}")
    timestamp = now or _now()
    material = "|".join([policy.policy_id, source_ref, category, severity, title, summary])
    return ReviewRecord(
        review_id="review-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        policy_id=policy.policy_id,
        source_ref=source_ref,
        category=category,
        severity=severity,
        title=title,
        summary=summary,
        evidence_refs=sorted(set(evidence_refs or [])),
        recommended_action=recommended_action,
        status="open",
        approval_required=policy.required_review,
        automatic_changes=False,
        administrator_controlled=True,
        raw_payload_stored=False,
        created_at=timestamp,
        updated_at=timestamp,
    )


def _severity(value: Any) -> str:
    severity = str(value or "info").lower()
    return severity if severity in SEVERITY_ORDER else "info"


def _source_ref(prefix: str, row: dict[str, Any], fallback: str) -> str:
    for key in ("source_ref", "event_id", "finding_id", "delta_id", "snapshot_id", "timeline_id"):
        value = row.get(key)
        if value:
            return f"{prefix}:{value}"
    return f"{prefix}:{fallback}"


def _evidence_refs(row: dict[str, Any], fallback: str) -> list[str]:
    refs: list[str] = []
    for key in ("asset_ref", "service_ref", "snapshot_ref", "finding_ref", "edge_id", "asset_id", "service_id"):
        value = row.get(key)
        if value:
            refs.append(f"{key}:{value}")
    raw_refs = row.get("evidence_refs")
    if isinstance(raw_refs, list):
        refs.extend(str(item) for item in raw_refs if item)
    if not refs:
        refs.append(fallback)
    return sorted(set(refs))


def _recommended_action(row: dict[str, Any]) -> str:
    value = row.get("recommended_action") or row.get("action")
    return str(value) if value else "operator_review"


def _now() -> str:
    return datetime.now(UTC).isoformat()
