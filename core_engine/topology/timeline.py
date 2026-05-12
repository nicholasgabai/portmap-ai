from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def build_timeline_entries(
    *,
    events: Iterable[dict[str, Any]] | None = None,
    deltas: Iterable[dict[str, Any]] | None = None,
    findings: Iterable[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build operator-readable timeline entries from local events and deltas."""
    entries: list[dict[str, Any]] = []
    for event in _rows(events):
        entries.append(_entry_from_event(event))
    for delta in _rows(deltas):
        entries.append(_entry_from_delta(delta))
    for finding in _rows(findings):
        entries.append(_entry_from_finding(finding))
    entries.sort(key=lambda item: (str(item.get("timestamp") or ""), item["timeline_id"]))
    return entries


def summarize_timeline(entries: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(entries)
    by_severity: dict[str, int] = {key: 0 for key in SEVERITY_ORDER}
    by_category: dict[str, int] = {}
    recommended_review_count = 0
    for entry in rows:
        severity = str(entry.get("severity") or "info")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        category = str(entry.get("category") or "unknown")
        by_category[category] = by_category.get(category, 0) + 1
        if entry.get("recommended_review"):
            recommended_review_count += 1
    return {
        "status": "ok",
        "entry_count": len(rows),
        "by_severity": {key: value for key, value in by_severity.items() if value},
        "by_category": dict(sorted(by_category.items())),
        "recommended_review_count": recommended_review_count,
        "highest_severity": _highest_severity(rows),
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
        "read_only": True,
    }


def _entry_from_event(event: dict[str, Any]) -> dict[str, Any]:
    event_type = str(event.get("event_type") or "system_notice")
    severity = _severity(event.get("severity"))
    timestamp = _timestamp(event)
    title = event_type.replace("_", " ").title()
    return _entry(
        timestamp=timestamp,
        category=event_type,
        severity=severity,
        title=title,
        summary=str(event.get("message") or title),
        asset_ref=_optional_str(event.get("asset_ref")),
        service_ref=_optional_str(event.get("service_ref")),
        snapshot_ref=_optional_str(event.get("snapshot_ref")),
        source_refs=[_source_ref("event", event, event_type)],
        recommended_review=severity in {"high", "critical"} or event_type in {"operator_review_created", "policy_review_required"},
    )


def _entry_from_delta(delta: dict[str, Any]) -> dict[str, Any]:
    delta_type = str(delta.get("type") or delta.get("delta_type") or "baseline_delta")
    severity = _severity(delta.get("severity"))
    evidence = delta.get("evidence") if isinstance(delta.get("evidence"), dict) else {}
    target = str(delta.get("target") or evidence.get("target") or evidence.get("asset_id") or "sample target")
    return _entry(
        timestamp=_timestamp(delta),
        category="baseline_delta",
        severity=severity,
        title=delta_type.replace("_", " ").title(),
        summary=f"{delta_type.replace('_', ' ')} observed for {target}",
        asset_ref=_optional_str(evidence.get("asset_id") or delta.get("asset_ref")),
        service_ref=_optional_str(evidence.get("service") or delta.get("service_ref")),
        snapshot_ref=_optional_str(delta.get("snapshot_ref")),
        source_refs=[_source_ref("delta", delta, delta_type)],
        recommended_review=severity in {"medium", "high", "critical"},
    )


def _entry_from_finding(finding: dict[str, Any]) -> dict[str, Any]:
    finding_type = str(finding.get("type") or finding.get("finding_type") or "advisory_finding")
    severity = _severity(finding.get("severity"))
    return _entry(
        timestamp=_timestamp(finding),
        category="finding",
        severity=severity,
        title=finding_type.replace("_", " ").title(),
        summary=str(finding.get("summary") or finding.get("message") or finding_type.replace("_", " ")),
        asset_ref=_optional_str(finding.get("asset_ref")),
        service_ref=_optional_str(finding.get("service_ref")),
        snapshot_ref=_optional_str(finding.get("snapshot_ref")),
        source_refs=[_source_ref("finding", finding, finding_type)],
        recommended_review=severity in {"medium", "high", "critical"} or bool(finding.get("recommended_review")),
    )


def _entry(
    *,
    timestamp: str,
    category: str,
    severity: str,
    title: str,
    summary: str,
    asset_ref: str | None = None,
    service_ref: str | None = None,
    snapshot_ref: str | None = None,
    source_refs: list[str] | None = None,
    recommended_review: bool = False,
) -> dict[str, Any]:
    material = "|".join([timestamp, category, severity, title, summary, asset_ref or "", service_ref or "", snapshot_ref or ""])
    return {
        "timeline_id": "timeline-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        "timestamp": timestamp,
        "category": category,
        "severity": severity,
        "title": title,
        "summary": summary,
        "asset_ref": asset_ref,
        "service_ref": service_ref,
        "snapshot_ref": snapshot_ref,
        "source_refs": sorted(set(source_refs or [])),
        "recommended_review": recommended_review,
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _severity(value: Any) -> str:
    severity = str(value or "info").lower()
    return severity if severity in SEVERITY_ORDER else "info"


def _timestamp(row: dict[str, Any]) -> str:
    value = row.get("timestamp") or row.get("observed_at") or row.get("created_at")
    return str(value) if value else datetime.now(UTC).isoformat()


def _optional_str(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


def _source_ref(kind: str, row: dict[str, Any], fallback: str) -> str:
    for key in ("source_ref", "event_id", "finding_id", "delta_id", "snapshot_id"):
        value = row.get(key)
        if value:
            return f"{kind}:{value}"
    return f"{kind}:{fallback}"


def _highest_severity(entries: list[dict[str, Any]]) -> str | None:
    if not entries:
        return None
    return max((str(entry.get("severity") or "info") for entry in entries), key=lambda item: SEVERITY_ORDER.get(item, 0))
