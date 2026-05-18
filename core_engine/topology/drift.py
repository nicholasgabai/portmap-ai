from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.correlation.scoring import assign_advisory_severity, score_delta_finding, summarize_delta_scores
from core_engine.topology.snapshots import SAFETY_FLAGS, summarize_topology_snapshot
from core_engine.topology.timeline import build_timeline_entries


def build_drift_report(
    baseline: dict[str, Any],
    current: dict[str, Any],
    drifts: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
    errors: list[str] | None = None,
    status: str = "ok",
) -> dict[str, Any]:
    rows = [_with_score(row) for row in drifts]
    findings = [drift_to_finding(row) for row in rows]
    report = {
        "status": status,
        "ok": status == "ok",
        "generated_at": generated_at or _now(),
        "baseline_snapshot_id": str(baseline.get("snapshot_id") or ""),
        "current_snapshot_id": str(current.get("snapshot_id") or ""),
        "baseline_summary": summarize_topology_snapshot(baseline) if isinstance(baseline, dict) else {},
        "current_summary": summarize_topology_snapshot(current) if isinstance(current, dict) else {},
        "drift_count": len(rows),
        "drifts": sorted(rows, key=lambda item: (SEVERITY_ORDER.get(item["severity"], 0), item["drift_id"]), reverse=True),
        "findings": findings,
        "summary": summarize_drift(rows, errors=errors or []),
        "errors": list(errors or []),
        "event_ready": True,
        "storage_ready": True,
        "policy_review_ready": any(row.get("recommended_review") for row in rows) or bool(errors),
        "timeline_ready": True,
        "correlation_ready": True,
        **SAFETY_FLAGS,
    }
    report["report_id"] = _stable_id("topology-drift", report["baseline_snapshot_id"], report["current_snapshot_id"], report["summary"], report["errors"])
    return report


def summarize_drift(drifts: Iterable[dict[str, Any]], *, errors: list[str] | None = None) -> dict[str, Any]:
    rows = list(drifts)
    by_category: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for row in rows:
        category = str(row.get("category") or "unknown")
        drift_type = str(row.get("drift_type") or "unknown")
        severity = str(row.get("severity") or "info")
        by_category[category] = by_category.get(category, 0) + 1
        by_type[drift_type] = by_type.get(drift_type, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
    return {
        "drift_count": len(rows),
        "by_category": dict(sorted(by_category.items())),
        "by_type": dict(sorted(by_type.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "recommended_review_count": sum(1 for row in rows if row.get("recommended_review")),
        "score_summary": summarize_delta_scores([drift_to_finding(row) for row in rows]),
        "error_count": len(errors or []),
        **SAFETY_FLAGS,
    }


def drift_to_finding(drift: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": _stable_id("finding", drift.get("drift_id"), drift.get("drift_type")),
        "finding_type": str(drift.get("drift_type") or "topology_drift"),
        "category": f"topology_{drift.get('category') or 'drift'}_drift",
        "severity": str(drift.get("severity") or "info"),
        "score": float(drift.get("score") or 0.0),
        "title": str(drift.get("title") or "Topology Drift"),
        "summary": str(drift.get("summary") or ""),
        "evidence_refs": list(drift.get("evidence_refs") or []),
        "recommended_review": bool(drift.get("recommended_review")),
        "source_refs": list(drift.get("source_refs") or []),
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def build_drift_event(report: dict[str, Any], *, source: str = "topology.drift", timestamp: str | None = None) -> dict[str, Any]:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    severity = _highest_severity(report.get("drifts") or [])
    event_type = "policy_review_required" if summary.get("recommended_review_count") or report.get("errors") else "system_notice"
    message = f"Topology drift comparison found {int(summary.get('drift_count') or 0)} drift records."
    return {
        "event_id": _stable_id("evt", report.get("report_id"), event_type, message),
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "timestamp": timestamp or _now(),
        "message": message,
        "asset_ref": None,
        "service_ref": None,
        "flow_ref": None,
        "snapshot_ref": report.get("current_snapshot_id"),
        "finding_ref": _stable_id("finding", report.get("report_id"), "topology_drift"),
        "metadata": {
            "diagnostic_type": "topology_snapshot_drift",
            "baseline_snapshot_id": report.get("baseline_snapshot_id"),
            "current_snapshot_id": report.get("current_snapshot_id"),
            "summary": summary,
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_drift_storage_record(report: dict[str, Any], *, record_type: str = "topology_snapshot_drift") -> dict[str, Any]:
    return {
        "record_id": _stable_id("storage", report.get("report_id"), record_type),
        "record_type": record_type,
        "summary": report.get("summary") or {},
        "payload": {
            "report_id": report.get("report_id"),
            "status": report.get("status"),
            "baseline_snapshot_id": report.get("baseline_snapshot_id"),
            "current_snapshot_id": report.get("current_snapshot_id"),
            "drift_count": report.get("drift_count"),
            "drifts": report.get("drifts") or [],
            "findings": report.get("findings") or [],
            "errors": report.get("errors") or [],
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def build_drift_policy_records(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [finding for finding in report.get("findings") or [] if finding.get("recommended_review")]


def build_drift_timeline_entries(report: dict[str, Any]) -> list[dict[str, Any]]:
    return build_timeline_entries(deltas=report.get("drifts") or [], findings=report.get("findings") or [])


def build_drift_correlation_records(report: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for finding in report.get("findings") or []:
        records.append(
            {
                **finding,
                "correlation_key": f"topology_snapshot_drift:{finding.get('finding_type')}:{finding.get('severity')}",
                "confidence": 0.9,
            }
        )
    return records


def _with_score(drift: dict[str, Any]) -> dict[str, Any]:
    item = dict(drift)
    finding = drift_to_finding(item)
    score = score_delta_finding(finding)
    item["score"] = score
    item["severity"] = assign_advisory_severity(score)
    item["recommended_review"] = item["severity"] in {"medium", "high", "critical"} or bool(item.get("recommended_review"))
    return item


def _highest_severity(rows: Iterable[dict[str, Any]]) -> str:
    highest = "info"
    for row in rows:
        severity = str(row.get("severity") or "info")
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(highest, 0):
            highest = severity
    return highest


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "|".join(str(part) for part in parts)
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
