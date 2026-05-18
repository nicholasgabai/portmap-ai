from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Callable, Iterable

from core_engine.events import create_event, event_to_dict
from core_engine.policy.evaluator import evaluate_delta_against_policies, evaluate_finding_against_policies
from core_engine.policy.models import Policy, ReviewRecord
from core_engine.storage.repositories import LocalStorageRepository
from core_engine.topology.diff import compare_topology_snapshots
from core_engine.topology.drift import (
    build_drift_correlation_records,
    build_drift_event,
    build_drift_storage_record,
    build_drift_timeline_entries,
)
from core_engine.topology.snapshots import SAFETY_FLAGS, build_topology_snapshot
from core_engine.topology.state import persist_topology_snapshot
from core_engine.visibility import build_visibility_report


StepCallable = Callable[[dict[str, Any]], Any]


def run_runtime_pipeline(
    *,
    assets: Iterable[dict[str, Any]] | None = None,
    services: Iterable[dict[str, Any]] | None = None,
    flows: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    findings: Iterable[dict[str, Any]] | None = None,
    visibility_report: dict[str, Any] | None = None,
    baseline_snapshot: dict[str, Any] | None = None,
    current_snapshot: dict[str, Any] | None = None,
    policies: Iterable[Policy] | None = None,
    repository: LocalStorageRepository | None = None,
    dry_run: bool = True,
    write_local: bool = False,
    generated_at: str | None = None,
    label: str = "runtime-pipeline",
) -> dict[str, Any]:
    """Run the explicit local runtime workflow over operator-provided records.

    The pipeline never collects data, contacts nodes, executes remediation, or
    writes storage unless ``write_local`` is true and ``dry_run`` is false.
    """
    context: dict[str, Any] = {
        "assets": _rows(assets),
        "services": _rows(services),
        "flows": flows,
        "input_findings": _rows(findings),
        "visibility_report": visibility_report,
        "baseline_snapshot": baseline_snapshot,
        "current_snapshot": current_snapshot,
        "policies": list(policies or []),
        "repository": repository,
        "dry_run": bool(dry_run),
        "write_local": bool(write_local),
        "generated_at": generated_at or _now(),
        "label": label,
        "events": [],
        "snapshots": [],
        "findings": [],
        "review_drafts": [],
        "timeline_entries": [],
        "correlation_records": [],
        "storage_records": [],
        "storage_writes": [],
    }
    steps = [
        ("visibility", _step_visibility),
        ("topology_snapshot", _step_topology_snapshot),
        ("drift_detection", _step_drift_detection),
        ("events", _step_events),
        ("policy_review", _step_policy_review),
        ("correlation", _step_correlation),
        ("storage", _step_storage),
    ]
    step_results = [_run_step(name, step, context) for name, step in steps]
    return {
        "status": "ok" if all(step["ok"] for step in step_results) else "partial",
        "ok": all(step["ok"] for step in step_results),
        "generated_at": context["generated_at"],
        "dry_run": context["dry_run"],
        "write_local": context["write_local"],
        "step_results": step_results,
        "summary": summarize_runtime_pipeline(context, step_results),
        "visibility_report": context.get("visibility_report"),
        "topology_snapshot": context.get("topology_snapshot"),
        "drift_report": context.get("drift_report"),
        "events": list(context["events"]),
        "findings": list(context["findings"]),
        "review_drafts": list(context["review_drafts"]),
        "timeline_entries": list(context["timeline_entries"]),
        "correlation_records": list(context["correlation_records"]),
        "storage_records": list(context["storage_records"]),
        "storage_writes": list(context["storage_writes"]),
        **SAFETY_FLAGS,
    }


def summarize_runtime_pipeline(context: dict[str, Any], step_results: Iterable[dict[str, Any]]) -> dict[str, Any]:
    steps = list(step_results)
    return {
        "step_count": len(steps),
        "failed_step_count": sum(1 for step in steps if not step["ok"]),
        "event_count": len(context.get("events") or []),
        "snapshot_count": len(context.get("snapshots") or []),
        "finding_count": len(context.get("findings") or []),
        "review_draft_count": len(context.get("review_drafts") or []),
        "timeline_entry_count": len(context.get("timeline_entries") or []),
        "correlation_record_count": len(context.get("correlation_records") or []),
        "storage_record_count": len(context.get("storage_records") or []),
        "storage_write_count": len(context.get("storage_writes") or []),
        "dry_run": bool(context.get("dry_run", True)),
        "write_local": bool(context.get("write_local", False)),
        **SAFETY_FLAGS,
    }


def _step_visibility(context: dict[str, Any]) -> dict[str, Any]:
    report = context.get("visibility_report")
    if report is None and (context["assets"] or context["services"] or context["flows"]):
        report = build_visibility_report(
            assets=context["assets"],
            services=context["services"],
            flows=context["flows"],
        )
        context["visibility_report"] = report
    findings = _rows(context["input_findings"])
    if isinstance(report, dict):
        findings.extend(_rows(report.get("findings")))
    context["findings"].extend(_dedupe_by_id(findings, "finding_id"))
    return {
        "visibility_report_created": isinstance(report, dict),
        "finding_count": len(context["findings"]),
    }


def _step_topology_snapshot(context: dict[str, Any]) -> dict[str, Any]:
    snapshot = context.get("current_snapshot")
    if snapshot is None and (context["assets"] or context["services"] or context["findings"]):
        snapshot = build_topology_snapshot(
            assets=context["assets"],
            services=context["services"],
            findings=context["findings"],
            label=context["label"],
            observed_at=context["generated_at"],
            source_ref="runtime:pipeline",
        )
    if isinstance(snapshot, dict):
        context["topology_snapshot"] = snapshot
        context["current_snapshot"] = snapshot
        context["snapshots"].append(snapshot)
        return {"snapshot_created": True, "snapshot_id": snapshot.get("snapshot_id")}
    return {"snapshot_created": False, "snapshot_id": None}


def _step_drift_detection(context: dict[str, Any]) -> dict[str, Any]:
    baseline = context.get("baseline_snapshot")
    current = context.get("current_snapshot")
    if not isinstance(baseline, dict) or not isinstance(current, dict):
        return {"drift_compared": False, "drift_count": 0}
    report = compare_topology_snapshots(baseline, current, generated_at=context["generated_at"])
    context["drift_report"] = report
    context["findings"].extend(_dedupe_by_id(_rows(report.get("findings")), "finding_id"))
    context["storage_records"].append(build_drift_storage_record(report))
    context["timeline_entries"].extend(build_drift_timeline_entries(report))
    context["correlation_records"].extend(build_drift_correlation_records(report))
    return {"drift_compared": True, "drift_count": int(report.get("drift_count") or 0)}


def _step_events(context: dict[str, Any]) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    if isinstance(context.get("visibility_report"), dict):
        summary = context["visibility_report"].get("summary") or {}
        events.append(
            event_to_dict(
                create_event(
                    "system_notice",
                    severity=_event_severity_from_findings(context["visibility_report"].get("findings") or []),
                    source="runtime.pipeline.visibility",
                    message=f"Visibility workflow summarized {int(summary.get('asset_count') or 0)} assets and {int(summary.get('service_count') or 0)} services.",
                    metadata={"workflow": "runtime_pipeline", "summary": summary},
                )
            )
        )
    if isinstance(context.get("topology_snapshot"), dict):
        snapshot = context["topology_snapshot"]
        events.append(
            event_to_dict(
                create_event(
                    "snapshot_created",
                    severity="info",
                    source="runtime.pipeline.topology",
                    message="Topology snapshot prepared by runtime pipeline.",
                    snapshot_ref=str(snapshot.get("snapshot_id") or ""),
                    metadata={"workflow": "runtime_pipeline", "summary": snapshot.get("summary") or {}},
                )
            )
        )
    if isinstance(context.get("drift_report"), dict):
        events.append(build_drift_event(context["drift_report"], source="runtime.pipeline.drift", timestamp=context["generated_at"]))
    context["events"].extend(_dedupe_by_id(events, "event_id"))
    return {"event_count": len(context["events"])}


def _step_policy_review(context: dict[str, Any]) -> dict[str, Any]:
    policies = context["policies"]
    if not policies:
        return {"review_draft_count": 0, "policy_count": 0}
    reviews: list[ReviewRecord] = []
    for finding in context["findings"]:
        reviews.extend(evaluate_finding_against_policies(finding, policies))
    for drift in _rows((context.get("drift_report") or {}).get("drifts")):
        reviews.extend(evaluate_delta_against_policies(drift, policies))
    draft_rows = [review.to_dict() for review in _dedupe_reviews(reviews)]
    context["review_drafts"].extend(draft_rows)
    return {"review_draft_count": len(draft_rows), "policy_count": len(policies)}


def _step_correlation(context: dict[str, Any]) -> dict[str, Any]:
    records = list(context["correlation_records"])
    for finding in context["findings"]:
        records.append(
            {
                **finding,
                "correlation_key": f"runtime_pipeline:{finding.get('category') or finding.get('finding_type') or 'finding'}:{finding.get('severity') or 'info'}",
                "source_refs": sorted(set(finding.get("source_refs") or []) | {"runtime:pipeline"}),
                "raw_payload_stored": False,
                "automatic_changes": False,
                "administrator_controlled": True,
                "local_only": True,
            }
        )
    context["correlation_records"] = _dedupe_by_id(records, "finding_id")
    return {"correlation_record_count": len(context["correlation_records"])}


def _step_storage(context: dict[str, Any]) -> dict[str, Any]:
    if context["dry_run"] or not context["write_local"]:
        return {"storage_write_count": 0, "skipped": "dry_run" if context["dry_run"] else "write_local_disabled"}
    repository = context.get("repository")
    if not isinstance(repository, LocalStorageRepository):
        raise ValueError("write_local requires a LocalStorageRepository")
    writes: list[dict[str, Any]] = []
    for event in context["events"]:
        writes.append({"record_type": "event", "row_id": repository.insert_event(event), "record_id": event.get("event_id")})
    for snapshot in context["snapshots"]:
        writes.append({"record_type": "snapshot", "row_id": persist_topology_snapshot(repository, snapshot), "record_id": snapshot.get("snapshot_id")})
    for finding in context["findings"]:
        writes.append({"record_type": "finding", "row_id": repository.insert_finding(finding), "record_id": finding.get("finding_id")})
    context["storage_writes"].extend(writes)
    return {"storage_write_count": len(writes)}


def _run_step(name: str, step: StepCallable, context: dict[str, Any]) -> dict[str, Any]:
    try:
        result = step(context)
    except Exception as exc:  # Pipeline steps report failures without aborting later steps.
        return {
            "step": name,
            "ok": False,
            "status": "failed",
            "error": str(exc),
            "automatic_changes": False,
            "administrator_controlled": True,
            "raw_payload_stored": False,
            "local_only": True,
        }
    return {
        "step": name,
        "ok": True,
        "status": "ok",
        "result": result,
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
        "local_only": True,
    }


def _event_severity_from_findings(findings: Iterable[dict[str, Any]]) -> str:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    highest = "info"
    for finding in _rows(findings):
        severity = str(finding.get("severity") or "info")
        if order.get(severity, 0) > order[highest]:
            highest = severity
    return highest


def _dedupe_by_id(rows: Iterable[dict[str, Any]], key_name: str) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(_rows(rows)):
        key = str(row.get(key_name) or f"{key_name}-{index}")
        by_key.setdefault(key, row)
    return [by_key[key] for key in sorted(by_key)]


def _dedupe_reviews(reviews: Iterable[ReviewRecord]) -> list[ReviewRecord]:
    by_key: dict[str, ReviewRecord] = {}
    for review in reviews:
        by_key.setdefault(review.review_id, review)
    return [by_key[key] for key in sorted(by_key)]


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _now() -> str:
    return datetime.now(UTC).isoformat()
