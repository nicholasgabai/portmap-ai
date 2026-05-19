from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from core_engine.events import LocalEvent, event_to_dict
from core_engine.events.queue import LocalEventQueue
from core_engine.policy.review_queue import ReviewQueue
from core_engine.policy.review_store import PersistentReviewStore
from core_engine.runtime.profiles import RuntimeProfile, summarize_runtime_profile
from core_engine.runtime.recovery import detect_export_ready_records, detect_pending_reviews
from core_engine.runtime.scheduler import LocalRuntimeScheduler
from core_engine.runtime.session import RuntimeSessionManager
from core_engine.runtime.session_state import SAFETY_FLAGS, RuntimeSession, summarize_runtime_session
from core_engine.storage.repositories import LocalStorageRepository


DEFAULT_RESOURCE_BUDGETS = {
    "event_queue_warning_depth": 1000,
    "event_queue_critical_depth": 5000,
    "storage_warning_records": 10000,
    "storage_critical_records": 50000,
    "review_warning_count": 100,
    "review_critical_count": 500,
}

RASPBERRY_PI_RESOURCE_BUDGETS = {
    "event_queue_warning_depth": 250,
    "event_queue_critical_depth": 1000,
    "storage_warning_records": 2500,
    "storage_critical_records": 10000,
    "review_warning_count": 50,
    "review_critical_count": 200,
}


def build_runtime_health_summary(
    *,
    profile: RuntimeProfile | dict[str, Any] | None = None,
    scheduler: LocalRuntimeScheduler | dict[str, Any] | None = None,
    event_queue: LocalEventQueue | list[Any] | None = None,
    repository: LocalStorageRepository | None = None,
    review_store: PersistentReviewStore | ReviewQueue | None = None,
    dashboard_provider: Any | dict[str, Any] | None = None,
    sessions: RuntimeSessionManager | list[RuntimeSession | dict[str, Any]] | None = None,
    export_bundle: dict[str, Any] | None = None,
    resource_budgets: dict[str, int] | None = None,
    edge_device: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    budgets = _resource_budgets(resource_budgets, edge_device=edge_device)
    checks = [
        storage_health_check(repository, budgets=budgets),
        event_queue_health_check(event_queue, budgets=budgets),
        scheduler_health_check(scheduler),
        review_queue_health_check(review_store, budgets=budgets),
        dashboard_provider_health_check(dashboard_provider),
        export_readiness_health_check(repository=repository, review_store=review_store, export_bundle=export_bundle),
        runtime_session_health_check(sessions),
    ]
    profile_summary = summarize_runtime_profile(profile) if profile is not None else {}
    status = _overall_status(checks)
    event = build_runtime_health_event(
        checks=checks,
        status=status,
        generated_at=timestamp,
        metadata={"profile_id": profile_summary.get("profile_id"), "edge_device": bool(edge_device)},
    )
    return {
        "status": status,
        "generated_at": timestamp,
        "profile_summary": profile_summary,
        "checks": sorted(checks, key=lambda item: item["name"]),
        "summary": summarize_health_checks(checks),
        "resource_budgets": budgets,
        "health_event": event,
        **SAFETY_FLAGS,
    }


def storage_health_check(repository: LocalStorageRepository | None, *, budgets: dict[str, int] | None = None) -> dict[str, Any]:
    if repository is None:
        return _check("storage", "unavailable", "info", "No local storage repository was provided.", {"record_count": 0})
    try:
        counts = {
            "event_count": len(repository.list_events()),
            "snapshot_count": len(repository.list_snapshots()),
            "asset_count": len(repository.list_assets()),
            "service_count": len(repository.list_services()),
            "topology_edge_count": len(repository.list_topology_edges()),
            "finding_count": len(repository.list_findings()),
        }
    except Exception as exc:
        return _check("storage", "degraded", "high", f"Storage check failed: {exc}", {"record_count": 0, "error": str(exc)})
    total = sum(counts.values())
    severity = _budget_severity(total, budgets or DEFAULT_RESOURCE_BUDGETS, "storage_warning_records", "storage_critical_records")
    status = "ok" if severity == "info" else "degraded"
    return _check("storage", status, severity, "Local storage repository is readable.", {"record_count": total, **counts})


def event_queue_health_check(event_queue: LocalEventQueue | list[Any] | None, *, budgets: dict[str, int] | None = None) -> dict[str, Any]:
    depth = 0
    if isinstance(event_queue, LocalEventQueue):
        depth = len(event_queue)
    elif isinstance(event_queue, list):
        depth = len(event_queue)
    severity = _budget_severity(depth, budgets or DEFAULT_RESOURCE_BUDGETS, "event_queue_warning_depth", "event_queue_critical_depth")
    return _check(
        "event_queue",
        "ok" if severity == "info" else "degraded",
        severity,
        "Local event queue depth checked.",
        {"queue_depth": depth},
    )


def scheduler_health_check(scheduler: LocalRuntimeScheduler | dict[str, Any] | None) -> dict[str, Any]:
    if scheduler is None:
        return _check("scheduler", "unavailable", "info", "No local scheduler was provided.", {"scheduler_status": "not_configured"})
    try:
        status = scheduler.status() if isinstance(scheduler, LocalRuntimeScheduler) else dict(scheduler)
    except Exception as exc:
        return _check("scheduler", "degraded", "high", f"Scheduler status check failed: {exc}", {"error": str(exc)})
    failed = int(status.get("failed_job_count") or 0)
    running = str(status.get("scheduler_status") or "unknown") == "running"
    severity = "medium" if failed else "info"
    return _check(
        "scheduler",
        "degraded" if failed else "ok",
        severity,
        "Local scheduler status checked.",
        {"scheduler_status": status.get("scheduler_status"), "running": running, "failed_job_count": failed, "executed_job_count": int(status.get("executed_job_count") or 0)},
    )


def review_queue_health_check(review_store: PersistentReviewStore | ReviewQueue | None, *, budgets: dict[str, int] | None = None) -> dict[str, Any]:
    if review_store is None:
        summary = ReviewQueue().summarize_reviews()
    else:
        summary = review_store.summarize_reviews()
    pending = detect_pending_reviews(summary)
    review_count = int(summary.get("review_count") or 0)
    severity = _budget_severity(review_count, budgets or DEFAULT_RESOURCE_BUDGETS, "review_warning_count", "review_critical_count")
    if pending["requires_operator_review"] and severity == "info":
        severity = "low"
    return _check(
        "review_queue",
        "ok" if severity in {"info", "low"} else "degraded",
        severity,
        "Local operator review queue summarized.",
        {"review_count": review_count, "pending": pending, "summary": summary},
    )


def dashboard_provider_health_check(provider: Any | dict[str, Any] | None) -> dict[str, Any]:
    if provider is None:
        return _check("dashboard_provider", "unavailable", "info", "No dashboard provider was provided.", {"ready": False})
    if isinstance(provider, dict):
        status = str(provider.get("status") or "ok")
        return _check("dashboard_provider", status, "info" if status == "ok" else "medium", "Dashboard provider summary checked.", dict(provider))
    try:
        response = provider.get("/health")
        if isinstance(response, tuple):
            code, payload = response
        else:
            code, payload = 200, response
    except Exception as exc:
        return _check("dashboard_provider", "degraded", "medium", f"Dashboard provider check failed: {exc}", {"ready": False, "error": str(exc)})
    ok = int(code) == 200 and isinstance(payload, dict) and payload.get("status") in {None, "ok"}
    return _check(
        "dashboard_provider",
        "ok" if ok else "degraded",
        "info" if ok else "medium",
        "Dashboard provider health endpoint checked.",
        {"ready": ok, "status_code": int(code), "payload_status": payload.get("status") if isinstance(payload, dict) else "invalid"},
    )


def export_readiness_health_check(
    *,
    repository: LocalStorageRepository | None = None,
    review_store: PersistentReviewStore | ReviewQueue | None = None,
    export_bundle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    completed = 1 if export_bundle else 0
    if repository is None and review_store is None:
        readiness = detect_export_ready_records(
            {"event_count": 0, "snapshot_count": 0, "finding_count": 0},
            {"review_count": 0},
            {"completed_export_count": completed},
        )
        return _check("export_readiness", "ok", "info", "No export-ready records were provided.", readiness)
    storage = {
        "event_count": len(repository.list_events()) if repository else 0,
        "snapshot_count": len(repository.list_snapshots()) if repository else 0,
        "finding_count": len(repository.list_findings()) if repository else 0,
    }
    review = review_store.summarize_reviews() if review_store is not None else {"review_count": 0}
    readiness = detect_export_ready_records(storage, review, {"completed_export_count": completed})
    if export_bundle is None and readiness["export_ready"]:
        try:
            from core_engine.export import build_operational_export_bundle

            bundle = build_operational_export_bundle(repository=repository, review_store=review_store)
            readiness["bundle_digest"] = str((bundle.get("manifest") or {}).get("digest") or "")
        except Exception as exc:
            return _check("export_readiness", "degraded", "medium", f"Export readiness check failed: {exc}", {"error": str(exc)})
    return _check(
        "export_readiness",
        "ok",
        "low" if readiness["export_ready"] else "info",
        "Local export readiness checked.",
        readiness,
    )


def runtime_session_health_check(sessions: RuntimeSessionManager | list[RuntimeSession | dict[str, Any]] | None) -> dict[str, Any]:
    if sessions is None:
        return _check("runtime_sessions", "unavailable", "info", "No runtime session records were provided.", {"session_count": 0})
    if isinstance(sessions, RuntimeSessionManager):
        summary = sessions.summarize_sessions()
    else:
        items = [summarize_runtime_session(session) for session in sessions]
        failed = sum(1 for item in items if item.get("status") == "failed")
        summary = {
            "session_count": len(items),
            "failed_session_count": failed,
            "items": items,
            **SAFETY_FLAGS,
        }
    sessions_by_status = summary.get("sessions_by_status") if isinstance(summary.get("sessions_by_status"), dict) else {}
    failed_count = int(summary.get("failed_session_count") or sessions_by_status.get("failed", 0) or 0)
    return _check(
        "runtime_sessions",
        "degraded" if failed_count else "ok",
        "medium" if failed_count else "info",
        "Runtime session summaries checked.",
        summary,
    )


def build_runtime_health_event(
    *,
    checks: list[dict[str, Any]],
    status: str,
    generated_at: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary = summarize_health_checks(checks)
    severity = "medium" if status == "degraded" else "info"
    if summary["critical_count"]:
        severity = "critical"
    elif summary["high_count"]:
        severity = "high"
    event = LocalEvent(
        event_type="runtime_health",
        severity=severity,
        source="runtime.health",
        timestamp=generated_at,
        message=f"Runtime health status: {status}",
        metadata={"summary": summary, **dict(metadata or {})},
    )
    return event_to_dict(event)


def summarize_health_checks(checks: list[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for check in checks:
        status = str(check.get("status") or "unknown")
        severity = str(check.get("severity") or "info")
        by_status[status] = by_status.get(status, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
    return {
        "check_count": len(checks),
        "by_status": dict(sorted(by_status.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "degraded_count": by_status.get("degraded", 0),
        "critical_count": by_severity.get("critical", 0),
        "high_count": by_severity.get("high", 0),
        **SAFETY_FLAGS,
    }


def _check(name: str, status: str, severity: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "severity": severity,
        "message": message,
        "details": dict(details or {}),
        **SAFETY_FLAGS,
    }


def _overall_status(checks: list[dict[str, Any]]) -> str:
    if any(check.get("status") == "degraded" or check.get("severity") in {"high", "critical"} for check in checks):
        return "degraded"
    return "ok"


def _budget_severity(value: int, budgets: dict[str, int], warning_key: str, critical_key: str) -> str:
    if value >= int(budgets.get(critical_key, 0)):
        return "critical"
    if value >= int(budgets.get(warning_key, 0)):
        return "medium"
    return "info"


def _resource_budgets(overrides: dict[str, int] | None, *, edge_device: bool) -> dict[str, int]:
    budgets = dict(RASPBERRY_PI_RESOURCE_BUDGETS if edge_device else DEFAULT_RESOURCE_BUDGETS)
    for key, value in dict(overrides or {}).items():
        if key in budgets and isinstance(value, int) and value > 0:
            budgets[key] = value
    return budgets


def _now() -> str:
    return datetime.now(UTC).isoformat()
