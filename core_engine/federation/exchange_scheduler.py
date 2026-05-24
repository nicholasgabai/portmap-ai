from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.federation.exchange_jobs import (
    EXCHANGE_JOB_RECORD_VERSION,
    EXCHANGE_SCHEDULER_SAFETY_FLAGS,
    build_exchange_job_from_loop_plan,
    build_peer_exchange_schedule_record,
    deterministic_exchange_job_json,
    summarize_federation_exchange_jobs,
)
from core_engine.federation.peer_lifecycle import build_peer_lifecycle_record
from core_engine.federation.peer_registry import build_trusted_peer_registry
from core_engine.federation.runtime_manager import build_default_federation_loop_plans


def build_runtime_exchange_scheduler(
    *,
    runtime_manager: dict[str, Any] | None = None,
    peer_registry: dict[str, Any] | None = None,
    trust_profile: dict[str, Any] | None = None,
    loop_plans: Iterable[dict[str, Any]] | None = None,
    exchange_jobs: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build scheduler summaries for federation exchange loops.

    The output is a planning record. It does not start a scheduler thread,
    execute jobs, open listeners, or contact trusted peers.
    """
    timestamp = generated_at or _now()
    registry = peer_registry or _registry_from_runtime(runtime_manager=runtime_manager, trust_profile=trust_profile, generated_at=timestamp)
    lifecycle_by_peer = {
        str(row.get("peer_node_id") or ""): dict(row)
        for row in ((registry.get("peer_records") or registry.get("peers")) if isinstance(registry, dict) else []) or []
        if isinstance(row, dict)
    }
    plans = _loop_plans(runtime_manager=runtime_manager, trust_profile=trust_profile, loop_plans=loop_plans, generated_at=timestamp)
    jobs = _exchange_jobs(exchange_jobs, plans=plans, lifecycle_by_peer=lifecycle_by_peer, generated_at=timestamp)
    per_peer = build_per_peer_exchange_schedules(jobs, lifecycle_by_peer=lifecycle_by_peer, generated_at=timestamp)
    summary = summarize_runtime_exchange_scheduler(jobs=jobs, per_peer_schedules=per_peer, generated_at=timestamp)
    dashboard = build_exchange_scheduler_dashboard_record(summary=summary, per_peer_schedules=per_peer, generated_at=timestamp)
    api = build_exchange_scheduler_api_response(summary=summary, dashboard=dashboard, per_peer_schedules=per_peer, jobs=jobs, generated_at=timestamp)
    return {
        "record_type": "runtime_exchange_scheduler",
        "record_version": EXCHANGE_JOB_RECORD_VERSION,
        "scheduler_id": _stable_id("runtime-exchange-scheduler", timestamp, summary, [job.get("job_id") for job in jobs]),
        "generated_at": timestamp,
        "jobs": jobs,
        "per_peer_schedules": per_peer,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        "peer_registry_summary": dict((registry or {}).get("summary") or {}),
        **EXCHANGE_SCHEDULER_SAFETY_FLAGS,
    }


def build_per_peer_exchange_schedules(
    jobs: Iterable[dict[str, Any]],
    *,
    lifecycle_by_peer: dict[str, dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    rows = [dict(job) for job in jobs or [] if isinstance(job, dict)]
    peer_ids = sorted(set([str(job.get("peer_node_id") or "") for job in rows if str(job.get("peer_node_id") or "")] + list((lifecycle_by_peer or {}).keys())))
    schedules: list[dict[str, Any]] = []
    for peer_id in peer_ids:
        schedules.append(
            build_peer_exchange_schedule_record(
                peer_node_id=peer_id,
                jobs=[job for job in rows if str(job.get("peer_node_id") or "") == peer_id],
                lifecycle_record=(lifecycle_by_peer or {}).get(peer_id),
                generated_at=timestamp,
            )
        )
    return schedules


def summarize_runtime_exchange_scheduler(
    *,
    jobs: Iterable[dict[str, Any]],
    per_peer_schedules: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    job_summary = summarize_federation_exchange_jobs(jobs, generated_at=timestamp)
    peer_rows = [dict(row) for row in per_peer_schedules or [] if isinstance(row, dict)]
    status = str(job_summary.get("status") or "ready")
    if any(str(peer.get("peer_lifecycle_state") or "") in {"paused", "revoked", "expired"} for peer in peer_rows):
        status = "review_required"
    return {
        "record_type": "runtime_exchange_scheduler_summary",
        "record_version": EXCHANGE_JOB_RECORD_VERSION,
        "generated_at": timestamp,
        "status": status,
        "peer_schedule_count": len(peer_rows),
        "peer_review_required_count": sum(1 for peer in peer_rows if str(peer.get("peer_lifecycle_state") or "") in {"paused", "revoked", "expired"} or int(peer.get("failure_count") or 0)),
        "job_count": int(job_summary.get("job_count") or 0),
        "enabled_job_count": int(job_summary.get("enabled_job_count") or 0),
        "disabled_job_count": int(job_summary.get("disabled_job_count") or 0),
        "failed_job_count": int(job_summary.get("failed_job_count") or 0),
        "failure_count": int(job_summary.get("failure_count") or 0),
        "by_job_type": dict(job_summary.get("by_job_type") or {}),
        "by_job_status": dict(job_summary.get("by_job_status") or {}),
        "next_run_at": str(job_summary.get("next_run_at") or ""),
        "last_run_at": str(job_summary.get("last_run_at") or ""),
        "operator_summary": _operator_summary(status, job_summary, peer_rows),
        **EXCHANGE_SCHEDULER_SAFETY_FLAGS,
    }


def build_exchange_scheduler_dashboard_record(
    *,
    summary: dict[str, Any],
    per_peer_schedules: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    return {
        "record_type": "runtime_exchange_scheduler_dashboard",
        "panel": "federation_exchange_scheduler",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": timestamp,
        "metrics": {
            "peer_schedule_count": int(summary.get("peer_schedule_count") or 0),
            "job_count": int(summary.get("job_count") or 0),
            "enabled_job_count": int(summary.get("enabled_job_count") or 0),
            "disabled_job_count": int(summary.get("disabled_job_count") or 0),
            "failed_job_count": int(summary.get("failed_job_count") or 0),
            "failure_count": int(summary.get("failure_count") or 0),
        },
        "next_run_at": str(summary.get("next_run_at") or ""),
        "rows": _dashboard_rows(per_peer_schedules),
        "recommended_review": str(summary.get("status") or "") == "review_required",
        **EXCHANGE_SCHEDULER_SAFETY_FLAGS,
    }


def build_exchange_scheduler_api_response(
    *,
    summary: dict[str, Any],
    dashboard: dict[str, Any],
    per_peer_schedules: Iterable[dict[str, Any]],
    jobs: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "runtime_exchange_scheduler_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "dashboard": dict(dashboard),
        "per_peer_schedules": [dict(row) for row in per_peer_schedules or [] if isinstance(row, dict)],
        "jobs": [dict(job) for job in jobs or [] if isinstance(job, dict)],
        **EXCHANGE_SCHEDULER_SAFETY_FLAGS,
    }


def deterministic_exchange_scheduler_json(record: dict[str, Any]) -> str:
    return deterministic_exchange_job_json(record)


def _registry_from_runtime(
    *,
    runtime_manager: dict[str, Any] | None,
    trust_profile: dict[str, Any] | None,
    generated_at: str,
) -> dict[str, Any]:
    if trust_profile:
        return build_trusted_peer_registry(trust_profile=trust_profile, generated_at=generated_at)
    enrollments = ((runtime_manager or {}).get("runtime_state") or {}).get("peer_enrollments") or []
    lifecycle_records = []
    for enrollment in enrollments:
        if not isinstance(enrollment, dict):
            continue
        lifecycle_records.append(
            build_peer_lifecycle_record(
                {
                    "record_type": "approved_peer_record",
                    "peer_node_id": str(enrollment.get("peer_node_id") or ""),
                    "peer_role": str(enrollment.get("peer_role") or "worker"),
                    "peer_label": str(enrollment.get("peer_label") or enrollment.get("peer_node_id") or ""),
                    "approval_status": str(enrollment.get("approval_status") or "approved"),
                    "trust_scope_labels": list(enrollment.get("trust_scope_labels") or []),
                    "source_refs": list(enrollment.get("source_refs") or []),
                },
                transport_session_ids=enrollment.get("transport_session_ids") or [],
                generated_at=generated_at,
            )
        )
    return build_trusted_peer_registry(peer_lifecycle_records=lifecycle_records, generated_at=generated_at)


def _loop_plans(
    *,
    runtime_manager: dict[str, Any] | None,
    trust_profile: dict[str, Any] | None,
    loop_plans: Iterable[dict[str, Any]] | None,
    generated_at: str,
) -> list[dict[str, Any]]:
    provided = [dict(row) for row in loop_plans or [] if isinstance(row, dict)]
    if provided:
        return sorted(provided, key=lambda item: (str(item.get("peer_node_id") or ""), str(item.get("loop_type") or "")))
    manager_plans = [dict(row) for row in (runtime_manager or {}).get("loop_plans") or [] if isinstance(row, dict)]
    if manager_plans:
        return sorted(manager_plans, key=lambda item: (str(item.get("peer_node_id") or ""), str(item.get("loop_type") or "")))
    if trust_profile:
        return build_default_federation_loop_plans(trust_profile=trust_profile, state="active", generated_at=generated_at)
    return []


def _exchange_jobs(
    exchange_jobs: Iterable[dict[str, Any]] | None,
    *,
    plans: list[dict[str, Any]],
    lifecycle_by_peer: dict[str, dict[str, Any]],
    generated_at: str,
) -> list[dict[str, Any]]:
    provided = [dict(row) for row in exchange_jobs or [] if isinstance(row, dict)]
    if provided:
        return sorted(provided, key=lambda item: (str(item.get("peer_node_id") or ""), str(item.get("job_type") or "")))
    jobs = []
    for plan in plans:
        peer_id = str(plan.get("peer_node_id") or "")
        jobs.append(build_exchange_job_from_loop_plan(plan, peer_lifecycle=lifecycle_by_peer.get(peer_id), generated_at=generated_at))
    return sorted(jobs, key=lambda item: (str(item.get("peer_node_id") or ""), str(item.get("job_type") or "")))


def _dashboard_rows(per_peer_schedules: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for schedule in sorted([dict(row) for row in per_peer_schedules or [] if isinstance(row, dict)], key=lambda item: str(item.get("peer_node_id") or "")):
        rows.append(
            {
                "peer_node_id": schedule.get("peer_node_id"),
                "peer_lifecycle_state": schedule.get("peer_lifecycle_state"),
                "job_count": schedule.get("job_count"),
                "enabled_job_count": schedule.get("enabled_job_count"),
                "failure_count": schedule.get("failure_count"),
                "next_run_at": schedule.get("next_run_at"),
            }
        )
    return rows


def _operator_summary(status: str, job_summary: dict[str, Any], peer_rows: list[dict[str, Any]]) -> str:
    if status == "review_required":
        return "Runtime exchange scheduler has peer lifecycle or job failure records requiring operator review."
    return (
        f"Runtime exchange scheduler has {job_summary.get('enabled_job_count', 0)} enabled job(s) "
        f"for {len(peer_rows)} trusted peer schedule(s)."
    )


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
