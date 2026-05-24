from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Iterable

from core_engine.federation.runtime_state import (
    DEFAULT_LOOP_INTERVALS,
    FEDERATION_RUNTIME_SAFETY_FLAGS,
)


EXCHANGE_JOB_RECORD_VERSION = 1
EXCHANGE_JOB_TYPES = frozenset({"signed_summary_exchange", "cluster_state_sync", "event_propagation"})
EXCHANGE_JOB_STATUSES = frozenset({"enabled", "disabled", "error"})
DEFAULT_JOB_BACKOFF_SECONDS = 30
MAX_JOB_BACKOFF_SECONDS = 900
LOOP_TYPE_TO_JOB_TYPE = {
    "signed_exchange": "signed_summary_exchange",
    "synchronization": "cluster_state_sync",
    "event_propagation": "event_propagation",
}
JOB_TYPE_TO_LOOP_TYPE = {value: key for key, value in LOOP_TYPE_TO_JOB_TYPE.items()}
DEFAULT_JOB_INTERVALS = {
    "signed_summary_exchange": DEFAULT_LOOP_INTERVALS["signed_exchange"],
    "cluster_state_sync": DEFAULT_LOOP_INTERVALS["synchronization"],
    "event_propagation": DEFAULT_LOOP_INTERVALS["event_propagation"],
}
EXCHANGE_SCHEDULER_SAFETY_FLAGS = {
    **FEDERATION_RUNTIME_SAFETY_FLAGS,
    "scheduler_record_only": True,
    "runtime_scheduler_compatible": True,
    "job_execution_enabled": False,
    "network_listener_enabled": False,
    "background_daemon_enabled": False,
}


class FederationExchangeJobError(ValueError):
    """Raised when federation exchange job records are invalid."""


def build_signed_summary_exchange_job(**kwargs: Any) -> dict[str, Any]:
    return build_federation_exchange_job("signed_summary_exchange", trust_scope_label="runtime-summary", **kwargs)


def build_cluster_state_sync_job(**kwargs: Any) -> dict[str, Any]:
    return build_federation_exchange_job("cluster_state_sync", trust_scope_label="runtime-summary", **kwargs)


def build_event_propagation_job(**kwargs: Any) -> dict[str, Any]:
    return build_federation_exchange_job("event_propagation", trust_scope_label="event-summary", **kwargs)


def build_federation_exchange_job(
    job_type: str,
    *,
    peer_node_id: str,
    trust_scope_label: str = "runtime-summary",
    interval_seconds: int | None = None,
    backoff_seconds: int = DEFAULT_JOB_BACKOFF_SECONDS,
    max_backoff_seconds: int = MAX_JOB_BACKOFF_SECONDS,
    enabled: bool = True,
    last_run_at: str | None = None,
    next_run_at: str | None = None,
    failure_count: int = 0,
    last_error_summary: str = "",
    source_refs: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a scheduler-compatible federation exchange job record.

    The record describes when an exchange should run, but does not execute it.
    """
    timestamp = generated_at or _now()
    normalized_type = _job_type(job_type)
    interval = DEFAULT_JOB_INTERVALS[normalized_type] if interval_seconds is None else int(interval_seconds)
    if interval <= 0:
        raise FederationExchangeJobError("interval_seconds must be greater than zero")
    backoff = int(backoff_seconds)
    max_backoff = int(max_backoff_seconds)
    if backoff < 0:
        raise FederationExchangeJobError("backoff_seconds cannot be negative")
    if max_backoff < backoff:
        raise FederationExchangeJobError("max_backoff_seconds must be greater than or equal to backoff_seconds")
    failures = int(failure_count)
    if failures < 0:
        raise FederationExchangeJobError("failure_count cannot be negative")
    status = _status(enabled, failures, last_error_summary)
    next_run = str(next_run_at or _next_run_timestamp(timestamp, last_run_at, interval, backoff, max_backoff, failures, enabled))
    peer_id = str(peer_node_id or "")
    payload = {
        "record_type": "federation_exchange_job",
        "record_version": EXCHANGE_JOB_RECORD_VERSION,
        "job_id": _stable_id("federation-exchange-job", normalized_type, peer_id, trust_scope_label, interval, generated_at or ""),
        "job_type": normalized_type,
        "loop_type": JOB_TYPE_TO_LOOP_TYPE[normalized_type],
        "peer_node_id": peer_id,
        "trust_scope_label": str(trust_scope_label or "runtime-summary"),
        "enabled": bool(enabled),
        "job_status": status,
        "interval_seconds": interval,
        "backoff_seconds": backoff,
        "max_backoff_seconds": max_backoff,
        "effective_backoff_seconds": _effective_backoff(backoff, max_backoff, failures),
        "last_run_at": str(last_run_at or ""),
        "next_run_at": next_run,
        "failure_count": failures,
        "last_error_summary": str(last_error_summary or ""),
        "source_refs": _source_refs(source_refs, fallback=f"node:{peer_id or 'unknown'}"),
        "runtime_job_metadata": {
            "name": "federation_exchange",
            "job_type": normalized_type,
            "peer_node_id": peer_id,
            "loop_type": JOB_TYPE_TO_LOOP_TYPE[normalized_type],
            "interval_seconds": interval,
            "enabled": bool(enabled),
        },
        "operator_summary": _job_operator_summary(normalized_type, peer_id, status, interval, failures),
        "generated_at": timestamp,
        **EXCHANGE_SCHEDULER_SAFETY_FLAGS,
    }
    payload["validation"] = validate_federation_exchange_job(payload)
    if not payload["validation"]["ok"]:
        raise FederationExchangeJobError("; ".join(payload["validation"]["errors"]))
    return payload


def build_exchange_job_from_loop_plan(
    loop_plan: dict[str, Any],
    *,
    peer_lifecycle: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(loop_plan, dict):
        raise FederationExchangeJobError("loop_plan must be an object")
    loop_type = str(loop_plan.get("loop_type") or "")
    job_type = LOOP_TYPE_TO_JOB_TYPE.get(loop_type)
    if job_type is None:
        raise FederationExchangeJobError(f"unsupported loop_type: {loop_type}")
    lifecycle_state = str((peer_lifecycle or {}).get("lifecycle_state") or "approved")
    lifecycle_enabled = lifecycle_state == "approved"
    return build_federation_exchange_job(
        job_type,
        peer_node_id=str(loop_plan.get("peer_node_id") or loop_plan.get("peer_node_id") or ""),
        trust_scope_label=str(loop_plan.get("trust_scope_label") or "runtime-summary"),
        interval_seconds=int(loop_plan.get("interval_seconds") or DEFAULT_JOB_INTERVALS[job_type]),
        enabled=bool(loop_plan.get("enabled", True)) and lifecycle_enabled,
        last_run_at=str(loop_plan.get("last_success_at") or ""),
        failure_count=1 if loop_plan.get("last_error_at") else 0,
        last_error_summary=str(loop_plan.get("last_error_at") and f"Last loop error at {loop_plan.get('last_error_at')}" or ""),
        source_refs=loop_plan.get("source_refs") or [],
        generated_at=generated_at or str(loop_plan.get("generated_at") or "") or None,
    )


def build_peer_exchange_schedule_record(
    *,
    peer_node_id: str,
    jobs: Iterable[dict[str, Any]],
    lifecycle_record: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = sorted(_rows(jobs), key=lambda item: str(item.get("job_type") or ""))
    state = str((lifecycle_record or {}).get("lifecycle_state") or "approved")
    enabled_jobs = [job for job in rows if job.get("enabled")]
    failed_jobs = [job for job in rows if int(job.get("failure_count") or 0)]
    return {
        "record_type": "peer_exchange_schedule",
        "record_version": EXCHANGE_JOB_RECORD_VERSION,
        "schedule_id": _stable_id("peer-exchange-schedule", peer_node_id, state, rows),
        "peer_node_id": str(peer_node_id or ""),
        "peer_lifecycle_state": state,
        "job_count": len(rows),
        "enabled_job_count": len(enabled_jobs),
        "disabled_job_count": len(rows) - len(enabled_jobs),
        "failure_count": sum(int(job.get("failure_count") or 0) for job in rows),
        "last_error_count": len(failed_jobs),
        "last_run_at": max([str(job.get("last_run_at") or "") for job in rows if str(job.get("last_run_at") or "")], default=""),
        "next_run_at": min([str(job.get("next_run_at") or "") for job in enabled_jobs if str(job.get("next_run_at") or "")], default=""),
        "jobs": rows,
        "operator_summary": _peer_operator_summary(peer_node_id, state, rows, failed_jobs),
        "generated_at": timestamp,
        **EXCHANGE_SCHEDULER_SAFETY_FLAGS,
    }


def summarize_federation_exchange_jobs(
    jobs: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = sorted(_rows(jobs), key=lambda item: (str(item.get("peer_node_id") or ""), str(item.get("job_type") or "")))
    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for job in rows:
        by_type[str(job.get("job_type") or "unknown")] = by_type.get(str(job.get("job_type") or "unknown"), 0) + 1
        by_status[str(job.get("job_status") or "unknown")] = by_status.get(str(job.get("job_status") or "unknown"), 0) + 1
    failure_count = sum(int(job.get("failure_count") or 0) for job in rows)
    enabled_count = sum(1 for job in rows if job.get("enabled"))
    return {
        "record_type": "federation_exchange_job_summary",
        "record_version": EXCHANGE_JOB_RECORD_VERSION,
        "generated_at": timestamp,
        "status": "review_required" if failure_count else "ready",
        "job_count": len(rows),
        "enabled_job_count": enabled_count,
        "disabled_job_count": len(rows) - enabled_count,
        "failed_job_count": sum(1 for job in rows if int(job.get("failure_count") or 0)),
        "failure_count": failure_count,
        "by_job_type": dict(sorted(by_type.items())),
        "by_job_status": dict(sorted(by_status.items())),
        "next_run_at": min([str(job.get("next_run_at") or "") for job in rows if job.get("enabled") and str(job.get("next_run_at") or "")], default=""),
        "last_run_at": max([str(job.get("last_run_at") or "") for job in rows if str(job.get("last_run_at") or "")], default=""),
        "operator_summary": _summary_operator_text(len(rows), enabled_count, failure_count),
        **EXCHANGE_SCHEDULER_SAFETY_FLAGS,
    }


def validate_federation_exchange_job(job: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(job, dict):
        return {"ok": False, "errors": ["job must be an object"], "warnings": []}
    if job.get("job_type") not in EXCHANGE_JOB_TYPES:
        errors.append("job_type is unsupported")
    if not str(job.get("peer_node_id") or "").strip():
        errors.append("peer_node_id is required")
    if int(job.get("interval_seconds") or 0) <= 0:
        errors.append("interval_seconds must be greater than zero")
    if int(job.get("failure_count") or 0) < 0:
        errors.append("failure_count cannot be negative")
    if job.get("job_status") not in EXCHANGE_JOB_STATUSES:
        errors.append("job_status is unsupported")
    return {"ok": not errors, "errors": errors, "warnings": []}


def deterministic_exchange_job_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _job_type(value: str) -> str:
    normalized = str(value or "").strip()
    if normalized not in EXCHANGE_JOB_TYPES:
        raise FederationExchangeJobError(f"unsupported job_type: {value}")
    return normalized


def _status(enabled: bool, failure_count: int, last_error_summary: str) -> str:
    if not enabled:
        return "disabled"
    if failure_count or str(last_error_summary or "").strip():
        return "error"
    return "enabled"


def _next_run_timestamp(
    generated_at: str,
    last_run_at: str | None,
    interval_seconds: int,
    backoff_seconds: int,
    max_backoff_seconds: int,
    failure_count: int,
    enabled: bool,
) -> str:
    if not enabled:
        return ""
    if not last_run_at:
        return generated_at
    delay = interval_seconds + _effective_backoff(backoff_seconds, max_backoff_seconds, failure_count)
    return (_parse_time(last_run_at) + timedelta(seconds=delay)).isoformat()


def _effective_backoff(backoff_seconds: int, max_backoff_seconds: int, failure_count: int) -> int:
    if failure_count <= 0 or backoff_seconds <= 0:
        return 0
    return min(max_backoff_seconds, backoff_seconds * (2 ** (failure_count - 1)))


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise FederationExchangeJobError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _rows(values: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(value) for value in values or [] if isinstance(value, dict)]


def _source_refs(values: Iterable[str] | None, *, fallback: str) -> list[str]:
    refs = sorted(set(str(item) for item in values or [] if str(item).strip()))
    refs.append(fallback)
    return sorted(set(refs))


def _job_operator_summary(job_type: str, peer_node_id: str, status: str, interval: int, failures: int) -> str:
    if status == "disabled":
        return f"{job_type} job for {peer_node_id} is disabled for operator review."
    if status == "error":
        return f"{job_type} job for {peer_node_id} has {failures} failure(s) and requires review."
    return f"{job_type} job for {peer_node_id} is scheduled every {interval} second(s)."


def _peer_operator_summary(peer_node_id: str, lifecycle_state: str, jobs: list[dict[str, Any]], failed_jobs: list[dict[str, Any]]) -> str:
    if lifecycle_state != "approved":
        return f"Peer {peer_node_id} is {lifecycle_state}; exchange jobs remain disabled."
    if failed_jobs:
        return f"Peer {peer_node_id} has {len(failed_jobs)} exchange job(s) requiring operator review."
    return f"Peer {peer_node_id} has {len(jobs)} planned exchange job(s)."


def _summary_operator_text(job_count: int, enabled_count: int, failure_count: int) -> str:
    if failure_count:
        return f"Federation exchange scheduler has {failure_count} failure(s) across {job_count} job(s)."
    return f"Federation exchange scheduler has {enabled_count} enabled job(s) across {job_count} planned job(s)."


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
