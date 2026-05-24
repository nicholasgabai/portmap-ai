from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable

from core_engine.federation.exchange_scheduler import build_runtime_exchange_scheduler
from core_engine.federation.health import (
    distributed_event_propagation_health_check,
    replay_window_status_check,
    signed_exchange_verification_check,
    synchronization_window_health_check,
)
from core_engine.federation.peer_registry import build_trusted_peer_registry
from core_engine.federation.runtime_state import FEDERATION_RUNTIME_SAFETY_FLAGS


ACTIVE_FEDERATION_VALIDATION_RECORD_VERSION = 1
ACTIVE_FEDERATION_VALIDATION_SAFETY_FLAGS = {
    **FEDERATION_RUNTIME_SAFETY_FLAGS,
    "validation_record_only": True,
    "network_listener_enabled": False,
    "background_daemon_enabled": False,
    "job_execution_enabled": False,
}


def build_active_federation_validation_checks(
    *,
    runtime_manager: dict[str, Any] | None = None,
    peer_registry: dict[str, Any] | None = None,
    exchange_scheduler: dict[str, Any] | None = None,
    trust_profile: dict[str, Any] | None = None,
    signed_exchanges: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    sync_result: dict[str, Any] | None = None,
    event_batch: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    registry = peer_registry or build_trusted_peer_registry(trust_profile=trust_profile, generated_at=timestamp) if trust_profile else peer_registry
    scheduler = exchange_scheduler or build_runtime_exchange_scheduler(
        runtime_manager=runtime_manager,
        peer_registry=registry,
        trust_profile=trust_profile,
        generated_at=timestamp,
    )
    return sorted(
        [
            build_trusted_peer_validation_summary(peer_registry=registry, trust_profile=trust_profile, generated_at=timestamp),
            build_signed_exchange_validation_summary(signed_exchanges=signed_exchanges, generated_at=timestamp),
            build_synchronization_window_validation_summary(sync_result=sync_result, generated_at=timestamp),
            build_event_propagation_validation_summary(event_batch=event_batch, generated_at=timestamp),
            build_replay_window_validation_summary(sync_result=sync_result, event_batch=event_batch, generated_at=timestamp),
            build_runtime_scheduler_validation_summary(exchange_scheduler=scheduler, generated_at=timestamp),
            build_federation_runtime_validation_summary(runtime_manager=runtime_manager, generated_at=timestamp),
        ],
        key=lambda item: item["name"],
    )


def build_trusted_peer_validation_summary(
    *,
    peer_registry: dict[str, Any] | None = None,
    trust_profile: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    registry = peer_registry or build_trusted_peer_registry(trust_profile=trust_profile, generated_at=timestamp) if trust_profile else peer_registry
    summary = registry.get("summary") if isinstance(registry, dict) and isinstance(registry.get("summary"), dict) else {}
    details = {
        "peer_count": int(summary.get("peer_count") or 0),
        "approved_peer_count": int(summary.get("approved_peer_count") or 0),
        "paused_peer_count": int(summary.get("paused_peer_count") or 0),
        "stale_peer_count": int(summary.get("stale_peer_count") or 0),
        "expired_peer_count": int(summary.get("expired_peer_count") or 0),
        "revoked_peer_count": int(summary.get("revoked_peer_count") or 0),
    }
    if not registry:
        return _check("trusted_peers", "unavailable", "medium", "No trusted peer registry or trust profile was provided.", details, generated_at=timestamp)
    if details["approved_peer_count"] == 0 or details["stale_peer_count"] or details["expired_peer_count"] or details["revoked_peer_count"]:
        return _check("trusted_peers", "degraded", "medium", "Trusted peer records require operator review before active federation.", details, generated_at=timestamp)
    return _check("trusted_peers", "ok", "info", "Trusted peer records are ready for active federation validation.", details, generated_at=timestamp)


def build_signed_exchange_validation_summary(
    *,
    signed_exchanges: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    check = signed_exchange_verification_check(signed_exchanges, generated_at=generated_at)
    return {**check, "name": "signed_exchanges", "validation_source": "signed_exchange_verification_check", **ACTIVE_FEDERATION_VALIDATION_SAFETY_FLAGS}


def build_synchronization_window_validation_summary(
    *,
    sync_result: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    check = synchronization_window_health_check(sync_result, generated_at=generated_at)
    return {**check, "name": "synchronization_window", "validation_source": "synchronization_window_health_check", **ACTIVE_FEDERATION_VALIDATION_SAFETY_FLAGS}


def build_event_propagation_validation_summary(
    *,
    event_batch: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    check = distributed_event_propagation_health_check(event_batch, generated_at=generated_at)
    return {**check, "name": "event_propagation", "validation_source": "distributed_event_propagation_health_check", **ACTIVE_FEDERATION_VALIDATION_SAFETY_FLAGS}


def build_replay_window_validation_summary(
    *,
    sync_result: dict[str, Any] | None = None,
    event_batch: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    check = replay_window_status_check(sync_result=sync_result, event_batch=event_batch, generated_at=generated_at)
    return {**check, "name": "replay_windows", "validation_source": "replay_window_status_check", **ACTIVE_FEDERATION_VALIDATION_SAFETY_FLAGS}


def build_runtime_scheduler_validation_summary(
    *,
    exchange_scheduler: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    summary = exchange_scheduler.get("summary") if isinstance(exchange_scheduler, dict) and isinstance(exchange_scheduler.get("summary"), dict) else {}
    details = {
        "job_count": int(summary.get("job_count") or 0),
        "enabled_job_count": int(summary.get("enabled_job_count") or 0),
        "disabled_job_count": int(summary.get("disabled_job_count") or 0),
        "failed_job_count": int(summary.get("failed_job_count") or 0),
        "failure_count": int(summary.get("failure_count") or 0),
        "next_run_at": str(summary.get("next_run_at") or ""),
    }
    if not exchange_scheduler:
        return _check("runtime_scheduler", "unavailable", "medium", "No runtime exchange scheduler record was provided.", details, generated_at=timestamp)
    if details["job_count"] == 0 or details["failed_job_count"] or details["failure_count"] or str(summary.get("status") or "") == "review_required":
        return _check("runtime_scheduler", "degraded", "medium", "Runtime exchange scheduler requires operator review.", details, generated_at=timestamp)
    return _check("runtime_scheduler", "ok", "info", "Runtime exchange scheduler records are ready.", details, generated_at=timestamp)


def build_federation_runtime_validation_summary(
    *,
    runtime_manager: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    summary = runtime_manager.get("summary") if isinstance(runtime_manager, dict) and isinstance(runtime_manager.get("summary"), dict) else {}
    state = str((runtime_manager or {}).get("state") or summary.get("status") or "unknown")
    details = {
        "state": state,
        "peer_count": int(summary.get("peer_count") or 0),
        "loop_plan_count": int(summary.get("loop_plan_count") or 0),
        "enabled_loop_plan_count": int(summary.get("enabled_loop_plan_count") or 0),
        "error_count": int(summary.get("error_count") or 0),
    }
    if not runtime_manager:
        return _check("federation_runtime", "unavailable", "medium", "No federation runtime manager record was provided.", details, generated_at=timestamp)
    if state == "error" or details["error_count"]:
        return _check("federation_runtime", "degraded", "medium", "Federation runtime manager reports errors.", details, generated_at=timestamp)
    if details["loop_plan_count"] == 0:
        return _check("federation_runtime", "degraded", "low", "Federation runtime manager has no planned exchange loops.", details, generated_at=timestamp)
    return _check("federation_runtime", "ok", "info", "Federation runtime manager records are ready.", details, generated_at=timestamp)


def _check(name: str, status: str, severity: str, message: str, details: dict[str, Any], *, generated_at: str) -> dict[str, Any]:
    return {
        "record_type": "active_federation_validation_check",
        "record_version": ACTIVE_FEDERATION_VALIDATION_RECORD_VERSION,
        "name": name,
        "status": status,
        "severity": severity,
        "message": message,
        "details": dict(details),
        "generated_at": generated_at,
        **ACTIVE_FEDERATION_VALIDATION_SAFETY_FLAGS,
    }


def _now() -> str:
    return datetime.now(UTC).isoformat()
