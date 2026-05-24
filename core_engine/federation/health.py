from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable

from core_engine.events import LocalEvent, event_to_dict
from core_engine.federation.signing import SIGNING_SAFETY_FLAGS
from core_engine.federation.trust import summarize_trust_profile


FEDERATION_HEALTH_RECORD_VERSION = 1
DEFAULT_FEDERATION_THRESHOLDS = {
    "stale_warning_count": 1,
    "rejected_warning_count": 1,
    "duplicate_warning_count": 1,
    "replayed_warning_count": 1,
    "malformed_warning_count": 1,
    "readiness_degraded_below": 80,
}
RASPBERRY_PI_FEDERATION_THRESHOLDS = {
    "stale_warning_count": 1,
    "rejected_warning_count": 1,
    "duplicate_warning_count": 1,
    "replayed_warning_count": 1,
    "malformed_warning_count": 1,
    "readiness_degraded_below": 75,
}


def build_federation_health_summary(
    *,
    trust_profile: dict[str, Any] | None = None,
    transport_sessions: Iterable[dict[str, Any]] | None = None,
    signed_exchanges: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    sync_result: dict[str, Any] | None = None,
    event_batch: dict[str, Any] | None = None,
    cluster_health: dict[str, Any] | None = None,
    distributed_state: dict[str, Any] | None = None,
    thresholds: dict[str, int] | None = None,
    edge_device: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    threshold_values = _thresholds(thresholds, edge_device=edge_device)
    checks = [
        trusted_peer_status_check(trust_profile, generated_at=timestamp),
        transport_session_health_check(transport_sessions or [], generated_at=timestamp),
        signed_exchange_verification_check(signed_exchanges, thresholds=threshold_values, generated_at=timestamp),
        synchronization_window_health_check(sync_result, thresholds=threshold_values, generated_at=timestamp),
        distributed_event_propagation_health_check(event_batch, thresholds=threshold_values, generated_at=timestamp),
        replay_window_status_check(sync_result=sync_result, event_batch=event_batch, thresholds=threshold_values, generated_at=timestamp),
        distributed_runtime_health_check(cluster_health=cluster_health, distributed_state=distributed_state, generated_at=timestamp),
    ]
    summary = summarize_federation_health_checks(checks, generated_at=timestamp)
    readiness = calculate_federation_readiness_score(checks, thresholds=threshold_values)
    status = "degraded" if readiness["score"] < threshold_values["readiness_degraded_below"] or summary["degraded_count"] else "ok"
    return {
        "record_type": "federation_health_summary",
        "record_version": FEDERATION_HEALTH_RECORD_VERSION,
        "status": status,
        "generated_at": timestamp,
        "checks": sorted(checks, key=lambda item: item["name"]),
        "summary": summary,
        "readiness": readiness,
        "resource_thresholds": threshold_values,
        **SIGNING_SAFETY_FLAGS,
    }


def trusted_peer_status_check(trust_profile: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not trust_profile:
        return _check("trusted_peers", "unavailable", "medium", "No trust profile was provided.", {"peer_count": 0}, generated_at=timestamp)
    summary = summarize_trust_profile(trust_profile, generated_at=timestamp)
    expired = int(summary.get("expired_peer_count") or 0)
    approved = int(summary.get("approved_peer_count") or 0)
    if expired:
        return _check("trusted_peers", "degraded", "medium", "Trusted peer profile contains expired peer approvals.", summary, generated_at=timestamp)
    if approved == 0:
        return _check("trusted_peers", "degraded", "medium", "No approved trusted peers are available.", summary, generated_at=timestamp)
    return _check("trusted_peers", "ok", "info", "Trusted peer approvals are available.", summary, generated_at=timestamp)


def transport_session_health_check(sessions: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = [dict(row) for row in sessions or [] if isinstance(row, dict)]
    by_status: dict[str, int] = {}
    expired = 0
    for row in rows:
        status = str(row.get("status") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
        if _is_expired(row.get("expires_at"), generated_at=timestamp):
            expired += 1
    details = {
        "session_count": len(rows),
        "expired_session_count": expired,
        "by_status": dict(sorted(by_status.items())),
    }
    if not rows:
        return _check("transport_sessions", "unavailable", "medium", "No trusted transport sessions were provided.", details, generated_at=timestamp)
    if expired or by_status.get("rejected", 0):
        return _check("transport_sessions", "degraded", "medium", "Transport session records require operator review.", details, generated_at=timestamp)
    return _check("transport_sessions", "ok", "info", "Transport session records are ready.", details, generated_at=timestamp)


def signed_exchange_verification_check(
    exchanges: Iterable[dict[str, Any]] | dict[str, Any] | None,
    *,
    thresholds: dict[str, int] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    threshold_values = thresholds or DEFAULT_FEDERATION_THRESHOLDS
    rows = _exchange_rows(exchanges)
    by_status: dict[str, int] = {}
    rejected = 0
    for row in rows:
        exchange_status = str(row.get("exchange_status") or "unknown")
        verification = row.get("verification_status") if isinstance(row.get("verification_status"), dict) else {}
        verification_status = str(verification.get("verification_status") or exchange_status)
        by_status[verification_status] = by_status.get(verification_status, 0) + 1
        if exchange_status not in {"accepted", "exchange-ready"} and verification_status not in {"metadata-valid", "not-verified"}:
            rejected += 1
    details = {
        "exchange_count": len(rows),
        "rejected_exchange_count": rejected,
        "by_verification_status": dict(sorted(by_status.items())),
    }
    if not rows:
        return _check("signed_exchanges", "unavailable", "info", "No signed exchange records were provided.", details, generated_at=timestamp)
    if rejected >= threshold_values["rejected_warning_count"]:
        return _check("signed_exchanges", "degraded", "medium", "Signed exchange verification has rejected records.", details, generated_at=timestamp)
    return _check("signed_exchanges", "ok", "info", "Signed exchange verification records are acceptable.", details, generated_at=timestamp)


def synchronization_window_health_check(
    sync_result: dict[str, Any] | None,
    *,
    thresholds: dict[str, int] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    threshold_values = thresholds or DEFAULT_FEDERATION_THRESHOLDS
    summary = sync_result.get("summary") if isinstance(sync_result, dict) and isinstance(sync_result.get("summary"), dict) else {}
    details = {
        "accepted_update_count": int(summary.get("accepted_update_count") or 0),
        "rejected_update_count": int(summary.get("rejected_update_count") or 0),
        "stale_update_count": int(summary.get("stale_update_count") or 0),
        "replayed_update_count": int(summary.get("replayed_update_count") or 0),
        "conflict_count": int(summary.get("conflict_count") or 0),
        "drift_count": int(summary.get("drift_count") or 0),
        "last_sequence_by_node": dict(summary.get("last_sequence_by_node") or {}),
    }
    if not sync_result:
        return _check("synchronization_window", "unavailable", "info", "No synchronization result was provided.", details, generated_at=timestamp)
    if (
        details["rejected_update_count"] >= threshold_values["rejected_warning_count"]
        or details["stale_update_count"] >= threshold_values["stale_warning_count"]
        or details["replayed_update_count"] >= threshold_values["replayed_warning_count"]
        or details["conflict_count"]
    ):
        return _check("synchronization_window", "degraded", "medium", "Synchronization window has rejected, stale, replayed, or conflicting updates.", details, generated_at=timestamp)
    return _check("synchronization_window", "ok", "info", "Synchronization window update state is acceptable.", details, generated_at=timestamp)


def distributed_event_propagation_health_check(
    event_batch: dict[str, Any] | None,
    *,
    thresholds: dict[str, int] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    threshold_values = thresholds or DEFAULT_FEDERATION_THRESHOLDS
    summary = event_batch.get("summary") if isinstance(event_batch, dict) and isinstance(event_batch.get("summary"), dict) else {}
    details = {
        "event_count": int(summary.get("event_count") or 0),
        "accepted_event_count": int(summary.get("accepted_event_count") or 0),
        "rejected_event_count": int(summary.get("rejected_event_count") or 0),
        "duplicate_event_count": int(summary.get("duplicate_event_count") or 0),
        "stale_event_count": int(summary.get("stale_event_count") or 0),
        "malformed_event_count": int(summary.get("malformed_event_count") or 0),
        "by_propagation_status": dict(summary.get("by_propagation_status") or {}),
    }
    if not event_batch:
        return _check("distributed_events", "unavailable", "info", "No distributed event propagation batch was provided.", details, generated_at=timestamp)
    if (
        details["rejected_event_count"] >= threshold_values["rejected_warning_count"]
        or details["duplicate_event_count"] >= threshold_values["duplicate_warning_count"]
        or details["stale_event_count"] >= threshold_values["stale_warning_count"]
        or details["malformed_event_count"] >= threshold_values["malformed_warning_count"]
    ):
        return _check("distributed_events", "degraded", "medium", "Distributed event propagation has rejected, duplicate, stale, or malformed events.", details, generated_at=timestamp)
    return _check("distributed_events", "ok", "info", "Distributed event propagation state is acceptable.", details, generated_at=timestamp)


def replay_window_status_check(
    *,
    sync_result: dict[str, Any] | None = None,
    event_batch: dict[str, Any] | None = None,
    thresholds: dict[str, int] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    threshold_values = thresholds or DEFAULT_FEDERATION_THRESHOLDS
    sync_summary = sync_result.get("summary") if isinstance(sync_result, dict) and isinstance(sync_result.get("summary"), dict) else {}
    event_summary = event_batch.get("summary") if isinstance(event_batch, dict) and isinstance(event_batch.get("summary"), dict) else {}
    replayed = int(sync_summary.get("replayed_update_count") or 0)
    duplicates = int(event_summary.get("duplicate_event_count") or 0)
    stale = int(sync_summary.get("stale_update_count") or 0) + int(event_summary.get("stale_event_count") or 0)
    details = {
        "replayed_update_count": replayed,
        "duplicate_event_count": duplicates,
        "stale_record_count": stale,
        "sync_window_id": str(sync_summary.get("window_id") or ""),
        "event_window_id": str(event_summary.get("window_id") or ""),
    }
    if replayed >= threshold_values["replayed_warning_count"] or duplicates >= threshold_values["duplicate_warning_count"] or stale >= threshold_values["stale_warning_count"]:
        return _check("replay_windows", "degraded", "medium", "Replay-window counters require operator review.", details, generated_at=timestamp)
    return _check("replay_windows", "ok", "info", "Replay-window counters are within thresholds.", details, generated_at=timestamp)


def distributed_runtime_health_check(
    *,
    cluster_health: dict[str, Any] | None = None,
    distributed_state: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    cluster_summary = cluster_health.get("summary") if isinstance(cluster_health, dict) and isinstance(cluster_health.get("summary"), dict) else {}
    state_summary = distributed_state.get("summary") if isinstance(distributed_state, dict) and isinstance(distributed_state.get("summary"), dict) else {}
    details = {
        "cluster_status": str(cluster_health.get("status") or "unknown") if isinstance(cluster_health, dict) else "unavailable",
        "degraded_node_count": int(cluster_summary.get("degraded_node_count") or 0),
        "unavailable_node_count": int(cluster_summary.get("unavailable_node_count") or 0),
        "stale_node_count": int(cluster_summary.get("stale_node_count") or state_summary.get("stale_node_count") or 0),
        "distributed_node_count": int(state_summary.get("node_count") or 0),
    }
    if not cluster_health and not distributed_state:
        return _check("distributed_runtime", "unavailable", "info", "No distributed runtime or cluster health records were provided.", details, generated_at=timestamp)
    if details["degraded_node_count"] or details["unavailable_node_count"] or details["stale_node_count"]:
        return _check("distributed_runtime", "degraded", "medium", "Distributed runtime state contains degraded, unavailable, or stale nodes.", details, generated_at=timestamp)
    return _check("distributed_runtime", "ok", "info", "Distributed runtime health inputs are acceptable.", details, generated_at=timestamp)


def calculate_federation_readiness_score(checks: Iterable[dict[str, Any]], *, thresholds: dict[str, int] | None = None) -> dict[str, Any]:
    rows = [dict(check) for check in checks]
    score = 100
    for check in rows:
        if check.get("status") == "degraded":
            score -= 15
        elif check.get("status") == "unavailable":
            score -= 8
        severity = str(check.get("severity") or "info")
        if severity == "critical":
            score -= 30
        elif severity == "high":
            score -= 20
        elif severity == "medium":
            score -= 10
        elif severity == "low":
            score -= 4
    score = max(0, min(100, score))
    threshold_values = thresholds or DEFAULT_FEDERATION_THRESHOLDS
    return {
        "score": score,
        "status": "ready" if score >= threshold_values["readiness_degraded_below"] else "degraded",
        "degraded_below": threshold_values["readiness_degraded_below"],
        **SIGNING_SAFETY_FLAGS,
    }


def summarize_federation_health_checks(checks: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(check) for check in checks]
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for check in rows:
        status = str(check.get("status") or "unknown")
        severity = str(check.get("severity") or "info")
        by_status[status] = by_status.get(status, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
    return {
        "generated_at": generated_at or _now(),
        "check_count": len(rows),
        "by_status": dict(sorted(by_status.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "degraded_count": by_status.get("degraded", 0),
        "unavailable_count": by_status.get("unavailable", 0),
        "high_count": by_severity.get("high", 0),
        "critical_count": by_severity.get("critical", 0),
        **SIGNING_SAFETY_FLAGS,
    }


def build_federation_health_event(health: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    readiness = health.get("readiness") if isinstance(health.get("readiness"), dict) else {}
    severity = "medium" if str(health.get("status") or "") == "degraded" else "info"
    event = LocalEvent(
        event_type="runtime_health",
        severity=severity,
        source="federation.health",
        timestamp=timestamp,
        message=f"Federation health status: {health.get('status') or 'unknown'}",
        metadata={
            "readiness_score": readiness.get("score"),
            "summary": health.get("summary") if isinstance(health.get("summary"), dict) else {},
        },
    )
    return event_to_dict(event)


def _check(name: str, status: str, severity: str, message: str, details: dict[str, Any] | None = None, *, generated_at: str) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "severity": severity,
        "message": message,
        "details": dict(details or {}),
        "generated_at": generated_at,
        **SIGNING_SAFETY_FLAGS,
    }


def _exchange_rows(exchanges: Iterable[dict[str, Any]] | dict[str, Any] | None) -> list[dict[str, Any]]:
    if not exchanges:
        return []
    if isinstance(exchanges, dict):
        if isinstance(exchanges.get("envelopes"), list):
            return [dict(row) for row in exchanges["envelopes"] if isinstance(row, dict)]
        return [dict(exchanges)]
    return [dict(row) for row in exchanges if isinstance(row, dict)]


def _thresholds(overrides: dict[str, int] | None, *, edge_device: bool) -> dict[str, int]:
    values = dict(RASPBERRY_PI_FEDERATION_THRESHOLDS if edge_device else DEFAULT_FEDERATION_THRESHOLDS)
    for key, value in dict(overrides or {}).items():
        if key in values and isinstance(value, int) and value >= 0:
            values[key] = value
    return values


def _is_expired(value: Any, *, generated_at: str) -> bool:
    if not value:
        return False
    try:
        return _parse_time(str(value)) <= _parse_time(generated_at)
    except ValueError:
        return True


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _now() -> str:
    return datetime.now(UTC).isoformat()
