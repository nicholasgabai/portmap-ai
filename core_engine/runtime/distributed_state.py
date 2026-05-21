from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.nodes.registry import NodeRegistryEntry
from core_engine.runtime.checkpoints import summarize_runtime_checkpoints
from core_engine.runtime.profiles import RuntimeProfile, summarize_runtime_profile
from core_engine.runtime.session_state import RuntimeSession, summarize_runtime_session


DISTRIBUTED_STATE_RECORD_VERSION = 1
TRUSTED_RUNTIME_ROLES = frozenset({"master", "worker", "orchestrator"})
SAFETY_FLAGS = {
    "local_only": True,
    "trusted_node_scoped": True,
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
    "remote_control_enabled": False,
}


class DistributedNodeStateError(ValueError):
    """Raised when distributed runtime state input is malformed."""


def normalize_node_runtime_state(
    report: NodeRegistryEntry | dict[str, Any],
    *,
    generated_at: str | None = None,
    stale_after_seconds: float | None = None,
    source_ref: str | None = None,
) -> dict[str, Any]:
    """Normalize a trusted local node summary into a runtime state record.

    This helper reads already-provided node/runtime summaries only. It does not
    contact nodes, start services, or persist records.
    """
    timestamp = generated_at or _now()
    payload = _entry_to_payload(report)
    node_id = _required_str(payload.get("node_id"), "node_id")
    role = str(payload.get("role") or _nested(payload, "identity", "role") or "worker")
    if role not in TRUSTED_RUNTIME_ROLES:
        raise DistributedNodeStateError(f"unsupported trusted runtime role: {role}")

    heartbeat = _dict(payload.get("heartbeat"))
    session_summary = _session_summary(payload)
    profile_summary = _profile_summary(payload)
    health_summary = _summary_dict(payload.get("health_summary") or payload.get("runtime_health"))
    checkpoint_summary = _checkpoint_summary(payload)
    capabilities = _capabilities_summary(payload)
    component_summary = summarize_node_components(
        session_summary=session_summary,
        capabilities_summary=capabilities,
        health_summary=health_summary,
    )
    last_seen_at = str(
        payload.get("last_seen_at")
        or heartbeat.get("last_seen_at")
        or health_summary.get("generated_at")
        or payload.get("updated_at")
        or timestamp
    )
    lifecycle_state = str(payload.get("lifecycle_state") or payload.get("state") or "registered")
    sync_status = classify_node_sync_status(
        lifecycle_state=lifecycle_state,
        last_seen_at=last_seen_at,
        generated_at=timestamp,
        stale_after_seconds=stale_after_seconds,
    )
    record = {
        "record_type": "distributed_node_runtime_state",
        "record_version": DISTRIBUTED_STATE_RECORD_VERSION,
        "state_id": "",
        "node_id": node_id,
        "node_label": str(payload.get("node_label") or payload.get("label") or node_id),
        "role": role,
        "lifecycle_state": lifecycle_state,
        "sync_status": sync_status,
        "observed_at": str(payload.get("observed_at") or timestamp),
        "last_seen_at": last_seen_at,
        "source_refs": _source_refs(payload, source_ref=source_ref),
        "identity_summary": _identity_summary(payload, node_id=node_id, role=role),
        "capability_summary": capabilities,
        "component_summary": component_summary,
        "session_reference": build_node_runtime_reference("runtime_session", session_summary),
        "profile_reference": build_node_runtime_reference("runtime_profile", profile_summary),
        "health_reference": build_node_runtime_reference("runtime_health", health_summary),
        "checkpoint_reference": build_node_runtime_reference("runtime_checkpoint", checkpoint_summary),
        "session_summary": session_summary,
        "profile_summary": profile_summary,
        "health_summary": health_summary,
        "checkpoint_summary": checkpoint_summary,
        "metadata": _dict(payload.get("metadata")),
        **SAFETY_FLAGS,
    }
    record["state_id"] = _stable_id("node-state", node_id, role, record["observed_at"], record["source_refs"])
    return record


def build_node_runtime_reference(name: str, summary: dict[str, Any]) -> dict[str, Any]:
    health_event = summary.get("health_event") if isinstance(summary.get("health_event"), dict) else {}
    record_id = (
        summary.get("session_id")
        or summary.get("profile_id")
        or summary.get("checkpoint_id")
        or summary.get("latest_checkpoint_id")
        or health_event.get("event_id")
    )
    if record_id is None:
        record_id = summary.get("record_id") or summary.get("generated_at") or ""
    return {
        "name": str(name),
        "record_id": str(record_id or ""),
        "status": str(summary.get("status") or "available" if summary else "missing"),
        "summary": dict(summary or {}),
        **SAFETY_FLAGS,
    }


def summarize_node_components(
    *,
    session_summary: dict[str, Any] | None = None,
    capabilities_summary: dict[str, Any] | None = None,
    health_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    session = dict(session_summary or {})
    capabilities = dict(capabilities_summary or {})
    health = dict(health_summary or {})
    enabled_components = session.get("enabled_components") if isinstance(session.get("enabled_components"), dict) else {}
    supported_features = capabilities.get("supported_features") if isinstance(capabilities.get("supported_features"), list) else []
    health_checks = health.get("checks") if isinstance(health.get("checks"), list) else []
    check_names = [str(check.get("name")) for check in health_checks if isinstance(check, dict) and check.get("name")]
    return {
        "enabled_component_count": int(session.get("component_count") or len(enabled_components)),
        "enabled_components": sorted(str(key) for key in enabled_components),
        "supported_feature_count": len(supported_features),
        "supported_features": sorted(str(item) for item in supported_features),
        "health_check_count": len(check_names),
        "health_checks": sorted(check_names),
        **SAFETY_FLAGS,
    }


def classify_node_sync_status(
    *,
    lifecycle_state: str,
    last_seen_at: str,
    generated_at: str | None = None,
    stale_after_seconds: float | None = None,
) -> str:
    if lifecycle_state in {"removed", "offline"}:
        return "missing"
    if lifecycle_state == "stale":
        return "stale"
    if stale_after_seconds is None:
        return "current"
    try:
        age = (_parse_time(generated_at or _now()) - _parse_time(last_seen_at)).total_seconds()
    except DistributedNodeStateError:
        return "conflicting"
    return "stale" if age >= stale_after_seconds else "current"


def summarize_role_counts(states: list[dict[str, Any]]) -> dict[str, Any]:
    by_role = {role: 0 for role in sorted(TRUSTED_RUNTIME_ROLES)}
    by_status: dict[str, int] = {}
    for state in states:
        role = str(state.get("role") or "worker")
        if role not in by_role:
            by_role[role] = 0
        by_role[role] += 1
        status = str(state.get("sync_status") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    return {
        "node_count": len(states),
        "by_role": dict(sorted(by_role.items())),
        "by_sync_status": dict(sorted(by_status.items())),
        "master_count": by_role.get("master", 0),
        "worker_count": by_role.get("worker", 0),
        **SAFETY_FLAGS,
    }


def _entry_to_payload(report: NodeRegistryEntry | dict[str, Any]) -> dict[str, Any]:
    if isinstance(report, NodeRegistryEntry):
        payload = report.to_dict()
        payload["node_label"] = report.node_id
        return payload
    if not isinstance(report, dict):
        raise DistributedNodeStateError("node runtime state report must be an object")
    return dict(report)


def _session_summary(payload: dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload.get("session_summary"), dict):
        return dict(payload["session_summary"])
    session = payload.get("session")
    if isinstance(session, RuntimeSession) or isinstance(session, dict):
        return summarize_runtime_session(session)
    return {}


def _profile_summary(payload: dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload.get("profile_summary"), dict):
        return dict(payload["profile_summary"])
    profile = payload.get("profile")
    if isinstance(profile, RuntimeProfile) or isinstance(profile, dict):
        return summarize_runtime_profile(profile)
    return {}


def _checkpoint_summary(payload: dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload.get("checkpoint_summary"), dict):
        return dict(payload["checkpoint_summary"])
    checkpoint = payload.get("checkpoint")
    if isinstance(checkpoint, dict):
        return summarize_runtime_checkpoints([checkpoint])
    checkpoints = payload.get("checkpoints")
    if isinstance(checkpoints, list):
        return summarize_runtime_checkpoints([row for row in checkpoints if isinstance(row, dict)])
    return {}


def _capabilities_summary(payload: dict[str, Any]) -> dict[str, Any]:
    capabilities = _dict(payload.get("capabilities") or payload.get("capability_summary"))
    return {
        "platform": str(capabilities.get("platform") or payload.get("platform") or "unknown"),
        "architecture": str(capabilities.get("architecture") or payload.get("architecture") or "unknown"),
        "runtime_version": capabilities.get("runtime_version"),
        "supported_features": sorted(str(item) for item in capabilities.get("supported_features") or []),
        **SAFETY_FLAGS,
    }


def _identity_summary(payload: dict[str, Any], *, node_id: str, role: str) -> dict[str, Any]:
    identity = _dict(payload.get("identity"))
    return {
        "node_id": node_id,
        "role": role,
        "fingerprint": str(identity.get("fingerprint") or payload.get("fingerprint") or ""),
        "created_at": str(identity.get("created_at") or payload.get("created_at") or ""),
        "updated_at": str(identity.get("updated_at") or payload.get("updated_at") or ""),
        **SAFETY_FLAGS,
    }


def _source_refs(payload: dict[str, Any], *, source_ref: str | None) -> list[str]:
    refs = [str(item) for item in payload.get("source_refs") or [] if str(item).strip()]
    if source_ref:
        refs.append(source_ref)
    if not refs:
        refs.append(f"node:{payload.get('node_id') or 'unknown'}")
    return sorted(set(refs))


def _summary_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _nested(payload: dict[str, Any], parent: str, key: str) -> Any:
    value = payload.get(parent)
    return value.get(key) if isinstance(value, dict) else None


def _required_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DistributedNodeStateError(f"{field_name} must be a non-empty string")
    return value


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise DistributedNodeStateError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
