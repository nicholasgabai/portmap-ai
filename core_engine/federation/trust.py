from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.nodes.identity import NodeIdentity
from core_engine.runtime.distributed_state import SAFETY_FLAGS, TRUSTED_RUNTIME_ROLES


TRUST_RECORD_VERSION = 1
DEFAULT_REPLAY_WINDOW_SECONDS = 300
TRUST_SCOPE_LABELS = frozenset(
    {
        "runtime-summary",
        "health-summary",
        "topology-summary",
        "review-summary",
        "export-summary",
        "event-summary",
        "operator-visibility",
        "service-readiness",
    }
)
TRUST_STATUSES = frozenset({"approved", "suspended", "expired", "revoked"})
DEFAULT_TRUST_SCOPES = (
    "runtime-summary",
    "health-summary",
    "operator-visibility",
    "event-summary",
)
DEFAULT_TRANSPORT_MODES = (
    "local-file",
    "loopback-api",
    "trusted-lan-preview",
)
TRUST_SAFETY_FLAGS = {
    **SAFETY_FLAGS,
    "operator_approved": True,
    "network_listener_enabled": False,
    "cryptographic_signing_enabled": False,
    "public_exposure_enabled": False,
    "cloud_sync_enabled": False,
    "remote_control_enabled": False,
}


class TrustedNodeTrustError(ValueError):
    """Raised when a trusted federation record is malformed."""


def build_local_node_trust_profile(
    local_node: NodeIdentity | dict[str, Any],
    *,
    approved_peers: Iterable[dict[str, Any]] | None = None,
    profile_id: str | None = None,
    trust_scope_labels: Iterable[str] | None = None,
    default_transport_modes: Iterable[str] | None = None,
    replay_window_seconds: int = DEFAULT_REPLAY_WINDOW_SECONDS,
    created_at: str | None = None,
    updated_at: str | None = None,
    expires_at: str | None = None,
    source_refs: Iterable[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a local trust profile for operator-approved federation peers.

    The profile reuses existing node identity fields by reference. It does not
    create a new node identity schema and does not contact peers.
    """
    timestamp = created_at or _now()
    identity = normalize_node_identity_reference(local_node)
    scopes = _scope_labels(trust_scope_labels or DEFAULT_TRUST_SCOPES)
    modes = _string_list(default_transport_modes or DEFAULT_TRANSPORT_MODES)
    if replay_window_seconds <= 0:
        raise TrustedNodeTrustError("replay_window_seconds must be greater than zero")
    peers = [
        _normalize_peer_record(peer, default_scopes=scopes, default_modes=modes, generated_at=timestamp)
        for peer in approved_peers or []
    ]
    peers = sorted(peers, key=lambda item: item["peer_node_id"])
    peer_ids = [peer["peer_node_id"] for peer in peers]
    payload = {
        "record_type": "local_node_trust_profile",
        "record_version": TRUST_RECORD_VERSION,
        "profile_id": profile_id or _stable_id("trust-profile", identity, peer_ids, scopes, timestamp),
        "local_node": identity,
        "trust_scope_labels": scopes,
        "default_transport_modes": modes,
        "replay_window_seconds": replay_window_seconds,
        "approved_peer_ids": peer_ids,
        "approved_peers": peers,
        "created_at": timestamp,
        "updated_at": updated_at or timestamp,
        "expires_at": str(expires_at or ""),
        "source_refs": _source_refs(source_refs, fallback=f"node:{identity['node_id']}"),
        "metadata": _sorted_dict(metadata or {}),
        **TRUST_SAFETY_FLAGS,
    }
    validation = validate_local_node_trust_profile(payload, generated_at=timestamp)
    payload["validation"] = validation
    if not validation["ok"]:
        raise TrustedNodeTrustError("; ".join(validation["errors"]))
    return payload


def build_approved_peer_record(
    peer: NodeIdentity | dict[str, Any],
    *,
    trust_scope_labels: Iterable[str] | None = None,
    allowed_transport_modes: Iterable[str] | None = None,
    approval_status: str = "approved",
    approved_at: str | None = None,
    expires_at: str | None = None,
    approved_by: str = "local-operator",
    source_refs: Iterable[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    timestamp = approved_at or _now()
    identity = normalize_node_identity_reference(peer)
    status = str(approval_status or "approved")
    if status not in TRUST_STATUSES:
        raise TrustedNodeTrustError(f"unsupported approval_status: {status}")
    payload = {
        "record_type": "approved_peer_record",
        "record_version": TRUST_RECORD_VERSION,
        "peer_node_id": identity["node_id"],
        "peer_role": identity["role"],
        "peer_label": str(_payload(peer).get("node_label") or _payload(peer).get("label") or identity["node_id"]),
        "identity_reference": identity,
        "capability_summary": _capability_summary(_payload(peer)),
        "trust_scope_labels": _scope_labels(trust_scope_labels or DEFAULT_TRUST_SCOPES),
        "allowed_transport_modes": _string_list(allowed_transport_modes or DEFAULT_TRANSPORT_MODES),
        "approval_status": status,
        "approved_by": str(approved_by or "local-operator"),
        "approved_at": timestamp,
        "expires_at": str(expires_at or ""),
        "source_refs": _source_refs(source_refs, fallback=f"node:{identity['node_id']}"),
        "metadata": _sorted_dict(metadata or {}),
        **TRUST_SAFETY_FLAGS,
    }
    validation = validate_approved_peer_record(payload, generated_at=timestamp)
    payload["validation"] = validation
    if not validation["ok"]:
        raise TrustedNodeTrustError("; ".join(validation["errors"]))
    return payload


def normalize_node_identity_reference(node: NodeIdentity | dict[str, Any]) -> dict[str, Any]:
    payload = _payload(node)
    identity = payload.get("identity") if isinstance(payload.get("identity"), dict) else payload
    node_id = _required_str(identity.get("node_id") or payload.get("node_id"), "node_id")
    role = _required_str(identity.get("role") or payload.get("role"), "role")
    if role not in TRUSTED_RUNTIME_ROLES:
        raise TrustedNodeTrustError(f"unsupported trusted runtime role: {role}")
    return {
        "node_id": node_id,
        "role": role,
        "fingerprint": str(identity.get("fingerprint") or payload.get("fingerprint") or ""),
        "source_ref": f"node:{node_id}",
        **SAFETY_FLAGS,
    }


def validate_local_node_trust_profile(profile: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(profile, dict):
        return _validation(False, ["trust profile must be an object"], [], generated_at=timestamp)
    local_node = profile.get("local_node")
    if not isinstance(local_node, dict) or not local_node.get("node_id"):
        errors.append("local_node.node_id is required")
    if not isinstance(local_node, dict) or local_node.get("role") not in TRUSTED_RUNTIME_ROLES:
        errors.append("local_node.role must be a trusted runtime role")
    _validate_scopes(profile.get("trust_scope_labels"), errors, field_name="trust_scope_labels")
    modes = _string_list(profile.get("default_transport_modes") or [])
    if not modes:
        errors.append("default_transport_modes must include at least one mode")
    replay_window = profile.get("replay_window_seconds")
    if not isinstance(replay_window, int) or replay_window <= 0:
        errors.append("replay_window_seconds must be a positive integer")
    peers = profile.get("approved_peers")
    if not isinstance(peers, list):
        errors.append("approved_peers must be a list")
        peers = []
    peer_ids: list[str] = []
    for peer in peers:
        result = validate_approved_peer_record(peer, generated_at=timestamp)
        errors.extend(f"approved_peers: {message}" for message in result["errors"])
        warnings.extend(f"approved_peers: {message}" for message in result["warnings"])
        peer_id = str(peer.get("peer_node_id") or "") if isinstance(peer, dict) else ""
        if peer_id:
            peer_ids.append(peer_id)
    duplicate_ids = sorted({peer_id for peer_id in peer_ids if peer_ids.count(peer_id) > 1})
    if duplicate_ids:
        errors.append(f"duplicate approved peers: {', '.join(duplicate_ids)}")
    if _is_expired(profile.get("expires_at"), generated_at=timestamp):
        warnings.append("trust profile is expired")
    return _validation(not errors, errors, warnings, generated_at=timestamp)


def validate_approved_peer_record(peer: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(peer, dict):
        return _validation(False, ["approved peer must be an object"], [], generated_at=timestamp)
    if not str(peer.get("peer_node_id") or "").strip():
        errors.append("peer_node_id is required")
    if peer.get("peer_role") not in TRUSTED_RUNTIME_ROLES:
        errors.append("peer_role must be a trusted runtime role")
    _validate_scopes(peer.get("trust_scope_labels"), errors, field_name="trust_scope_labels")
    if not _string_list(peer.get("allowed_transport_modes") or []):
        errors.append("allowed_transport_modes must include at least one mode")
    if peer.get("approval_status") not in TRUST_STATUSES:
        errors.append("approval_status must be approved, suspended, expired, or revoked")
    if _is_expired(peer.get("expires_at"), generated_at=timestamp):
        warnings.append("approved peer record is expired")
    return _validation(not errors, errors, warnings, generated_at=timestamp)


def is_peer_approved(
    profile: dict[str, Any],
    peer_node_id: str,
    *,
    trust_scope_label: str | None = None,
    transport_mode: str | None = None,
    generated_at: str | None = None,
) -> bool:
    timestamp = generated_at or _now()
    peer_id = str(peer_node_id or "")
    for peer in profile.get("approved_peers") or []:
        if str(peer.get("peer_node_id") or "") != peer_id:
            continue
        if peer.get("approval_status") != "approved":
            return False
        if _is_expired(peer.get("expires_at"), generated_at=timestamp):
            return False
        if trust_scope_label and trust_scope_label not in set(peer.get("trust_scope_labels") or []):
            return False
        if transport_mode and transport_mode not in set(peer.get("allowed_transport_modes") or []):
            return False
        return True
    return False


def summarize_trust_profile(profile: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    peers = [dict(peer) for peer in profile.get("approved_peers") or [] if isinstance(peer, dict)]
    by_status: dict[str, int] = {}
    by_role: dict[str, int] = {}
    expired_count = 0
    for peer in peers:
        status = str(peer.get("approval_status") or "unknown")
        role = str(peer.get("peer_role") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
        by_role[role] = by_role.get(role, 0) + 1
        if _is_expired(peer.get("expires_at"), generated_at=timestamp):
            expired_count += 1
    return {
        "record_type": "local_node_trust_profile_summary",
        "profile_id": str(profile.get("profile_id") or ""),
        "local_node_id": str((profile.get("local_node") or {}).get("node_id") or ""),
        "peer_count": len(peers),
        "approved_peer_count": by_status.get("approved", 0),
        "expired_peer_count": expired_count,
        "by_status": dict(sorted(by_status.items())),
        "by_role": dict(sorted(by_role.items())),
        "trust_scope_labels": sorted(str(item) for item in profile.get("trust_scope_labels") or []),
        "default_transport_modes": sorted(str(item) for item in profile.get("default_transport_modes") or []),
        "generated_at": timestamp,
        **TRUST_SAFETY_FLAGS,
    }


def deterministic_trust_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _normalize_peer_record(
    peer: dict[str, Any],
    *,
    default_scopes: list[str],
    default_modes: list[str],
    generated_at: str,
) -> dict[str, Any]:
    if peer.get("record_type") == "approved_peer_record":
        payload = dict(peer)
        payload["trust_scope_labels"] = _scope_labels(payload.get("trust_scope_labels") or default_scopes)
        payload["allowed_transport_modes"] = _string_list(payload.get("allowed_transport_modes") or default_modes)
        payload["validation"] = validate_approved_peer_record(payload, generated_at=generated_at)
        if not payload["validation"]["ok"]:
            raise TrustedNodeTrustError("; ".join(payload["validation"]["errors"]))
        return payload
    return build_approved_peer_record(
        peer,
        trust_scope_labels=peer.get("trust_scope_labels") or default_scopes,
        allowed_transport_modes=peer.get("allowed_transport_modes") or default_modes,
        approval_status=str(peer.get("approval_status") or "approved"),
        approved_at=str(peer.get("approved_at") or generated_at),
        expires_at=str(peer.get("expires_at") or ""),
        source_refs=peer.get("source_refs") or None,
        metadata=peer.get("metadata") if isinstance(peer.get("metadata"), dict) else None,
    )


def _payload(node: NodeIdentity | dict[str, Any]) -> dict[str, Any]:
    if isinstance(node, NodeIdentity):
        return node.to_dict()
    if not isinstance(node, dict):
        raise TrustedNodeTrustError("node reference must be an object")
    return dict(node)


def _capability_summary(payload: dict[str, Any]) -> dict[str, Any]:
    capabilities = payload.get("capabilities") if isinstance(payload.get("capabilities"), dict) else {}
    return {
        "platform": str(capabilities.get("platform") or payload.get("platform") or "unknown"),
        "architecture": str(capabilities.get("architecture") or payload.get("architecture") or "unknown"),
        "supported_features": sorted(str(item) for item in capabilities.get("supported_features") or []),
        **SAFETY_FLAGS,
    }


def _validate_scopes(value: Any, errors: list[str], *, field_name: str) -> None:
    scopes = _string_list(value or [])
    if not scopes:
        errors.append(f"{field_name} must include at least one trust scope")
        return
    unsupported = sorted(scope for scope in scopes if scope not in TRUST_SCOPE_LABELS)
    if unsupported:
        errors.append(f"{field_name} includes unsupported scopes: {', '.join(unsupported)}")


def _scope_labels(value: Iterable[str]) -> list[str]:
    scopes = sorted(set(_string_list(value)))
    unsupported = sorted(scope for scope in scopes if scope not in TRUST_SCOPE_LABELS)
    if unsupported:
        raise TrustedNodeTrustError(f"unsupported trust scope labels: {', '.join(unsupported)}")
    if not scopes:
        raise TrustedNodeTrustError("at least one trust scope label is required")
    return scopes


def _string_list(values: Iterable[Any]) -> list[str]:
    return sorted(set(str(item) for item in values if str(item).strip()))


def _source_refs(values: Iterable[str] | None, *, fallback: str) -> list[str]:
    refs = _string_list(values or [])
    refs.append(fallback)
    return sorted(set(refs))


def _required_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TrustedNodeTrustError(f"{field_name} must be a non-empty string")
    return value


def _is_expired(value: Any, *, generated_at: str) -> bool:
    if not value:
        return False
    try:
        return _parse_time(str(value)) <= _parse_time(generated_at)
    except TrustedNodeTrustError:
        return True


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise TrustedNodeTrustError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _validation(ok: bool, errors: list[str], warnings: list[str], *, generated_at: str) -> dict[str, Any]:
    return {
        "ok": ok,
        "status": "valid" if ok else "invalid",
        "errors": sorted(errors),
        "warnings": sorted(warnings),
        "generated_at": generated_at,
        **TRUST_SAFETY_FLAGS,
    }


def _sorted_dict(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in sorted(value):
        item = value[key]
        result[str(key)] = _sorted_dict(item) if isinstance(item, dict) else item
    return result


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
