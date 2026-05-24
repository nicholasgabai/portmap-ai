from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.federation.runtime_state import FEDERATION_RUNTIME_SAFETY_FLAGS
from core_engine.federation.trust import TRUST_SCOPE_LABELS, build_approved_peer_record


PEER_LIFECYCLE_RECORD_VERSION = 1
PEER_LIFECYCLE_STATES = frozenset({"enrolled", "approved", "paused", "revoked", "expired"})
PEER_LIFECYCLE_ACTIONS = frozenset({"enroll", "approve", "pause", "resume", "revoke", "expire", "update_scopes"})
PEER_LIFECYCLE_TRANSITIONS = {
    "enrolled": frozenset({"approve", "pause", "revoke", "expire", "update_scopes"}),
    "approved": frozenset({"pause", "revoke", "expire", "update_scopes"}),
    "paused": frozenset({"resume", "revoke", "expire", "update_scopes"}),
    "revoked": frozenset(),
    "expired": frozenset(),
}


class TrustedPeerLifecycleError(ValueError):
    """Raised when trusted peer lifecycle records are invalid."""


def build_peer_lifecycle_record(
    peer: dict[str, Any],
    *,
    lifecycle_state: str | None = None,
    trust_scope_labels: Iterable[str] | None = None,
    transport_session_ids: Iterable[str] | None = None,
    last_seen_at: str | None = None,
    last_verified_at: str | None = None,
    lifecycle_history: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    peer_record = _peer_record(peer, generated_at=timestamp)
    state = _state(lifecycle_state or _state_from_peer(peer_record))
    scopes = _scope_labels(trust_scope_labels or peer_record.get("trust_scope_labels") or [])
    history = _history(lifecycle_history)
    if not history:
        history = [
            build_peer_lifecycle_transition_record(
                peer_node_id=peer_record["peer_node_id"],
                from_state="",
                to_state=state,
                action="enroll" if state == "enrolled" else "approve" if state == "approved" else state.rstrip("d") if state in {"revoked", "expired"} else "pause",
                trust_scope_labels=scopes,
                transitioned_at=timestamp,
            )
        ]
    record = {
        "record_type": "trusted_peer_lifecycle",
        "record_version": PEER_LIFECYCLE_RECORD_VERSION,
        "lifecycle_id": _stable_id("peer-lifecycle", peer_record["peer_node_id"], state, scopes, history),
        "peer_node_id": peer_record["peer_node_id"],
        "peer_role": str(peer_record.get("peer_role") or "worker"),
        "peer_label": str(peer_record.get("peer_label") or peer_record["peer_node_id"]),
        "identity_reference": dict(peer_record.get("identity_reference") or {}),
        "capability_summary": dict(peer_record.get("capability_summary") or {}),
        "lifecycle_state": state,
        "approval_status": _approval_status(state),
        "trust_scope_labels": scopes,
        "allowed_transport_modes": sorted(str(item) for item in peer_record.get("allowed_transport_modes") or []),
        "transport_session_ids": sorted(set(str(item) for item in transport_session_ids or [] if str(item).strip())),
        "last_seen_at": str(last_seen_at or ""),
        "last_verified_at": str(last_verified_at or ""),
        "approved_at": str(peer_record.get("approved_at") or ""),
        "expires_at": str(peer_record.get("expires_at") or ""),
        "source_refs": list(peer_record.get("source_refs") or [f"node:{peer_record['peer_node_id']}"]),
        "lifecycle_history": history,
        "generated_at": timestamp,
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }
    record["validation"] = validate_peer_lifecycle_record(record, generated_at=timestamp)
    if not record["validation"]["ok"]:
        raise TrustedPeerLifecycleError("; ".join(record["validation"]["errors"]))
    return record


def apply_peer_lifecycle_transition(
    record: dict[str, Any],
    action: str,
    *,
    trust_scope_labels: Iterable[str] | None = None,
    transport_session_ids: Iterable[str] | None = None,
    last_seen_at: str | None = None,
    last_verified_at: str | None = None,
    transitioned_at: str | None = None,
    reviewed_by: str = "local-operator",
    note: str = "",
) -> dict[str, Any]:
    timestamp = transitioned_at or _now()
    current = _state(str(record.get("lifecycle_state") or "enrolled"))
    normalized_action = _action(action)
    next_state = _next_state(current, normalized_action)
    scopes = _scope_labels(trust_scope_labels or record.get("trust_scope_labels") or [])
    session_ids = sorted(
        set(
            [
                *[str(item) for item in record.get("transport_session_ids") or [] if str(item).strip()],
                *[str(item) for item in transport_session_ids or [] if str(item).strip()],
            ]
        )
    )
    transition = build_peer_lifecycle_transition_record(
        peer_node_id=str(record.get("peer_node_id") or ""),
        from_state=current,
        to_state=next_state,
        action=normalized_action,
        trust_scope_labels=scopes,
        transitioned_at=timestamp,
        reviewed_by=reviewed_by,
        note=note,
    )
    updated = {
        **dict(record),
        "lifecycle_state": next_state,
        "approval_status": _approval_status(next_state),
        "trust_scope_labels": scopes,
        "transport_session_ids": session_ids,
        "last_seen_at": str(last_seen_at if last_seen_at is not None else record.get("last_seen_at") or ""),
        "last_verified_at": str(last_verified_at if last_verified_at is not None else record.get("last_verified_at") or ""),
        "lifecycle_history": [*_history(record.get("lifecycle_history") or []), transition],
        "generated_at": timestamp,
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }
    updated["lifecycle_id"] = _stable_id("peer-lifecycle", updated["peer_node_id"], next_state, scopes, updated["lifecycle_history"])
    updated["validation"] = validate_peer_lifecycle_record(updated, generated_at=timestamp)
    if not updated["validation"]["ok"]:
        raise TrustedPeerLifecycleError("; ".join(updated["validation"]["errors"]))
    return updated


def build_peer_lifecycle_transition_record(
    *,
    peer_node_id: str,
    from_state: str,
    to_state: str,
    action: str,
    trust_scope_labels: Iterable[str],
    transitioned_at: str | None = None,
    reviewed_by: str = "local-operator",
    note: str = "",
) -> dict[str, Any]:
    timestamp = transitioned_at or _now()
    return {
        "record_type": "trusted_peer_lifecycle_transition",
        "record_version": PEER_LIFECYCLE_RECORD_VERSION,
        "transition_id": _stable_id("peer-transition", peer_node_id, from_state, to_state, action, timestamp, trust_scope_labels),
        "peer_node_id": str(peer_node_id or ""),
        "from_state": str(from_state or ""),
        "to_state": _state(to_state),
        "action": _action(action),
        "trust_scope_labels": _scope_labels(trust_scope_labels),
        "transitioned_at": timestamp,
        "reviewed_by": str(reviewed_by or "local-operator"),
        "review_note": str(note or ""),
        "automatic_changes": False,
        "remote_command_execution": False,
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def update_peer_trust_scopes(
    record: dict[str, Any],
    trust_scope_labels: Iterable[str],
    *,
    transitioned_at: str | None = None,
    reviewed_by: str = "local-operator",
    note: str = "",
) -> dict[str, Any]:
    return apply_peer_lifecycle_transition(
        record,
        "update_scopes",
        trust_scope_labels=trust_scope_labels,
        transitioned_at=transitioned_at,
        reviewed_by=reviewed_by,
        note=note,
    )


def validate_peer_lifecycle_transition(current_state: str, action: str) -> dict[str, Any]:
    current = _state(current_state)
    normalized_action = _action(action)
    errors: list[str] = []
    if normalized_action not in PEER_LIFECYCLE_TRANSITIONS[current]:
        errors.append(f"action {normalized_action} is not allowed from {current}")
    return _validation(not errors, errors)


def validate_peer_lifecycle_record(record: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(record, dict):
        return _validation(False, ["peer lifecycle record must be an object"], [], generated_at=generated_at)
    if not str(record.get("peer_node_id") or "").strip():
        errors.append("peer_node_id is required")
    if record.get("lifecycle_state") not in PEER_LIFECYCLE_STATES:
        errors.append("lifecycle_state must be enrolled, approved, paused, revoked, or expired")
    try:
        _scope_labels(record.get("trust_scope_labels") or [])
    except TrustedPeerLifecycleError as exc:
        errors.append(str(exc))
    if not isinstance(record.get("lifecycle_history"), list):
        errors.append("lifecycle_history must be a list")
    if _is_expired(record.get("expires_at"), generated_at=generated_at or _now()) and record.get("lifecycle_state") not in {"expired", "revoked"}:
        warnings.append("peer lifecycle record has an expired approval timestamp")
    return _validation(not errors, errors, warnings, generated_at=generated_at)


def summarize_peer_lifecycle(record: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "trusted_peer_lifecycle_summary",
        "generated_at": generated_at or _now(),
        "peer_node_id": str(record.get("peer_node_id") or ""),
        "peer_role": str(record.get("peer_role") or ""),
        "peer_label": str(record.get("peer_label") or record.get("peer_node_id") or ""),
        "lifecycle_state": str(record.get("lifecycle_state") or "enrolled"),
        "trust_scope_count": len(record.get("trust_scope_labels") or []),
        "transport_session_count": len(record.get("transport_session_ids") or []),
        "transition_count": len(record.get("lifecycle_history") or []),
        "last_seen_at": str(record.get("last_seen_at") or ""),
        "last_verified_at": str(record.get("last_verified_at") or ""),
        "operator_summary": _operator_summary(record),
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def deterministic_peer_lifecycle_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _peer_record(peer: dict[str, Any], *, generated_at: str) -> dict[str, Any]:
    if not isinstance(peer, dict):
        raise TrustedPeerLifecycleError("peer must be an object")
    if peer.get("record_type") == "approved_peer_record":
        return dict(peer)
    return build_approved_peer_record(peer, approved_at=generated_at)


def _next_state(current: str, action: str) -> str:
    validation = validate_peer_lifecycle_transition(current, action)
    if not validation["ok"]:
        raise TrustedPeerLifecycleError("; ".join(validation["errors"]))
    if action == "approve" or action == "resume":
        return "approved"
    if action == "pause":
        return "paused"
    if action == "revoke":
        return "revoked"
    if action == "expire":
        return "expired"
    return current


def _state_from_peer(peer: dict[str, Any]) -> str:
    status = str(peer.get("approval_status") or "approved")
    return {
        "approved": "approved",
        "suspended": "paused",
        "expired": "expired",
        "revoked": "revoked",
    }.get(status, "enrolled")


def _approval_status(state: str) -> str:
    return {
        "approved": "approved",
        "paused": "suspended",
        "expired": "expired",
        "revoked": "revoked",
        "enrolled": "suspended",
    }[state]


def _operator_summary(record: dict[str, Any]) -> str:
    state = str(record.get("lifecycle_state") or "enrolled")
    peer = str(record.get("peer_node_id") or "peer")
    if state == "approved":
        return f"Trusted peer {peer} is approved for selected federation scopes."
    if state == "paused":
        return f"Trusted peer {peer} is paused and will not be used for active federation loops."
    if state == "revoked":
        return f"Trusted peer {peer} is revoked and requires re-enrollment before use."
    if state == "expired":
        return f"Trusted peer {peer} is expired and requires operator renewal."
    return f"Trusted peer {peer} is enrolled and awaits approval."


def _history(history: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return sorted([dict(item) for item in history or [] if isinstance(item, dict)], key=lambda item: (str(item.get("transitioned_at") or ""), str(item.get("transition_id") or "")))


def _scope_labels(values: Iterable[str]) -> list[str]:
    scopes = sorted(set(str(item) for item in values if str(item).strip()))
    invalid = [scope for scope in scopes if scope not in TRUST_SCOPE_LABELS]
    if invalid:
        raise TrustedPeerLifecycleError(f"unsupported trust scope labels: {', '.join(invalid)}")
    return scopes


def _action(value: str) -> str:
    action = str(value or "")
    if action not in PEER_LIFECYCLE_ACTIONS:
        raise TrustedPeerLifecycleError(f"unsupported peer lifecycle action: {action}")
    return action


def _state(value: str) -> str:
    state = str(value or "")
    if state not in PEER_LIFECYCLE_STATES:
        raise TrustedPeerLifecycleError(f"unsupported peer lifecycle state: {state}")
    return state


def _validation(ok: bool, errors: list[str], warnings: list[str] | None = None, *, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "ok": bool(ok),
        "errors": list(errors),
        "warnings": list(warnings or []),
        "generated_at": generated_at or _now(),
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def _is_expired(value: Any, *, generated_at: str) -> bool:
    text = str(value or "")
    if not text:
        return False
    try:
        return datetime.fromisoformat(text) <= datetime.fromisoformat(generated_at)
    except ValueError:
        return False


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
