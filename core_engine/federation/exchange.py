from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Iterable

from core_engine.federation.signing import (
    SIGNING_RECORD_VERSION,
    SIGNING_SAFETY_FLAGS,
    build_payload_digest_record,
    build_signature_metadata,
    build_signing_status_record,
    build_verification_status_record,
    canonical_json,
    deterministic_digest,
    validate_signature_metadata,
)
from core_engine.federation.transport import TrustedTransportError, trusted_transport_session_to_dict
from core_engine.federation.trust import TRUST_SCOPE_LABELS, is_peer_approved, normalize_node_identity_reference


SUMMARY_EXCHANGE_SCOPES = frozenset(TRUST_SCOPE_LABELS)
EXCHANGE_STATUSES = frozenset({"exchange-ready", "accepted", "rejected", "stale", "replayed", "malformed", "untrusted"})


class SignedExchangeError(ValueError):
    """Raised when a signed runtime summary exchange envelope is malformed."""


def build_signed_runtime_summary_envelope(
    summary: dict[str, Any],
    *,
    source_node: dict[str, Any],
    destination_node: dict[str, Any],
    trust_profile: dict[str, Any],
    transport_session: dict[str, Any],
    trust_scope_label: str = "runtime-summary",
    sequence: int = 1,
    nonce: str = "",
    issued_at: str | None = None,
    expires_at: str | None = None,
    key_reference: str = "keyref:operator-approved-placeholder",
    signature_value: str | None = None,
    source_refs: Iterable[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic signed runtime summary exchange envelope.

    The envelope contains signature metadata and digest records only. It does
    not contact peers, open listeners, or store private signing material.
    """
    timestamp = issued_at or _now()
    if not isinstance(summary, dict):
        raise SignedExchangeError("summary payload must be an object")
    scope = _trust_scope(trust_scope_label)
    source = normalize_node_identity_reference(source_node)
    destination = normalize_node_identity_reference(destination_node)
    transport = _validated_transport(transport_session, source_node_id=source["node_id"], destination_node_id=destination["node_id"], trust_scope_label=scope)
    if not is_peer_approved(
        trust_profile,
        destination["node_id"],
        trust_scope_label=scope,
        transport_mode=transport["transport_mode"],
        generated_at=timestamp,
    ):
        raise SignedExchangeError("destination node is not approved for this signed exchange scope")
    if sequence < 0:
        raise SignedExchangeError("sequence must be non-negative")
    nonce_value = str(nonce or f"nonce-{sequence}")
    digest_record = build_payload_digest_record(summary, generated_at=timestamp)
    signature = build_signature_metadata(
        source_node=source,
        payload_digest=digest_record["payload_digest"],
        key_reference=key_reference,
        signature_value=signature_value,
        signed_at=timestamp,
    )
    signing_status = build_signing_status_record(signature, generated_at=timestamp)
    payload = {
        "record_type": "signed_runtime_summary_envelope",
        "record_version": SIGNING_RECORD_VERSION,
        "envelope_id": "",
        "exchange_status": "exchange-ready",
        "source_node": source,
        "destination_node": destination,
        "source_node_id": source["node_id"],
        "destination_node_id": destination["node_id"],
        "transport_session_id": transport["session_id"],
        "trust_profile_id": str(trust_profile.get("profile_id") or ""),
        "trust_scope_label": scope,
        "summary_record_type": str(summary.get("record_type") or "runtime_summary"),
        "summary_payload": dict(summary),
        "payload_digest": digest_record["payload_digest"],
        "payload_digest_record": digest_record,
        "signature_metadata": signature,
        "signing_status": signing_status,
        "verification_status": build_verification_status_record(
            envelope_id="",
            payload_digest=digest_record["payload_digest"],
            status="not-verified",
            verified_at=timestamp,
        ),
        "sequence": int(sequence),
        "nonce": nonce_value,
        "issued_at": timestamp,
        "expires_at": expires_at or transport["expires_at"],
        "replay_window": dict(transport.get("replay_window") or {}),
        "source_refs": _source_refs(source_refs, fallback=f"node:{source['node_id']}"),
        "metadata": _sorted_dict(metadata or {}),
        **SIGNING_SAFETY_FLAGS,
    }
    payload["envelope_id"] = _stable_id(
        "signed-summary-envelope",
        source["node_id"],
        destination["node_id"],
        scope,
        payload["payload_digest"],
        sequence,
        nonce_value,
    )
    payload["verification_status"] = {
        **payload["verification_status"],
        "envelope_id": payload["envelope_id"],
    }
    return payload


def validate_signed_runtime_summary_envelope(
    envelope: dict[str, Any],
    *,
    trust_profile: dict[str, Any] | None = None,
    transport_session: dict[str, Any] | None = None,
    seen_nonces: Iterable[str] | None = None,
    last_sequence_by_node: dict[str, int] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(envelope, dict):
        return build_verification_status_record(envelope_id="", payload_digest="", status="metadata-invalid", errors=["envelope must be an object"], verified_at=timestamp)
    envelope_id = str(envelope.get("envelope_id") or "")
    source_node_id = str(envelope.get("source_node_id") or "")
    destination_node_id = str(envelope.get("destination_node_id") or "")
    scope = str(envelope.get("trust_scope_label") or "")
    payload_digest = str(envelope.get("payload_digest") or "")
    if not envelope_id:
        errors.append("envelope_id is required")
    if not source_node_id:
        errors.append("source_node_id is required")
    if not destination_node_id:
        errors.append("destination_node_id is required")
    if scope not in SUMMARY_EXCHANGE_SCOPES:
        errors.append("trust_scope_label is unsupported")
    summary = envelope.get("summary_payload")
    if not isinstance(summary, dict):
        errors.append("summary_payload must be an object")
    elif deterministic_digest(summary) != payload_digest:
        errors.append("summary payload digest does not match payload_digest")
    signing = validate_signature_metadata(
        envelope.get("signature_metadata") if isinstance(envelope.get("signature_metadata"), dict) else {},
        payload_digest=payload_digest,
        source_node_id=source_node_id,
        generated_at=timestamp,
    )
    errors.extend(signing["errors"])
    warnings.extend(signing["warnings"])
    if trust_profile is not None:
        mode = str((transport_session or {}).get("transport_mode") or "local-file")
        if not is_peer_approved(
            trust_profile,
            destination_node_id,
            trust_scope_label=scope,
            transport_mode=mode,
            generated_at=timestamp,
        ):
            errors.append("destination node is not approved by trust profile")
    if transport_session is not None:
        _validate_transport_hook(envelope, transport_session, errors=errors)
    _validate_replay_hook(
        envelope,
        seen_nonces=seen_nonces,
        last_sequence_by_node=last_sequence_by_node,
        generated_at=timestamp,
        errors=errors,
        warnings=warnings,
    )
    status = _verification_status(errors)
    return build_verification_status_record(
        envelope_id=envelope_id,
        payload_digest=payload_digest,
        status=status,
        errors=errors,
        warnings=warnings,
        verified_at=timestamp,
    )


def verify_signed_runtime_summary_envelope(
    envelope: dict[str, Any],
    *,
    trust_profile: dict[str, Any] | None = None,
    transport_session: dict[str, Any] | None = None,
    seen_nonces: Iterable[str] | None = None,
    last_sequence_by_node: dict[str, int] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    verification = validate_signed_runtime_summary_envelope(
        envelope,
        trust_profile=trust_profile,
        transport_session=transport_session,
        seen_nonces=seen_nonces,
        last_sequence_by_node=last_sequence_by_node,
        generated_at=generated_at,
    )
    status = "accepted" if verification["verification_status"] == "metadata-valid" else _rejection_status(verification["errors"])
    return {
        **dict(envelope),
        "exchange_status": status,
        "verification_status": verification,
        **SIGNING_SAFETY_FLAGS,
    }


def build_exchange_summary(
    envelopes: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = sorted([dict(row) for row in envelopes], key=lambda item: str(item.get("envelope_id") or ""))
    by_status: dict[str, int] = {}
    by_scope: dict[str, int] = {}
    for row in rows:
        status = str(row.get("exchange_status") or "unknown")
        scope = str(row.get("trust_scope_label") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
        by_scope[scope] = by_scope.get(scope, 0) + 1
    return {
        "record_type": "signed_runtime_summary_exchange_summary",
        "record_version": SIGNING_RECORD_VERSION,
        "exchange_summary_id": _stable_id("signed-exchange-summary", timestamp, rows),
        "generated_at": timestamp,
        "envelope_count": len(rows),
        "by_status": dict(sorted(by_status.items())),
        "by_trust_scope": dict(sorted(by_scope.items())),
        "source_node_ids": sorted(set(str(row.get("source_node_id") or "") for row in rows if row.get("source_node_id"))),
        "destination_node_ids": sorted(set(str(row.get("destination_node_id") or "") for row in rows if row.get("destination_node_id"))),
        "envelopes": rows,
        **SIGNING_SAFETY_FLAGS,
    }


def deterministic_exchange_json(record: dict[str, Any]) -> str:
    return canonical_json(record)


def _validated_transport(
    transport_session: dict[str, Any],
    *,
    source_node_id: str,
    destination_node_id: str,
    trust_scope_label: str,
) -> dict[str, Any]:
    try:
        transport = trusted_transport_session_to_dict(transport_session)
    except TrustedTransportError as exc:
        raise SignedExchangeError(str(exc)) from exc
    if transport.get("source_node_id") != source_node_id:
        raise SignedExchangeError("transport session source does not match envelope source")
    if transport.get("destination_node_id") != destination_node_id:
        raise SignedExchangeError("transport session destination does not match envelope destination")
    if transport.get("trust_scope_label") != trust_scope_label:
        raise SignedExchangeError("transport session trust scope does not match envelope scope")
    return transport


def _validate_transport_hook(envelope: dict[str, Any], transport_session: dict[str, Any], *, errors: list[str]) -> None:
    transport = trusted_transport_session_to_dict(transport_session)
    if envelope.get("transport_session_id") != transport.get("session_id"):
        errors.append("transport_session_id does not match transport session")
    if envelope.get("source_node_id") != transport.get("source_node_id"):
        errors.append("source_node_id does not match transport session")
    if envelope.get("destination_node_id") != transport.get("destination_node_id"):
        errors.append("destination_node_id does not match transport session")
    if envelope.get("trust_scope_label") != transport.get("trust_scope_label"):
        errors.append("trust_scope_label does not match transport session")


def _validate_replay_hook(
    envelope: dict[str, Any],
    *,
    seen_nonces: Iterable[str] | None,
    last_sequence_by_node: dict[str, int] | None,
    generated_at: str,
    errors: list[str],
    warnings: list[str],
) -> None:
    nonce = str(envelope.get("nonce") or "")
    source_node_id = str(envelope.get("source_node_id") or "")
    sequence = envelope.get("sequence")
    replay = envelope.get("replay_window") if isinstance(envelope.get("replay_window"), dict) else {}
    if not nonce:
        errors.append("nonce is required")
    if nonce and nonce in set(str(item) for item in seen_nonces or []):
        errors.append("nonce has already been seen in replay window")
    if not isinstance(sequence, int) or sequence < 0:
        errors.append("sequence must be a non-negative integer")
    last_sequence = (last_sequence_by_node or {}).get(source_node_id)
    if isinstance(sequence, int) and isinstance(last_sequence, int) and sequence <= last_sequence:
        errors.append("sequence is not greater than last accepted sequence for source node")
    issued_at = str(envelope.get("issued_at") or "")
    expires_at = str(envelope.get("expires_at") or "")
    if _is_expired(expires_at, generated_at=generated_at):
        errors.append("exchange envelope is expired")
    window_started_at = str(replay.get("window_started_at") or "")
    window_expires_at = str(replay.get("window_expires_at") or "")
    if not window_started_at or not window_expires_at:
        errors.append("replay window timestamps are required")
    elif issued_at and (_parse_time(issued_at) < _parse_time(window_started_at) or _parse_time(issued_at) > _parse_time(window_expires_at)):
        errors.append("issued_at is outside the replay window")
    if replay.get("replay_safe_records") is not True:
        errors.append("replay window must mark records as replay-safe")
    if not envelope.get("signature_metadata", {}).get("signature_value"):
        warnings.append("verification is metadata-only; no cryptographic signature value was checked")


def _verification_status(errors: list[str]) -> str:
    return "metadata-invalid" if errors else "metadata-valid"


def _rejection_status(errors: list[str]) -> str:
    material = " ".join(errors)
    if "approved" in material or "trust" in material:
        return "untrusted"
    if "nonce" in material or "sequence" in material:
        return "replayed"
    if "expired" in material or "outside the replay window" in material:
        return "stale"
    if errors:
        return "rejected"
    return "accepted"


def _trust_scope(value: Any) -> str:
    scope = str(value or "")
    if scope not in SUMMARY_EXCHANGE_SCOPES:
        raise SignedExchangeError(f"unsupported trust_scope_label: {scope}")
    return scope


def _source_refs(values: Iterable[str] | None, *, fallback: str) -> list[str]:
    refs = sorted(set(str(item) for item in values or [] if str(item).strip()))
    refs.append(fallback)
    return sorted(set(refs))


def _sorted_dict(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in sorted(value):
        item = value[key]
        result[str(key)] = _sorted_dict(item) if isinstance(item, dict) else item
    return result


def _is_expired(value: Any, *, generated_at: str) -> bool:
    if not value:
        return False
    return _parse_time(str(value)) <= _parse_time(generated_at)


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise SignedExchangeError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + deterministic_digest(material).removeprefix("sha256:")[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
