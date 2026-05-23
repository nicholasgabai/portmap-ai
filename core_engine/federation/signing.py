from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from core_engine.export.node_manifest import digest_payload
from core_engine.federation.trust import TRUST_SAFETY_FLAGS, normalize_node_identity_reference


SIGNING_RECORD_VERSION = 1
SIGNING_STATUSES = frozenset({"metadata-only", "signed", "unsigned", "invalid"})
VERIFICATION_STATUSES = frozenset({"not-verified", "metadata-valid", "metadata-invalid", "rejected"})
SIGNING_SAFETY_FLAGS = {
    **TRUST_SAFETY_FLAGS,
    "private_signing_material_stored": False,
    "raw_private_key_stored": False,
    "signature_metadata_only": True,
}


class FederationSigningError(ValueError):
    """Raised when signing metadata cannot be built or validated."""


def canonical_json(payload: Any) -> str:
    """Return canonical JSON for deterministic federation digests."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def deterministic_digest(payload: Any) -> str:
    return digest_payload(json.loads(canonical_json(payload)))


def build_payload_digest_record(payload: Any, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    canonical = canonical_json(payload)
    return {
        "record_type": "federation_payload_digest",
        "record_version": SIGNING_RECORD_VERSION,
        "digest_algorithm": "sha256",
        "canonicalization": "json-sort-keys-compact",
        "canonical_size_bytes": len(canonical.encode("utf-8")),
        "payload_digest": digest_payload(json.loads(canonical)),
        "generated_at": timestamp,
        **SIGNING_SAFETY_FLAGS,
    }


def build_signature_metadata(
    *,
    source_node: dict[str, Any],
    payload_digest: str,
    key_reference: str,
    signature_value: str | None = None,
    signature_algorithm: str = "metadata-sha256",
    signed_at: str | None = None,
) -> dict[str, Any]:
    timestamp = signed_at or _now()
    source = normalize_node_identity_reference(source_node)
    if not str(payload_digest or "").startswith("sha256:"):
        raise FederationSigningError("payload_digest must use sha256: prefix")
    if not str(key_reference or "").strip():
        raise FederationSigningError("key_reference is required")
    status = "signed" if signature_value else "metadata-only"
    payload = {
        "record_type": "federation_signature_metadata",
        "record_version": SIGNING_RECORD_VERSION,
        "source_node_id": source["node_id"],
        "source_node_role": source["role"],
        "key_reference": str(key_reference),
        "signature_algorithm": str(signature_algorithm or "metadata-sha256"),
        "signature_value": str(signature_value or ""),
        "signature_value_stored": bool(signature_value),
        "payload_digest": str(payload_digest),
        "signed_at": timestamp,
        "signing_status": status,
        **SIGNING_SAFETY_FLAGS,
    }
    payload["signature_metadata_id"] = _stable_id("signature-metadata", payload_digest, source["node_id"], payload["key_reference"], timestamp)
    return payload


def build_signing_status_record(
    signature_metadata: dict[str, Any] | None,
    *,
    status: str | None = None,
    errors: list[str] | None = None,
    warnings: list[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    row = dict(signature_metadata or {})
    signing_status = str(status or row.get("signing_status") or "unsigned")
    if signing_status not in SIGNING_STATUSES:
        signing_status = "invalid"
    payload = {
        "record_type": "federation_signing_status",
        "record_version": SIGNING_RECORD_VERSION,
        "status": signing_status,
        "payload_digest": str(row.get("payload_digest") or ""),
        "signature_metadata_id": str(row.get("signature_metadata_id") or ""),
        "source_node_id": str(row.get("source_node_id") or ""),
        "key_reference": str(row.get("key_reference") or ""),
        "errors": sorted(str(item) for item in errors or []),
        "warnings": sorted(str(item) for item in warnings or []),
        "generated_at": timestamp,
        **SIGNING_SAFETY_FLAGS,
    }
    payload["status_id"] = _stable_id("signing-status", payload["status"], payload["payload_digest"], payload["errors"], timestamp)
    return payload


def build_verification_status_record(
    *,
    envelope_id: str,
    payload_digest: str,
    status: str,
    errors: list[str] | None = None,
    warnings: list[str] | None = None,
    verified_at: str | None = None,
) -> dict[str, Any]:
    timestamp = verified_at or _now()
    verification_status = str(status or "not-verified")
    if verification_status not in VERIFICATION_STATUSES:
        verification_status = "metadata-invalid"
    payload = {
        "record_type": "federation_verification_status",
        "record_version": SIGNING_RECORD_VERSION,
        "envelope_id": str(envelope_id or ""),
        "payload_digest": str(payload_digest or ""),
        "verification_status": verification_status,
        "errors": sorted(str(item) for item in errors or []),
        "warnings": sorted(str(item) for item in warnings or []),
        "verified_at": timestamp,
        "cryptographic_signature_verified": False,
        **SIGNING_SAFETY_FLAGS,
    }
    payload["verification_id"] = _stable_id("verification-status", envelope_id, payload_digest, verification_status, payload["errors"], timestamp)
    return payload


def validate_signature_metadata(
    signature_metadata: dict[str, Any],
    *,
    payload_digest: str,
    source_node_id: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(signature_metadata, dict):
        return build_signing_status_record(None, status="invalid", errors=["signature metadata must be an object"], generated_at=timestamp)
    if signature_metadata.get("payload_digest") != payload_digest:
        errors.append("signature metadata payload_digest does not match envelope payload digest")
    if signature_metadata.get("source_node_id") != source_node_id:
        errors.append("signature metadata source node does not match envelope source node")
    if not str(signature_metadata.get("key_reference") or "").strip():
        errors.append("signature metadata key_reference is required")
    if signature_metadata.get("private_signing_material_stored") is not False:
        errors.append("private signing material must not be stored")
    if not signature_metadata.get("signature_value"):
        warnings.append("signature value is not present; metadata-only signing status")
    status = "invalid" if errors else str(signature_metadata.get("signing_status") or "metadata-only")
    return build_signing_status_record(signature_metadata, status=status, errors=errors, warnings=warnings, generated_at=timestamp)


def _stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}-" + deterministic_digest(parts).removeprefix("sha256:")[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
