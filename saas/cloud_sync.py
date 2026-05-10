from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable


SYNC_SCHEMA_VERSION = "1"
VALID_CONFLICT_POLICIES = {"prefer_local", "prefer_remote", "manual_review"}


@dataclass(frozen=True)
class SyncManifest:
    tenant_id: str
    workspace_id: str
    payload_type: str
    encrypted_payload: str
    payload_sha256: str
    payload_hmac: str
    nonce: str
    key_fingerprint: str
    created_at: int = field(default_factory=lambda: int(time.time()))
    schema_version: str = SYNC_SCHEMA_VERSION
    offline_compatible: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "workspace_id": self.workspace_id,
            "payload_type": self.payload_type,
            "encrypted_payload": self.encrypted_payload,
            "payload_sha256": self.payload_sha256,
            "payload_hmac": self.payload_hmac,
            "nonce": self.nonce,
            "key_fingerprint": self.key_fingerprint,
            "created_at": self.created_at,
            "offline_compatible": self.offline_compatible,
            "cloud_sync_optional": True,
        }


def export_sync_manifest(
    payload: dict[str, Any],
    *,
    tenant_id: str,
    workspace_id: str,
    key: str,
    payload_type: str = "configuration",
) -> dict[str, Any]:
    if not key:
        raise ValueError("sync key is required")
    if not tenant_id:
        raise ValueError("tenant_id is required")
    if not workspace_id:
        raise ValueError("workspace_id is required")
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    nonce = os.urandom(16)
    ciphertext = _xor_stream(encoded, key, nonce)
    manifest = SyncManifest(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        payload_type=payload_type,
        encrypted_payload=base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        payload_sha256=hashlib.sha256(encoded).hexdigest(),
        payload_hmac=hmac.new(_key_bytes(key), nonce + ciphertext, hashlib.sha256).hexdigest(),
        nonce=base64.urlsafe_b64encode(nonce).decode("ascii"),
        key_fingerprint=_fingerprint(key),
    )
    return manifest.to_dict()


def import_sync_manifest(manifest: SyncManifest | dict[str, Any], *, key: str) -> dict[str, Any]:
    data = manifest.to_dict() if isinstance(manifest, SyncManifest) else dict(manifest)
    errors = validate_sync_manifest(data)
    if errors:
        raise ValueError("; ".join(errors))
    if data.get("key_fingerprint") != _fingerprint(key):
        raise ValueError("sync key fingerprint mismatch")
    nonce = base64.urlsafe_b64decode(str(data["nonce"]).encode("ascii"))
    ciphertext = base64.urlsafe_b64decode(str(data["encrypted_payload"]).encode("ascii"))
    expected_hmac = hmac.new(_key_bytes(key), nonce + ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_hmac, str(data["payload_hmac"])):
        raise ValueError("sync manifest integrity check failed")
    plaintext = _xor_stream(ciphertext, key, nonce)
    digest = hashlib.sha256(plaintext).hexdigest()
    if not hmac.compare_digest(digest, str(data["payload_sha256"])):
        raise ValueError("sync manifest payload digest mismatch")
    payload = json.loads(plaintext.decode("utf-8"))
    return {
        "ok": True,
        "tenant_id": data["tenant_id"],
        "workspace_id": data["workspace_id"],
        "payload_type": data["payload_type"],
        "payload": payload,
        "offline_compatible": bool(data.get("offline_compatible", True)),
    }


def validate_sync_manifest(manifest: dict[str, Any]) -> list[str]:
    if not isinstance(manifest, dict):
        return ["sync manifest must be an object"]
    errors: list[str] = []
    if manifest.get("schema_version") != SYNC_SCHEMA_VERSION:
        errors.append(f"schema_version must be {SYNC_SCHEMA_VERSION}")
    for field_name in (
        "tenant_id",
        "workspace_id",
        "payload_type",
        "encrypted_payload",
        "payload_sha256",
        "payload_hmac",
        "nonce",
        "key_fingerprint",
    ):
        if not isinstance(manifest.get(field_name), str) or not manifest.get(field_name):
            errors.append(f"{field_name} is required")
    if manifest.get("cloud_sync_optional") is not True:
        errors.append("cloud_sync_optional must be true")
    return errors


def resolve_sync_conflicts(
    local_records: Iterable[dict[str, Any]],
    remote_records: Iterable[dict[str, Any]],
    *,
    key_field: str = "id",
    policy: str = "manual_review",
) -> dict[str, Any]:
    if policy not in VALID_CONFLICT_POLICIES:
        raise ValueError(f"policy must be one of: {', '.join(sorted(VALID_CONFLICT_POLICIES))}")
    local = {str(item.get(key_field)): item for item in local_records if isinstance(item, dict) and item.get(key_field)}
    remote = {str(item.get(key_field)): item for item in remote_records if isinstance(item, dict) and item.get(key_field)}
    merged: dict[str, dict[str, Any]] = {}
    conflicts: list[dict[str, Any]] = []
    for record_id in sorted(set(local) | set(remote)):
        local_item = local.get(record_id)
        remote_item = remote.get(record_id)
        if local_item and remote_item and local_item != remote_item:
            conflicts.append({"id": record_id, "local": local_item, "remote": remote_item})
            if policy == "prefer_local":
                merged[record_id] = local_item
            elif policy == "prefer_remote":
                merged[record_id] = remote_item
            continue
        merged[record_id] = local_item or remote_item or {}
    return {
        "ok": policy != "manual_review" or not conflicts,
        "policy": policy,
        "records": list(merged.values()),
        "conflicts": conflicts,
        "requires_review": bool(conflicts) and policy == "manual_review",
    }


def _xor_stream(data: bytes, key: str, nonce: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < len(data):
        block = hashlib.sha256(_key_bytes(key) + nonce + counter.to_bytes(8, "big")).digest()
        output.extend(block)
        counter += 1
    return bytes(byte ^ output[index] for index, byte in enumerate(data))


def _key_bytes(key: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", str(key).encode("utf-8"), b"portmap-ai-sync", 100_000)


def _fingerprint(key: str) -> str:
    return hashlib.sha256(str(key).encode("utf-8")).hexdigest()[:16]


__all__ = [
    "SYNC_SCHEMA_VERSION",
    "VALID_CONFLICT_POLICIES",
    "SyncManifest",
    "export_sync_manifest",
    "import_sync_manifest",
    "resolve_sync_conflicts",
    "validate_sync_manifest",
]
