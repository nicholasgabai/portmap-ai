from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Mapping

SECRET_KEYWORDS = ("token", "secret", "password", "passwd", "key", "credential")
NODE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
VALID_NODE_ROLES = {"orchestrator", "master", "worker"}


def extract_bearer_token(header: str | None) -> str | None:
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    return value.strip()


def verify_token(candidate: str | None, expected: str | None) -> bool:
    if not expected:
        return True
    if not candidate:
        return False
    return hmac.compare_digest(str(candidate), str(expected))


def verify_bearer_header(header: str | None, expected: str | None) -> bool:
    return verify_token(extract_bearer_token(header), expected)


def token_fingerprint(token: str | None) -> str:
    if not token:
        return ""
    digest = hashlib.sha256(str(token).encode("utf-8")).hexdigest()
    return digest[:12]


def redact_secret(value: Any) -> str:
    if value in {None, ""}:
        return ""
    return f"<redacted:{token_fingerprint(str(value))}>"


def is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(keyword in lowered for keyword in SECRET_KEYWORDS)


def scrub_secrets(value: Any) -> Any:
    if isinstance(value, Mapping):
        scrubbed: dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            scrubbed[key_str] = redact_secret(item) if is_secret_key(key_str) else scrub_secrets(item)
        return scrubbed
    if isinstance(value, list):
        return [scrub_secrets(item) for item in value]
    return value


def validate_node_identity(node_id: Any, role: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(node_id, str) or not NODE_ID_PATTERN.match(node_id):
        errors.append("node_id must be 1-128 characters using letters, numbers, dot, underscore, colon, or dash")
    if not isinstance(role, str) or role.lower() not in VALID_NODE_ROLES:
        errors.append(f"role must be one of: {', '.join(sorted(VALID_NODE_ROLES))}")
    return errors


from .enrollment import (  # noqa: E402
    ENROLLMENT_STATES,
    SecureEnrollmentError,
    WorkerEnrollmentPreview,
    create_worker_enrollment_preview,
)
from .node_identity import (  # noqa: E402
    ENROLLMENT_IDENTITY_STATES,
    LOGICAL_NODE_CLASSES,
    TRUST_IDENTITY_STATES,
    SecureNodeIdentity,
    SecureNodeIdentityError,
    create_secure_node_identity,
    identity_regeneration_preview,
    identity_rotation_preview,
)
from .trust_chain import (  # noqa: E402
    TRUST_RELATIONSHIP_STATES,
    SecureTrustChainError,
    TrustRelationshipSummary,
    build_trust_chain_summary,
    create_trust_relationship_summary,
)

__all__ = [
    "ENROLLMENT_IDENTITY_STATES",
    "ENROLLMENT_STATES",
    "LOGICAL_NODE_CLASSES",
    "NODE_ID_PATTERN",
    "SECRET_KEYWORDS",
    "TRUST_IDENTITY_STATES",
    "TRUST_RELATIONSHIP_STATES",
    "SecureEnrollmentError",
    "SecureNodeIdentity",
    "SecureNodeIdentityError",
    "SecureTrustChainError",
    "TrustRelationshipSummary",
    "VALID_NODE_ROLES",
    "WorkerEnrollmentPreview",
    "build_trust_chain_summary",
    "create_secure_node_identity",
    "create_trust_relationship_summary",
    "create_worker_enrollment_preview",
    "extract_bearer_token",
    "identity_regeneration_preview",
    "identity_rotation_preview",
    "is_secret_key",
    "redact_secret",
    "scrub_secrets",
    "token_fingerprint",
    "validate_node_identity",
    "verify_bearer_header",
    "verify_token",
]
