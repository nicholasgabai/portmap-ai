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
from .transport_security import (  # noqa: E402
    AUTHENTICATION_STATES,
    CERTIFICATE_MODES,
    TRANSPORT_PROFILE_NAMES,
    TRANSPORT_ROLES,
    TRANSPORT_STATES,
    TransportSecurityError,
    TransportSecurityProfile,
    create_transport_security_profile,
    summarize_transport_profiles,
)
from .session_negotiation import (  # noqa: E402
    NEGOTIATION_TRUST_STATES,
    ROLE_PAIRS,
    SessionNegotiationError,
    SessionNegotiationPreview,
    create_session_negotiation_preview,
    summarize_session_negotiations,
)
from .secure_config import (  # noqa: E402
    BOOTSTRAP_MODES,
    PERSISTENCE_MODES,
    SECURE_CONFIG_PROFILE_NAMES,
    SECURE_CONFIG_STATES,
    SecureConfigError,
    SecureConfigProfile,
    create_secure_config_profile,
    summarize_secure_config_profiles,
)
from .secrets import (  # noqa: E402
    EXPOSURE_RISK_STATES,
    SECRET_CLASSES,
    SECRET_STORAGE_MODES,
    SecretManagementPreview,
    SecretsManagementError,
    create_secret_management_preview,
    summarize_secret_management_previews,
)
from .rbac import (  # noqa: E402
    ACCESS_STATES,
    AUTHORITY_STATES,
    PERMISSION_SCOPES,
    RBAC_ROLE_NAMES,
    RBACError,
    RBACRole,
    create_rbac_role,
    summarize_rbac_roles,
)
from .permissions import (  # noqa: E402
    ENFORCEMENT_MODES,
    PERMISSION_ACTIONS,
    PERMISSION_STATES,
    PermissionEvaluationPreview,
    PermissionPreviewError,
    evaluate_permission_preview,
    summarize_permission_matrix,
)
from .integrity import (  # noqa: E402
    INTEGRITY_STATES,
    INTEGRITY_TARGET_CLASSES,
    INTEGRITY_TARGET_NAMES,
    INTEGRITY_VERIFICATION_MODES,
    IntegrityError,
    IntegrityTargetRecord,
    create_integrity_target_record,
    summarize_integrity_targets,
)
from .tamper_detection import (  # noqa: E402
    TAMPER_DETECTION_NAMES,
    TAMPER_DETECTION_STATES,
    TAMPER_ENFORCEMENT_MODES,
    TAMPER_SEVERITIES,
    TamperDetectionError,
    TamperDetectionPreview,
    build_tamper_previews_from_integrity,
    create_tamper_detection_preview,
    summarize_tamper_detection,
)
from .update_verification import (  # noqa: E402
    UPDATE_COMPATIBILITY_STATES,
    UPDATE_DIGEST_STATES,
    UPDATE_SIGNATURE_STATES,
    UPDATE_TARGETS,
    UPDATE_VERIFICATION_STATES,
    UpdateVerificationError,
    UpdateVerificationRecord,
    create_update_verification_record,
    summarize_update_verification,
)
from .rollback_plans import (  # noqa: E402
    ROLLBACK_NAMES,
    ROLLBACK_STATES,
    ROLLBACK_TYPES,
    RollbackPlanError,
    RollbackPreviewRecord,
    create_rollback_preview_record,
    summarize_rollback_previews,
)

__all__ = [
    "ACCESS_STATES",
    "AUTHENTICATION_STATES",
    "AUTHORITY_STATES",
    "BOOTSTRAP_MODES",
    "CERTIFICATE_MODES",
    "ENROLLMENT_IDENTITY_STATES",
    "ENROLLMENT_STATES",
    "ENFORCEMENT_MODES",
    "EXPOSURE_RISK_STATES",
    "INTEGRITY_STATES",
    "INTEGRITY_TARGET_CLASSES",
    "INTEGRITY_TARGET_NAMES",
    "INTEGRITY_VERIFICATION_MODES",
    "LOGICAL_NODE_CLASSES",
    "NEGOTIATION_TRUST_STATES",
    "NODE_ID_PATTERN",
    "PERMISSION_ACTIONS",
    "PERMISSION_SCOPES",
    "PERMISSION_STATES",
    "PERSISTENCE_MODES",
    "RBAC_ROLE_NAMES",
    "ROLLBACK_NAMES",
    "ROLLBACK_STATES",
    "ROLLBACK_TYPES",
    "ROLE_PAIRS",
    "SECURE_CONFIG_PROFILE_NAMES",
    "SECURE_CONFIG_STATES",
    "SECRET_CLASSES",
    "SECRET_KEYWORDS",
    "SECRET_STORAGE_MODES",
    "TAMPER_DETECTION_NAMES",
    "TAMPER_DETECTION_STATES",
    "TAMPER_ENFORCEMENT_MODES",
    "TAMPER_SEVERITIES",
    "TRUST_IDENTITY_STATES",
    "TRUST_RELATIONSHIP_STATES",
    "TRANSPORT_PROFILE_NAMES",
    "TRANSPORT_ROLES",
    "TRANSPORT_STATES",
    "UPDATE_COMPATIBILITY_STATES",
    "UPDATE_DIGEST_STATES",
    "UPDATE_SIGNATURE_STATES",
    "UPDATE_TARGETS",
    "UPDATE_VERIFICATION_STATES",
    "SecureEnrollmentError",
    "IntegrityError",
    "IntegrityTargetRecord",
    "SecureNodeIdentity",
    "SecureNodeIdentityError",
    "SecretManagementPreview",
    "SecretsManagementError",
    "SessionNegotiationError",
    "SessionNegotiationPreview",
    "PermissionEvaluationPreview",
    "PermissionPreviewError",
    "RBACError",
    "RBACRole",
    "RollbackPlanError",
    "RollbackPreviewRecord",
    "SecureConfigError",
    "SecureConfigProfile",
    "SecureTrustChainError",
    "TamperDetectionError",
    "TamperDetectionPreview",
    "TransportSecurityError",
    "TransportSecurityProfile",
    "TrustRelationshipSummary",
    "UpdateVerificationError",
    "UpdateVerificationRecord",
    "VALID_NODE_ROLES",
    "WorkerEnrollmentPreview",
    "build_trust_chain_summary",
    "build_tamper_previews_from_integrity",
    "create_integrity_target_record",
    "create_rollback_preview_record",
    "create_secure_node_identity",
    "create_secret_management_preview",
    "create_session_negotiation_preview",
    "create_secure_config_profile",
    "create_rbac_role",
    "create_tamper_detection_preview",
    "create_trust_relationship_summary",
    "create_transport_security_profile",
    "create_update_verification_record",
    "create_worker_enrollment_preview",
    "extract_bearer_token",
    "identity_regeneration_preview",
    "identity_rotation_preview",
    "is_secret_key",
    "evaluate_permission_preview",
    "redact_secret",
    "scrub_secrets",
    "summarize_secret_management_previews",
    "summarize_integrity_targets",
    "summarize_secure_config_profiles",
    "summarize_session_negotiations",
    "summarize_permission_matrix",
    "summarize_rbac_roles",
    "summarize_rollback_previews",
    "summarize_tamper_detection",
    "summarize_transport_profiles",
    "summarize_update_verification",
    "token_fingerprint",
    "validate_node_identity",
    "verify_bearer_header",
    "verify_token",
]
