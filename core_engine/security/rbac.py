from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


RBAC_ROLE_NAMES = {
    "admin",
    "security_operator",
    "analyst",
    "auditor",
    "read_only",
    "service_account",
}
PERMISSION_SCOPES = {"full", "security_operations", "analysis", "audit", "read_only", "service_limited"}
AUTHORITY_STATES = {"none", "view", "request", "approve", "execute", "manage"}
ACCESS_STATES = {"none", "read", "limited", "full", "service"}


class RBACError(ValueError):
    """Raised when an RBAC role readiness record is malformed."""


@dataclass(frozen=True, slots=True)
class RBACRole:
    role_name: str
    permission_scope: str
    remediation_authority: str
    configuration_authority: str
    enrollment_authority: str
    audit_visibility: str
    export_authority: str
    dashboard_access: str
    api_access: str
    advisory_notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _validate_choice(self.role_name, RBAC_ROLE_NAMES, "role_name")
        _validate_choice(self.permission_scope, PERMISSION_SCOPES, "permission_scope")
        _validate_choice(self.remediation_authority, AUTHORITY_STATES, "remediation_authority")
        _validate_choice(self.configuration_authority, AUTHORITY_STATES, "configuration_authority")
        _validate_choice(self.enrollment_authority, AUTHORITY_STATES, "enrollment_authority")
        _validate_choice(self.audit_visibility, ACCESS_STATES, "audit_visibility")
        _validate_choice(self.export_authority, AUTHORITY_STATES, "export_authority")
        _validate_choice(self.dashboard_access, ACCESS_STATES, "dashboard_access")
        _validate_choice(self.api_access, ACCESS_STATES, "api_access")
        if not isinstance(self.advisory_notes, tuple) or not all(isinstance(note, str) for note in self.advisory_notes):
            raise RBACError("advisory_notes must be a tuple of strings")

    @property
    def export_safe(self) -> bool:
        return True

    @property
    def preview_only(self) -> bool:
        return True

    @property
    def live_auth_enforced(self) -> bool:
        return False

    @property
    def user_database_created(self) -> bool:
        return False

    @property
    def credentials_stored(self) -> bool:
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "role_name": self.role_name,
            "permission_scope": self.permission_scope,
            "remediation_authority": self.remediation_authority,
            "configuration_authority": self.configuration_authority,
            "enrollment_authority": self.enrollment_authority,
            "audit_visibility": self.audit_visibility,
            "export_authority": self.export_authority,
            "dashboard_access": self.dashboard_access,
            "api_access": self.api_access,
            "advisory_notes": list(self.advisory_notes),
            "export_safe": self.export_safe,
            "preview_only": self.preview_only,
            "live_auth_enforced": self.live_auth_enforced,
            "user_database_created": self.user_database_created,
            "credentials_stored": self.credentials_stored,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RBACRole":
        if not isinstance(payload, dict):
            raise RBACError("RBAC role must be an object")
        allowed = {
            "role_name",
            "permission_scope",
            "remediation_authority",
            "configuration_authority",
            "enrollment_authority",
            "audit_visibility",
            "export_authority",
            "dashboard_access",
            "api_access",
            "advisory_notes",
            "export_safe",
            "preview_only",
            "live_auth_enforced",
            "user_database_created",
            "credentials_stored",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise RBACError(f"unknown RBAC role fields: {', '.join(unknown)}")
        _reject_true(payload, "live_auth_enforced", "RBAC readiness records cannot enforce live auth")
        _reject_true(payload, "user_database_created", "RBAC readiness records cannot create user databases")
        _reject_true(payload, "credentials_stored", "RBAC readiness records cannot store credentials")
        data = {key: payload[key] for key in (
            "role_name",
            "permission_scope",
            "remediation_authority",
            "configuration_authority",
            "enrollment_authority",
            "audit_visibility",
            "export_authority",
            "dashboard_access",
            "api_access",
            "advisory_notes",
        ) if key in payload}
        if "advisory_notes" in data:
            data["advisory_notes"] = tuple(data["advisory_notes"])
        try:
            return cls(**data)
        except TypeError as exc:
            raise RBACError(f"malformed RBAC role: {exc}") from exc


def create_rbac_role(role_name: str) -> RBACRole:
    _validate_choice(role_name, RBAC_ROLE_NAMES, "role_name")
    if role_name == "admin":
        return RBACRole(
            role_name=role_name,
            permission_scope="full",
            remediation_authority="manage",
            configuration_authority="manage",
            enrollment_authority="manage",
            audit_visibility="full",
            export_authority="manage",
            dashboard_access="full",
            api_access="full",
            advisory_notes=("future live enforcement must require explicit authentication",),
        )
    if role_name == "security_operator":
        return RBACRole(
            role_name=role_name,
            permission_scope="security_operations",
            remediation_authority="approve",
            configuration_authority="request",
            enrollment_authority="approve",
            audit_visibility="limited",
            export_authority="approve",
            dashboard_access="full",
            api_access="limited",
            advisory_notes=("can approve but not directly manage RBAC roles",),
        )
    if role_name == "analyst":
        return RBACRole(
            role_name=role_name,
            permission_scope="analysis",
            remediation_authority="request",
            configuration_authority="none",
            enrollment_authority="none",
            audit_visibility="limited",
            export_authority="request",
            dashboard_access="full",
            api_access="read",
            advisory_notes=("can request remediation review but cannot approve execution",),
        )
    if role_name == "auditor":
        return RBACRole(
            role_name=role_name,
            permission_scope="audit",
            remediation_authority="none",
            configuration_authority="none",
            enrollment_authority="none",
            audit_visibility="full",
            export_authority="view",
            dashboard_access="read",
            api_access="read",
            advisory_notes=("audit role is read-focused with broad audit visibility",),
        )
    if role_name == "read_only":
        return RBACRole(
            role_name=role_name,
            permission_scope="read_only",
            remediation_authority="none",
            configuration_authority="none",
            enrollment_authority="none",
            audit_visibility="read",
            export_authority="none",
            dashboard_access="read",
            api_access="read",
            advisory_notes=("read-only role cannot export or approve changes",),
        )
    return RBACRole(
        role_name=role_name,
        permission_scope="service_limited",
        remediation_authority="none",
        configuration_authority="none",
        enrollment_authority="none",
        audit_visibility="none",
        export_authority="none",
        dashboard_access="none",
        api_access="service",
        advisory_notes=("service accounts are non-human readiness records only",),
    )


def summarize_rbac_roles(role_names: list[str] | None = None) -> dict[str, Any]:
    names = role_names or sorted(RBAC_ROLE_NAMES)
    roles = [create_rbac_role(role_name) for role_name in names]
    return {
        "summary_type": "rbac_roles",
        "role_count": len(roles),
        "roles": [role.to_dict() for role in roles],
        "export_safe": True,
        "preview_only": True,
        "live_auth_enforced": False,
        "user_database_created": False,
        "credentials_stored": False,
    }


def _reject_true(payload: dict[str, Any], field_name: str, message: str) -> None:
    if payload.get(field_name) is True:
        raise RBACError(message)


def _validate_choice(value: str, allowed: set[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise RBACError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")
