from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .rbac import RBAC_ROLE_NAMES, RBACError, RBACRole, create_rbac_role


PERMISSION_ACTIONS = {
    "view_telemetry",
    "view_history",
    "export_runtime",
    "approve_remediation",
    "execute_remediation",
    "rotate_node_identity",
    "approve_enrollment",
    "modify_config",
    "view_audit_log",
    "manage_roles",
}
PERMISSION_STATES = {"allowed", "denied", "requires_approval", "unavailable"}
ENFORCEMENT_MODES = {"preview", "advisory", "future_enforced"}


class PermissionPreviewError(ValueError):
    """Raised when a permission evaluation preview is malformed."""


@dataclass(frozen=True, slots=True)
class PermissionEvaluationPreview:
    requested_action: str
    role_name: str
    permission_state: str
    enforcement_mode: str
    reason: str
    operator_action_required: bool
    preview_only: bool = True
    destructive_action: bool = False

    def __post_init__(self) -> None:
        _validate_choice(self.requested_action, PERMISSION_ACTIONS, "requested_action")
        _validate_choice(self.role_name, RBAC_ROLE_NAMES, "role_name")
        _validate_choice(self.permission_state, PERMISSION_STATES, "permission_state")
        _validate_choice(self.enforcement_mode, ENFORCEMENT_MODES, "enforcement_mode")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise PermissionPreviewError("reason must be a non-empty string")
        if not isinstance(self.operator_action_required, bool):
            raise PermissionPreviewError("operator_action_required must be a boolean")
        if self.preview_only is not True:
            raise PermissionPreviewError("permission evaluation records must remain preview-only")
        if self.destructive_action is not False:
            raise PermissionPreviewError("permission evaluation records cannot be destructive")

    @property
    def live_auth_enforced(self) -> bool:
        return False

    @property
    def user_data_stored(self) -> bool:
        return False

    @property
    def credential_stored(self) -> bool:
        return False

    @property
    def export_safe(self) -> bool:
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_action": self.requested_action,
            "role_name": self.role_name,
            "permission_state": self.permission_state,
            "enforcement_mode": self.enforcement_mode,
            "reason": self.reason,
            "operator_action_required": self.operator_action_required,
            "preview_only": self.preview_only,
            "destructive_action": self.destructive_action,
            "live_auth_enforced": self.live_auth_enforced,
            "user_data_stored": self.user_data_stored,
            "credential_stored": self.credential_stored,
            "export_safe": self.export_safe,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "PermissionEvaluationPreview":
        if not isinstance(payload, dict):
            raise PermissionPreviewError("permission evaluation preview must be an object")
        allowed = {
            "requested_action",
            "role_name",
            "permission_state",
            "enforcement_mode",
            "reason",
            "operator_action_required",
            "preview_only",
            "destructive_action",
            "live_auth_enforced",
            "user_data_stored",
            "credential_stored",
            "export_safe",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise PermissionPreviewError(f"unknown permission preview fields: {', '.join(unknown)}")
        if payload.get("live_auth_enforced") is True:
            raise PermissionPreviewError("permission previews cannot enforce live auth")
        if payload.get("user_data_stored") is True:
            raise PermissionPreviewError("permission previews cannot store user data")
        if payload.get("credential_stored") is True:
            raise PermissionPreviewError("permission previews cannot store credentials")
        data = {key: payload[key] for key in (
            "requested_action",
            "role_name",
            "permission_state",
            "enforcement_mode",
            "reason",
            "operator_action_required",
            "preview_only",
            "destructive_action",
        ) if key in payload}
        try:
            return cls(**data)
        except TypeError as exc:
            raise PermissionPreviewError(f"malformed permission evaluation preview: {exc}") from exc


def evaluate_permission_preview(
    *,
    role: str | RBACRole,
    requested_action: str,
    enforcement_mode: str = "preview",
) -> PermissionEvaluationPreview:
    role_record = create_rbac_role(role) if isinstance(role, str) else _coerce_role(role)
    _validate_choice(requested_action, PERMISSION_ACTIONS, "requested_action")
    _validate_choice(enforcement_mode, ENFORCEMENT_MODES, "enforcement_mode")
    state, reason = _evaluate(role_record, requested_action)
    return PermissionEvaluationPreview(
        requested_action=requested_action,
        role_name=role_record.role_name,
        permission_state=state,
        enforcement_mode=enforcement_mode,
        reason=reason,
        operator_action_required=state in {"requires_approval", "unavailable"},
    )


def summarize_permission_matrix(
    *,
    role_names: list[str] | None = None,
    actions: list[str] | None = None,
) -> dict[str, Any]:
    roles = role_names or sorted(RBAC_ROLE_NAMES)
    requested_actions = actions or sorted(PERMISSION_ACTIONS)
    previews = [
        evaluate_permission_preview(role=role_name, requested_action=action)
        for role_name in roles
        for action in requested_actions
    ]
    by_state = {state: 0 for state in sorted(PERMISSION_STATES)}
    for preview in previews:
        by_state[preview.permission_state] += 1
    return {
        "summary_type": "permission_matrix_preview",
        "preview_count": len(previews),
        "by_permission_state": by_state,
        "previews": [preview.to_dict() for preview in previews],
        "preview_only": True,
        "destructive_action": False,
        "live_auth_enforced": False,
        "user_data_stored": False,
        "credential_stored": False,
        "export_safe": True,
    }


def _evaluate(role: RBACRole, action: str) -> tuple[str, str]:
    if role.role_name == "service_account":
        return _service_account_state(action)
    if action in {"view_telemetry", "view_history"}:
        if role.dashboard_access in {"read", "limited", "full"} or role.api_access in {"read", "limited", "full"}:
            return "allowed", "role has read access to operator visibility"
        return "denied", "role has no telemetry or history visibility"
    if action == "export_runtime":
        return _authority_state(role.export_authority, "runtime export")
    if action == "approve_remediation":
        return _authority_state(role.remediation_authority, "remediation approval")
    if action == "execute_remediation":
        if role.remediation_authority in {"execute", "manage"}:
            return "requires_approval", "execution remains advisory until live enforcement is implemented"
        return "denied", "role cannot execute remediation"
    if action == "rotate_node_identity":
        return _authority_state(role.enrollment_authority, "node identity rotation")
    if action == "approve_enrollment":
        return _authority_state(role.enrollment_authority, "node enrollment approval")
    if action == "modify_config":
        return _authority_state(role.configuration_authority, "configuration changes")
    if action == "view_audit_log":
        if role.audit_visibility in {"read", "limited", "full"}:
            return "allowed", "role has audit visibility"
        return "denied", "role cannot view audit logs"
    if action == "manage_roles":
        if role.role_name == "admin" and role.configuration_authority == "manage":
            return "requires_approval", "role management is preview-only until live auth is implemented"
        return "denied", "role cannot manage roles"
    raise PermissionPreviewError(f"unsupported action: {action}")


def _authority_state(authority: str, subject: str) -> tuple[str, str]:
    if authority in {"manage", "execute"}:
        return "allowed", f"role has authority for {subject}"
    if authority == "approve":
        return "allowed", f"role can approve {subject}"
    if authority == "request":
        return "requires_approval", f"role can request {subject} but needs approval"
    if authority == "view":
        return "allowed", f"role can view {subject}"
    return "denied", f"role lacks authority for {subject}"


def _service_account_state(action: str) -> tuple[str, str]:
    if action in {"view_telemetry", "view_history"}:
        return "unavailable", "service account visibility requires future scoped service credentials"
    return "denied", "service accounts cannot perform operator actions in preview mode"


def _coerce_role(role: RBACRole) -> RBACRole:
    if isinstance(role, RBACRole):
        return role
    raise PermissionPreviewError("role must be a role name or RBACRole")


def _validate_choice(value: str, allowed: set[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise PermissionPreviewError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")
