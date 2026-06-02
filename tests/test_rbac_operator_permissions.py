import json

import pytest

from core_engine.security import (
    PermissionEvaluationPreview,
    PermissionPreviewError,
    RBACError,
    RBACRole,
    create_rbac_role,
    evaluate_permission_preview,
    summarize_permission_matrix,
    summarize_rbac_roles,
)


def test_role_generation_distinguishes_operator_roles():
    admin = create_rbac_role("admin")
    operator = create_rbac_role("security_operator")
    analyst = create_rbac_role("analyst")
    auditor = create_rbac_role("auditor")
    read_only = create_rbac_role("read_only")
    service = create_rbac_role("service_account")

    assert admin.permission_scope == "full"
    assert admin.configuration_authority == "manage"
    assert operator.remediation_authority == "approve"
    assert analyst.remediation_authority == "request"
    assert auditor.audit_visibility == "full"
    assert read_only.export_authority == "none"
    assert service.api_access == "service"
    assert all(role.to_dict()["credentials_stored"] is False for role in [admin, operator, analyst, auditor, read_only, service])
    assert all(role.to_dict()["live_auth_enforced"] is False for role in [admin, operator, analyst, auditor, read_only, service])


def test_role_serialization_export_safety_and_malformed_handling():
    role = create_rbac_role("security_operator")
    exported = role.to_dict()
    serialized = json.dumps(exported, sort_keys=True)

    assert RBACRole.from_dict(exported) == role
    assert exported["user_database_created"] is False
    assert "password" not in serialized
    assert "token" not in serialized
    with pytest.raises(RBACError):
        create_rbac_role("owner")
    with pytest.raises(RBACError):
        RBACRole.from_dict({**exported, "live_auth_enforced": True})
    with pytest.raises(RBACError):
        RBACRole.from_dict({**exported, "user_database_created": True})
    with pytest.raises(RBACError):
        RBACRole.from_dict({**exported, "credentials_stored": True})


def test_permission_evaluation_matrix_core_boundaries():
    assert evaluate_permission_preview(role="admin", requested_action="modify_config").permission_state == "allowed"
    assert evaluate_permission_preview(role="admin", requested_action="manage_roles").permission_state == "requires_approval"
    assert evaluate_permission_preview(role="security_operator", requested_action="approve_remediation").permission_state == "allowed"
    assert evaluate_permission_preview(role="security_operator", requested_action="execute_remediation").permission_state == "denied"
    assert evaluate_permission_preview(role="analyst", requested_action="approve_remediation").permission_state == "requires_approval"
    assert evaluate_permission_preview(role="analyst", requested_action="approve_enrollment").permission_state == "denied"
    assert evaluate_permission_preview(role="auditor", requested_action="view_audit_log").permission_state == "allowed"
    assert evaluate_permission_preview(role="read_only", requested_action="export_runtime").permission_state == "denied"
    assert evaluate_permission_preview(role="service_account", requested_action="view_telemetry").permission_state == "unavailable"


def test_enrollment_and_remediation_authority_boundaries():
    operator_enrollment = evaluate_permission_preview(role="security_operator", requested_action="approve_enrollment")
    analyst_enrollment = evaluate_permission_preview(role="analyst", requested_action="approve_enrollment")
    admin_rotation = evaluate_permission_preview(role="admin", requested_action="rotate_node_identity")
    read_only_remediation = evaluate_permission_preview(role="read_only", requested_action="approve_remediation")

    assert operator_enrollment.permission_state == "allowed"
    assert analyst_enrollment.permission_state == "denied"
    assert admin_rotation.permission_state == "allowed"
    assert read_only_remediation.permission_state == "denied"


def test_permission_preview_serialization_and_safety_flags():
    preview = evaluate_permission_preview(role="analyst", requested_action="export_runtime")
    exported = preview.to_dict()

    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["live_auth_enforced"] is False
    assert exported["user_data_stored"] is False
    assert exported["credential_stored"] is False
    assert PermissionEvaluationPreview.from_dict(exported) == preview
    with pytest.raises(PermissionPreviewError):
        PermissionEvaluationPreview.from_dict({**exported, "preview_only": False})
    with pytest.raises(PermissionPreviewError):
        PermissionEvaluationPreview.from_dict({**exported, "destructive_action": True})
    with pytest.raises(PermissionPreviewError):
        PermissionEvaluationPreview.from_dict({**exported, "credential_stored": True})


def test_malformed_permission_role_and_action_handling():
    with pytest.raises(PermissionPreviewError):
        evaluate_permission_preview(role="admin", requested_action="delete_everything")
    with pytest.raises(RBACError):
        evaluate_permission_preview(role="root", requested_action="view_telemetry")
    with pytest.raises(PermissionPreviewError):
        evaluate_permission_preview(role="admin", requested_action="view_telemetry", enforcement_mode="live")


def test_role_and_permission_summaries_are_export_safe():
    role_summary = summarize_rbac_roles()
    matrix = summarize_permission_matrix(role_names=["admin", "read_only"], actions=["view_telemetry", "modify_config"])

    assert role_summary["role_count"] == 6
    assert role_summary["preview_only"] is True
    assert role_summary["credentials_stored"] is False
    assert matrix["preview_count"] == 4
    assert matrix["preview_only"] is True
    assert matrix["destructive_action"] is False
    assert matrix["credential_stored"] is False
    assert matrix["by_permission_state"]["allowed"] >= 1
    assert matrix["by_permission_state"]["denied"] >= 1
