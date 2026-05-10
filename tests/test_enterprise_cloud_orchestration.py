import json

import pytest

from core_engine.advisory.workflow import AdvisoryRecommendation, ReviewWorkflow, build_review_packet
from saas.cloud_sync import export_sync_manifest, import_sync_manifest, resolve_sync_conflicts
from saas.licensing import LicenseMetadata, UsageCounters, check_quota, feature_enabled, usage_summary
from saas.orgs import OrganizationRecord, TeamRecord, build_org_directory, effective_user_access
from saas.tenancy import TenantRecord, WorkspaceConfig, load_workspace_config, save_workspace_config


def test_org_directory_keeps_tenant_isolation_and_inherits_roles():
    tenant = TenantRecord(tenant_id="tenant.local", name="Local Tenant").to_dict()
    org = OrganizationRecord(org_id="org.ops", tenant_id="tenant.local", name="Ops").to_dict()
    team = TeamRecord(
        team_id="team.netops",
        tenant_id="tenant.local",
        org_id="org.ops",
        name="NetOps",
        roles=["analyst"],
        members=["alice"],
    ).to_dict()

    directory = build_org_directory(
        tenant=tenant,
        organizations=[org],
        teams=[team],
        user_roles={"alice": ["viewer"]},
    )
    access = effective_user_access(directory, "alice")

    assert directory["tenant_isolated"] is True
    assert access["roles"] == ["viewer", "analyst"]
    assert "execute:scan" in access["effective_permissions"]
    assert "read:nodes" in access["effective_permissions"]


def test_org_directory_rejects_cross_tenant_team():
    tenant = TenantRecord(tenant_id="tenant.local", name="Local Tenant").to_dict()
    org = OrganizationRecord(org_id="org.ops", tenant_id="tenant.local", name="Ops").to_dict()
    team = TeamRecord(team_id="team.other", tenant_id="tenant.other", org_id="org.ops", name="Other").to_dict()

    with pytest.raises(ValueError, match="same tenant"):
        build_org_directory(tenant=tenant, organizations=[org], teams=[team])


def test_workspace_config_persistence_round_trip(tmp_path):
    path = tmp_path / "workspace.json"
    config = WorkspaceConfig(
        workspace_id="workspace.local",
        tenant_id="tenant.local",
        org_id="org.ops",
        name="Local Workspace",
        settings={"retention_days": 7},
    )

    result = save_workspace_config(config, path)
    loaded = load_workspace_config(path)

    assert result["local_only"] is True
    assert loaded.workspace_id == "workspace.local"
    assert loaded.settings["retention_days"] == 7


def test_license_usage_summary_feature_and_quota():
    license_data = LicenseMetadata(
        license_id="lic-1",
        tenant_id="tenant.local",
        tier="team",
        features=["cloud_sync"],
        quotas={"workspaces": 2, "users": 10},
    )
    usage = UsageCounters(tenant_id="tenant.local", counters={"workspaces": 3, "users": 4})

    summary = usage_summary(license_data, usage)
    quota = check_quota(license_data, usage, "workspaces")
    gate = feature_enabled(license_data, "cloud_sync")

    assert any(row["name"] == "workspaces" and row["exceeded"] for row in summary["quotas"])
    assert quota["ok"] is False
    assert gate["enabled"] is True


def test_cloud_sync_manifest_export_import_and_conflicts():
    manifest = export_sync_manifest(
        {"workspace_id": "workspace.local", "setting": "value"},
        tenant_id="tenant.local",
        workspace_id="workspace.local",
        key="local-sync-key",
    )
    imported = import_sync_manifest(manifest, key="local-sync-key")
    conflicts = resolve_sync_conflicts(
        [{"id": "one", "value": "local"}],
        [{"id": "one", "value": "remote"}],
    )

    assert manifest["cloud_sync_optional"] is True
    assert "setting" not in manifest["encrypted_payload"]
    assert imported["payload"]["setting"] == "value"
    assert conflicts["requires_review"] is True


def test_cloud_sync_rejects_wrong_key():
    manifest = export_sync_manifest(
        {"value": "local"},
        tenant_id="tenant.local",
        workspace_id="workspace.local",
        key="local-sync-key",
    )

    with pytest.raises(ValueError, match="fingerprint"):
        import_sync_manifest(manifest, key="wrong-key")


def test_advisory_workflow_requires_admin_permission_for_approval():
    recommendation = AdvisoryRecommendation(
        recommendation_id="rec-1",
        title="Review workspace retention",
        summary="Retention settings should be reviewed by an administrator.",
        actions=["review retention_days"],
    )
    workflow = ReviewWorkflow([recommendation])

    with pytest.raises(PermissionError):
        workflow.transition("rec-1", new_state="approved", actor="alice", actor_roles=["analyst"])

    approved = workflow.transition("rec-1", new_state="approved", actor="admin", actor_roles=["admin"])
    events = workflow.audit_events(tenant_id="tenant.local")

    assert approved["state"] == "approved"
    assert events[-1]["tenant_id"] == "tenant.local"
    assert events[-1]["metadata"]["automatic_execution"] is False


def test_review_packet_is_json_serializable_and_administrator_controlled():
    packet = build_review_packet([
        {
            "recommendation_id": "rec-2",
            "title": "Review team membership",
            "summary": "Confirm team membership remains current.",
            "category": "access_review",
            "target": "team.netops",
            "actions": ["review team members"],
        }
    ])

    assert packet["administrator_controlled"] is True
    assert packet["automatic_execution"] is False
    assert json.loads(json.dumps(packet))["recommendation_count"] == 1
