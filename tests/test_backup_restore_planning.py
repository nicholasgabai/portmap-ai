import json
import re

import pytest

from core_engine.deployment import (
    BACKUP_TYPES,
    RESTORE_TYPES,
    backup_plan_to_dict,
    build_backup_plan,
    build_default_backup_plan_set,
    build_default_restore_preview_set,
    build_restore_preview,
    export_backup_plan,
    export_restore_preview,
    restore_preview_to_dict,
)


FIXED_TIME = "2026-01-01T00:00:00+00:00"

PRIVATE_IDENTIFIER_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/Users/"),
    re.compile(r"/home/"),
]


def test_default_backup_plan_set_covers_all_backup_types():
    plan_set = build_default_backup_plan_set(generated_at=FIXED_TIME)

    assert set(plan_set["backup_types"]) == BACKUP_TYPES
    assert plan_set["backup_count"] == len(BACKUP_TYPES)
    assert plan_set["dry_run_only"] is True
    assert plan_set["destructive_action"] is False
    assert plan_set["backup_created"] is False
    assert plan_set["archive_created"] is False


def test_configuration_backup_plan_excludes_sensitive_components():
    plan = build_backup_plan("configuration", generated_at=FIXED_TIME)

    assert plan["backup_type"] == "configuration"
    assert plan["encryption_recommended"] is True
    assert "credentials" in plan["excluded_components"]
    assert "secrets" in plan["excluded_components"]
    assert "runtime_logs" in plan["excluded_components"]
    assert plan["credentials_copied"] is False
    assert plan["files_copied"] is False
    assert plan["destructive_action"] is False


def test_historical_intelligence_backup_has_metadata_expectations():
    plan = build_backup_plan("historical_intelligence", generated_at=FIXED_TIME)

    assert "historical_snapshot_summaries" in plan["included_components"]
    assert "raw_browsing_history" in plan["excluded_components"]
    assert any("Historical intelligence backups" in note for note in plan["advisory_notes"])


def test_restore_preview_set_covers_all_restore_types():
    preview_set = build_default_restore_preview_set(generated_at=FIXED_TIME)

    assert set(preview_set["restore_types"]) == RESTORE_TYPES
    assert preview_set["restore_count"] == len(RESTORE_TYPES)
    assert preview_set["preview_only"] is True
    assert preview_set["destructive_action"] is False
    assert preview_set["restore_executed"] is False


def test_config_restore_preview_generates_conflict_warnings():
    preview = build_restore_preview(
        "config",
        conflict_hints=["existing config differs"],
        generated_at=FIXED_TIME,
    )

    assert preview["restore_type"] == "config"
    warnings = {row["warning"] for row in preview["conflict_warnings"]}
    assert "active_configuration_conflict_possible" in warnings
    assert "existing_config_differs" in warnings
    assert preview["preview_only"] is True
    assert preview["destructive_action"] is False
    assert preview["files_overwritten"] is False


def test_restore_preview_blocks_missing_source():
    preview = build_restore_preview(
        "deployment_manifest",
        source_available=False,
        generated_at=FIXED_TIME,
    )

    check_states = {row["check_name"]: row["state"] for row in preview["compatibility_checks"]}
    assert check_states["source_available"] == "blocked"
    assert preview["dashboard_status"]["state"] == "blocked"
    assert preview["restore_executed"] is False


def test_evidence_bundle_restore_requires_redaction_review():
    preview = build_restore_preview("evidence_bundle", generated_at=FIXED_TIME)

    warnings = {row["warning"] for row in preview["conflict_warnings"]}
    assert "redaction_validation_required" in warnings
    assert preview["archive_extracted"] is False
    assert preview["files_deleted"] is False


def test_backup_and_restore_serialization_are_export_safe():
    backup = build_backup_plan("operator_evidence_bundle", generated_at=FIXED_TIME)
    restore = build_restore_preview("historical_intelligence", generated_at=FIXED_TIME)

    backup_text = export_backup_plan(backup)
    restore_text = export_restore_preview(restore)

    assert json.loads(backup_text) == backup_plan_to_dict(backup)
    assert json.loads(restore_text) == restore_preview_to_dict(restore)
    assert json.loads(backup_text)["raw_payload_stored"] is False
    assert json.loads(restore_text)["credentials_copied"] is False
    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(backup_text)
        assert not pattern.search(restore_text)


def test_unknown_backup_and_restore_types_are_rejected():
    with pytest.raises(ValueError):
        build_backup_plan("private_database_copy")
    with pytest.raises(ValueError):
        build_restore_preview("secret_restore")
