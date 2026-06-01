import json
import re

import pytest

from core_engine.deployment import (
    MIGRATION_TYPES,
    build_default_migration_plan_set,
    build_migration_preview,
    build_upgrade_readiness_report,
    build_version_compatibility_summary,
    export_migration_preview,
    export_upgrade_readiness,
    migration_preview_to_dict,
    upgrade_readiness_to_dict,
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


def test_ready_upgrade_readiness_report_is_preview_only():
    report = build_upgrade_readiness_report(
        current_version="0.1.0",
        target_version="0.1.1",
        deployment_mode="standalone",
        service_lifecycle_impact="ready",
        rollback_available=True,
        generated_at=FIXED_TIME,
    )

    assert report["readiness_state"] == "ready"
    assert report["compatibility_state"] == "ready"
    assert report["operator_action_required"] is False
    assert report["rollback_available"] is True
    assert report["migration_executed"] is False
    assert report["destructive_action"] is False
    assert report["config_modified"] is False


def test_degraded_upgrade_when_service_lifecycle_requires_review():
    report = build_upgrade_readiness_report(
        current_version="0.1.0",
        target_version="0.2.0",
        deployment_mode="production_preview",
        service_lifecycle_impact="degraded",
        rollback_available=True,
        generated_at=FIXED_TIME,
    )

    assert report["readiness_state"] == "degraded"
    assert report["service_lifecycle_impact"]["state"] == "degraded"
    assert report["operator_action_required"] is True
    assert "service_lifecycle_impact requires operator review." in report["advisory_notes"]


def test_blocked_upgrade_for_downgrade_or_blocking_impact():
    report = build_upgrade_readiness_report(
        current_version="1.2.0",
        target_version="1.1.0",
        deployment_mode="orchestrator",
        service_lifecycle_impact="ready",
        generated_at=FIXED_TIME,
    )

    assert report["readiness_state"] == "blocked"
    assert report["compatibility_state"] == "blocked"
    assert report["operator_action_required"] is True


def test_unknown_upgrade_for_malformed_version():
    report = build_upgrade_readiness_report(
        current_version="version-current",
        target_version="version-target",
        service_lifecycle_impact="ready",
        generated_at=FIXED_TIME,
    )

    assert report["readiness_state"] == "unknown"
    assert report["compatibility_state"] == "unknown"
    assert report["operator_action_required"] is True


def test_version_compatibility_handles_major_jump_as_blocked():
    summary = build_version_compatibility_summary(
        current_version="1.0.0",
        target_version="3.0.0",
        generated_at=FIXED_TIME,
    )

    assert summary["state"] == "blocked"
    assert "major version jump" in summary["operator_summary"]


def test_default_migration_plan_set_covers_all_migration_types():
    plan = build_default_migration_plan_set(
        current_version="0.1.0",
        target_version="0.1.1",
        generated_at=FIXED_TIME,
    )

    assert {row["migration_type"] for row in plan["migrations"]} == MIGRATION_TYPES
    assert plan["migration_count"] == len(MIGRATION_TYPES)
    assert plan["preview_only"] is True
    assert plan["destructive_action"] is False
    for preview in plan["migrations"]:
        assert preview["migration_executed"] is False
        assert preview["required_backups"]
        assert preview["rollback_notes"]


def test_migration_preview_for_historical_snapshots_has_safety_warnings():
    preview = build_migration_preview(
        "historical_snapshot_schema",
        current_version="0.1.0",
        target_version="0.1.1",
        generated_at=FIXED_TIME,
    )

    assert preview["preview_only"] is True
    assert preview["destructive_action"] is False
    assert preview["history_store_modified"] is False
    assert preview["snapshots_rewritten"] is False
    assert "snapshot_rewrite_disabled" in preview["safety_warnings"]
    assert "historical_snapshot_export" in preview["required_backups"]


def test_upgrade_and_migration_serialization_are_export_safe():
    report = build_upgrade_readiness_report(
        current_version="0.1.0",
        target_version="0.1.1",
        service_lifecycle_impact="ready",
        generated_at=FIXED_TIME,
    )
    preview = build_migration_preview("config", generated_at=FIXED_TIME)

    upgrade_text = export_upgrade_readiness(report)
    migration_text = export_migration_preview(preview)

    assert json.loads(upgrade_text) == upgrade_readiness_to_dict(report)
    assert json.loads(migration_text) == migration_preview_to_dict(preview)
    assert json.loads(upgrade_text)["raw_payload_stored"] is False
    assert json.loads(migration_text)["credentials_generated"] is False
    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(upgrade_text)
        assert not pattern.search(migration_text)


def test_invalid_migration_type_is_rejected():
    with pytest.raises(ValueError):
        build_migration_preview("credential_migration")
