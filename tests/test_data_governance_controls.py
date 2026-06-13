from __future__ import annotations

import json

from core_engine.governance import (
    build_audit_event,
    build_compliance_profile,
    build_data_classification,
    build_data_governance_summary,
    deterministic_data_classification_json,
    deterministic_data_governance_json,
    empty_data_governance_summary,
    normalize_data_category,
    normalize_data_classification,
    normalize_data_governance_state,
    normalize_handling_state,
    normalize_sensitivity_level,
    summarize_audit_events,
    summarize_classifications,
)


def test_data_classification_creation():
    classification = build_data_classification(
        data_category="runtime_metadata",
        source_mode="fixture",
    ).to_dict()

    assert classification["record_type"] == "data_classification"
    assert classification["data_category"] == "runtime_metadata"
    assert classification["sensitivity_level"] == "internal"
    assert classification["handling_state"] == "review_required"
    assert classification["source_mode"] == "fixture"
    assert classification["preview_only"] is True
    assert classification["destructive_action"] is False
    assert classification["export_safe"] is True


def test_category_sensitivity_and_handling_validation():
    assert normalize_data_category("audit_metadata") == "audit_metadata"
    assert normalize_data_category("bad") == "unknown"
    assert normalize_sensitivity_level("sensitive") == "sensitive"
    assert normalize_sensitivity_level("bad") == "unknown"
    assert normalize_handling_state("redaction_required") == "redaction_required"
    assert normalize_handling_state("bad") == "unknown"
    assert normalize_data_governance_state("restricted") == "restricted"
    assert normalize_data_governance_state("bad") == "unknown"

    classification = build_data_classification(
        data_category="bad",
        sensitivity_level="bad",
        handling_state="bad",
    ).to_dict()

    assert classification["data_category"] == "unknown"
    assert classification["sensitivity_level"] == "unknown"
    assert classification["handling_state"] == "unknown"


def test_redaction_export_and_retention_flags():
    classification = build_data_classification(
        data_category="configuration_metadata",
        source_mode="local",
    ).to_dict()

    assert classification["sensitivity_level"] == "restricted"
    assert classification["handling_state"] == "restricted"
    assert classification["redaction_required"] is True
    assert classification["retention_required"] is True
    assert classification["export_allowed"] is False
    assert "credentials" in classification["expected_redactions"]


def test_governance_control_generation():
    classifications = [
        build_data_classification(data_category="runtime_metadata", source_mode="local"),
        build_data_classification(data_category="topology_metadata", source_mode="live"),
    ]

    summary = build_data_governance_summary(
        generated_at="2026-06-12T12:00:00Z",
        classifications=classifications,
    ).to_dict()

    assert summary["record_type"] == "data_governance_control_summary"
    assert summary["generated_at"] == "2026-06-12T12:00:00Z"
    assert summary["governance_state"] == "review_recommended"
    assert summary["classification_summary"]["classification_count"] == 2
    assert summary["privacy_boundary_summary"]["operator_review_required"] is True
    assert summary["retention_control_summary"]["deletion_allowed"] is False
    assert summary["export_governance_summary"]["private_export_read_by_default"] is False


def test_compliance_profile_integration():
    profile = build_compliance_profile(profile_type="enterprise_readiness")
    summary = build_data_governance_summary(
        classifications=[build_data_classification(data_category="audit_metadata")],
        compliance_profiles=[profile],
    ).to_dict()

    assert summary["compliance_profile_summary"]["profile_count"] == 1
    assert summary["compliance_profile_summary"]["type_counts"]["enterprise_readiness"] == 1
    assert summary["retention_control_summary"]["recommended_retention_days"] == 90
    assert summary["export_governance_summary"]["sensitive_data_scan_expected"] is True


def test_audit_summary_integration():
    audit_summary = summarize_audit_events(
        [
            build_audit_event(event_category="export", event_type="export_created"),
            build_audit_event(event_category="operator_action", event_type="reviewed"),
        ]
    )

    summary = build_data_governance_summary(audit_summary=audit_summary).to_dict()

    assert summary["audit_summary"]["record_type"] == "audit_event_summary"
    assert summary["audit_summary"]["event_count"] == 2
    assert summary["audit_summary"]["category_counts"]["export"] == 1


def test_privacy_boundary_summary():
    summary = build_data_governance_summary(
        classifications=[
            build_data_classification(data_category="configuration_metadata"),
            build_data_classification(data_category="operator_action_metadata"),
        ]
    ).to_dict()

    privacy = summary["privacy_boundary_summary"]
    assert privacy["classification_count"] == 2
    assert privacy["private_identifier_export_allowed"] is False
    assert privacy["operator_review_required"] is True
    assert privacy["restricted_count"] == 1


def test_retention_control_summary():
    summary = build_data_governance_summary(
        classifications=[build_data_classification(data_category="export_metadata")],
    ).to_dict()

    retention = summary["retention_control_summary"]
    assert retention["retention_required_count"] == 1
    assert retention["recommended_retention_days"] == 30
    assert retention["deletion_allowed"] is False
    assert retention["retention_preview_only"] is True


def test_redaction_readiness_and_export_governance():
    summary = build_data_governance_summary(
        classifications=[
            build_data_classification(data_category="topology_metadata"),
            build_data_classification(data_category="runtime_metadata"),
        ]
    ).to_dict()

    redaction = summary["redaction_readiness"]
    export = summary["export_governance_summary"]
    assert redaction["redaction_required_count"] == 2
    assert "private_addresses" in redaction["expected_redactions"]
    assert export["export_allowed_count"] == 2
    assert export["sensitive_data_scan_expected"] is True
    assert export["artifact_check_expected"] is True


def test_malformed_input_handling():
    classification = normalize_data_classification(object()).to_dict()
    summary = build_data_governance_summary(classifications=[object()]).to_dict()
    empty = empty_data_governance_summary(generated_at="2026-06-12T12:00:00Z").to_dict()

    assert classification["data_category"] == "unknown"
    assert classification["handling_state"] == "unknown"
    assert summary["governance_state"] == "degraded"
    assert empty["governance_state"] == "unavailable"
    assert empty["classification_summary"]["classification_count"] == 0


def test_preview_and_destructive_flags_are_fixed():
    classification = build_data_classification(
        redaction_required=False,
        export_allowed=True,
    ).to_dict()
    summary = build_data_governance_summary(
        classifications=[classification],
        governance_recommendations=["operator review only"],
    ).to_dict()

    for record in (classification, summary):
        assert record["preview_only"] is True
        assert record["destructive_action"] is False
        assert record["export_safe"] is True
        assert record["governance_control_enforced"] is False
        assert record["data_deleted"] is False
        assert record["file_read_performed"] is False
        assert record["runtime_behavior_changed"] is False


def test_no_enforcement_delete_or_file_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    classification = build_data_classification(data_category="audit_metadata").to_dict()
    summary = build_data_governance_summary(classifications=[classification]).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert summary["filesystem_written"] is False
    assert summary["data_deleted"] is False
    assert summary["governance_control_enforced"] is False
    assert summary["private_export_read"] is False


def test_export_safe_serialization():
    classification = build_data_classification(data_category="intelligence_metadata")
    summary = build_data_governance_summary(classifications=[classification])

    json.loads(deterministic_data_classification_json(classification))
    json.loads(deterministic_data_governance_json(summary))
    json.dumps(classification.to_dict(), sort_keys=True)
    json.dumps(summary.to_dict(), sort_keys=True)


def test_classification_summary_counts():
    summary = summarize_classifications(
        [
            build_data_classification(data_category="runtime_metadata"),
            build_data_classification(data_category="audit_metadata"),
        ]
    )

    assert summary["classification_count"] == 2
    assert summary["category_counts"]["runtime_metadata"] == 1
    assert summary["sensitivity_counts"]["sensitive"] == 1
    assert summary["redaction_required_count"] == 2


def test_cross_platform_compatibility():
    for category in [
        "runtime_metadata",
        "audit_metadata",
        "export_metadata",
        "configuration_metadata",
        "operator_action_metadata",
        "topology_metadata",
        "intelligence_metadata",
        "unknown",
    ]:
        classification = build_data_classification(data_category=category, source_mode="fixture").to_dict()
        assert classification["data_category"] == category
        assert classification["source_mode"] == "fixture"

    summary = build_data_governance_summary(
        classifications=[
            build_data_classification(data_category="runtime_metadata", source_mode="macos"),
            build_data_classification(data_category="audit_metadata", source_mode="linux_arm"),
        ]
    ).to_dict()

    assert summary["preview_only"] is True
    assert summary["export_safe"] is True
