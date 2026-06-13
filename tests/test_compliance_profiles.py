from __future__ import annotations

import json

from core_engine.governance import (
    build_compliance_profile,
    build_evidence_expectation,
    deterministic_compliance_profile_json,
    deterministic_evidence_expectation_json,
    normalize_compliance_profile,
    normalize_compliance_profile_state,
    normalize_compliance_profile_type,
    normalize_evidence_expectation,
    normalize_evidence_state,
    normalize_evidence_type,
    summarize_evidence_expectations,
)


def test_compliance_profile_creation():
    profile = build_compliance_profile(
        profile_name="Internal audit",
        profile_type="internal_audit",
    ).to_dict()

    assert profile["record_type"] == "compliance_profile"
    assert profile["profile_name"] == "Internal audit"
    assert profile["profile_type"] == "internal_audit"
    assert profile["profile_state"] == "ready"
    assert profile["evidence_expectations"]
    assert profile["audit_requirements"]["audit_events_expected"] is True
    assert profile["preview_only"] is True
    assert profile["destructive_action"] is False


def test_profile_type_and_state_validation():
    assert normalize_compliance_profile_type("privacy_review") == "privacy_review"
    assert normalize_compliance_profile_type("bad") == "unknown"
    assert normalize_compliance_profile_state("advisory") == "advisory"
    assert normalize_compliance_profile_state("bad") == "unknown"

    profile = build_compliance_profile(profile_type="bad", profile_state="bad").to_dict()

    assert profile["profile_type"] == "unknown"
    assert profile["profile_state"] == "unknown"


def test_evidence_profile_creation():
    evidence = build_evidence_expectation(
        evidence_type="export_summaries",
        expected_sources=["last_export_summary"],
        required_fields=["export_state"],
        retention_expectation_days=45,
        export_required=True,
    ).to_dict()

    assert evidence["record_type"] == "evidence_expectation"
    assert evidence["evidence_type"] == "export_summaries"
    assert evidence["evidence_state"] == "ready"
    assert evidence["retention_expectation_days"] == 45
    assert evidence["export_required"] is True
    assert evidence["redaction_required"] is True


def test_evidence_type_and_state_validation():
    assert normalize_evidence_type("runtime_logs") == "runtime_logs"
    assert normalize_evidence_type("bad") == "unknown"
    assert normalize_evidence_state("partial") == "partial"
    assert normalize_evidence_state("bad") == "unknown"

    evidence = build_evidence_expectation(evidence_type="bad", evidence_state="bad").to_dict()

    assert evidence["evidence_type"] == "unknown"
    assert evidence["evidence_state"] == "unknown"


def test_audit_export_retention_and_privacy_summaries():
    profile = build_compliance_profile(profile_type="enterprise_readiness").to_dict()

    assert profile["audit_requirements"]["daily_rotation_readiness_expected"] is True
    assert profile["export_requirements"]["export_validation_summary_expected"] is True
    assert profile["retention_expectations"]["retention_days"] == 90
    assert profile["privacy_requirements"]["redaction_required"] is True
    assert profile["privacy_requirements"]["private_identifier_export_allowed"] is False


def test_evidence_expectation_summary():
    summary = summarize_evidence_expectations(
        [
            build_evidence_expectation(evidence_type="audit_events"),
            build_evidence_expectation(evidence_type="runtime_logs", evidence_state="partial"),
        ]
    )

    assert summary["evidence_profile_count"] == 2
    assert summary["type_counts"]["audit_events"] == 1
    assert summary["state_counts"]["partial"] == 1
    assert summary["redaction_required_count"] == 2


def test_certification_claimed_is_always_false():
    profile = build_compliance_profile(profile_type="security_review").to_dict()

    assert profile["certification_claimed"] is False
    assert profile["legal_certification_claimed"] is False
    assert profile["legal_analysis_performed"] is False
    assert profile["legal_claim_created"] is False


def test_preview_and_destructive_flags_are_fixed():
    profile = build_compliance_profile().to_dict()
    evidence = build_evidence_expectation().to_dict()

    for record in (profile, evidence):
        assert record["preview_only"] is True
        assert record["destructive_action"] is False
        assert record["export_safe"] is True
        assert record["control_enforced"] is False
        assert record["enforcement_action_created"] is False
        assert record["credential_stored"] is False


def test_no_enforcement_or_legal_claim_fields():
    profile = build_compliance_profile().to_dict()
    evidence = build_evidence_expectation().to_dict()

    disallowed = {"legal_advice", "legal_opinion", "control_execution", "enforcement_mode"}
    assert disallowed.isdisjoint(profile)
    assert disallowed.isdisjoint(evidence)
    assert profile["control_enforced"] is False
    assert evidence["legal_claim_created"] is False


def test_malformed_input_handling():
    profile = normalize_compliance_profile(object()).to_dict()
    evidence = normalize_evidence_expectation(object()).to_dict()

    assert profile["profile_state"] == "degraded"
    assert evidence["evidence_state"] == "degraded"
    assert profile["preview_only"] is True
    assert evidence["preview_only"] is True


def test_export_safe_serialization():
    profile = build_compliance_profile(profile_type="privacy_review")
    evidence = build_evidence_expectation(evidence_type="configuration_snapshots")

    json.loads(deterministic_compliance_profile_json(profile))
    json.loads(deterministic_evidence_expectation_json(evidence))
    json.dumps(profile.to_dict(), sort_keys=True)
    json.dumps(evidence.to_dict(), sort_keys=True)


def test_cross_platform_compatibility():
    for profile_type in [
        "internal_audit",
        "privacy_review",
        "security_review",
        "incident_review",
        "enterprise_readiness",
        "custom",
        "unknown",
    ]:
        profile = build_compliance_profile(profile_type=profile_type).to_dict()
        assert profile["profile_type"] == profile_type

    for evidence_type in [
        "audit_events",
        "runtime_logs",
        "export_summaries",
        "policy_reviews",
        "remediation_previews",
        "configuration_snapshots",
        "security_reviews",
        "unknown",
    ]:
        evidence = build_evidence_expectation(evidence_type=evidence_type).to_dict()
        assert evidence["evidence_type"] == evidence_type


def test_no_file_read_or_runtime_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    profile = build_compliance_profile(profile_type="incident_review").to_dict()
    evidence = build_evidence_expectation(evidence_type="runtime_logs").to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert profile["file_read_performed"] is False
    assert evidence["file_read_performed"] is False
    assert profile["filesystem_written"] is False
    assert evidence["filesystem_written"] is False
