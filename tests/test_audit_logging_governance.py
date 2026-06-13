from __future__ import annotations

import json

from core_engine.governance import (
    build_audit_event,
    build_daily_log_rotation_readiness,
    build_export_audit,
    build_last_export_summary,
    deterministic_audit_event_json,
    deterministic_export_audit_json,
    deterministic_log_rotation_json,
    normalize_audit_event,
    normalize_audit_event_category,
    normalize_audit_event_state,
    normalize_export_audit,
    normalize_export_audit_state,
    normalize_export_type,
    normalize_log_family,
    normalize_log_rotation_readiness,
    normalize_log_rotation_state,
    summarize_audit_events,
)


GENERATED_AT = "2026-06-12T12:00:00+00:00"


def test_audit_event_creation():
    event = build_audit_event(
        event_type="runtime_export",
        event_category="export",
        actor_reference="operator-review",
        action_reference="runtime-export",
        target_reference="export-bundle",
        source_mode="live",
        created_at=GENERATED_AT,
        evidence_references=["export-summary"],
    ).to_dict()

    assert event["record_type"] == "audit_event_record"
    assert event["event_category"] == "export"
    assert event["event_state"] == "recorded"
    assert event["source_mode"] == "live"
    assert event["evidence_references"] == ["export-summary"]
    assert event["preview_only"] is True
    assert event["destructive_action"] is False


def test_category_and_state_validation():
    assert normalize_audit_event_category("runtime") == "runtime"
    assert normalize_audit_event_category("bad") == "unknown"
    assert normalize_audit_event_state("pending") == "pending"
    assert normalize_audit_event_state("bad") == "unknown"

    event = build_audit_event(event_category="bad", event_state="bad").to_dict()

    assert event["event_category"] == "unknown"
    assert event["event_state"] == "unknown"


def test_actor_target_action_sanitization():
    private_reference = ".".join(["192", "168", "1", "44"])
    event = build_audit_event(
        actor_reference="operator@example.invalid",
        action_reference="approve export",
        target_reference=private_reference,
        created_at=GENERATED_AT,
    ).to_dict()

    assert event["actor_reference"].startswith("ref-")
    assert event["target_reference"].startswith("ref-")
    assert event["action_reference"] == "approve-export"


def test_audit_event_summary():
    summary = summarize_audit_events(
        [
            build_audit_event(event_category="runtime", event_state="recorded"),
            build_audit_event(event_category="export", event_state="pending"),
        ]
    )

    assert summary["event_count"] == 2
    assert summary["category_counts"]["runtime"] == 1
    assert summary["state_counts"]["pending"] == 1
    assert summary["export_safe"] is True


def test_daily_log_rotation_readiness():
    rotation = build_daily_log_rotation_readiness(
        generated_at=GENERATED_AT,
        log_family="audit",
        current_log_reference="audit-current",
        retention_days=30,
        estimated_log_count=12,
    ).to_dict()

    assert rotation["record_type"] == "daily_log_rotation_readiness"
    assert rotation["rotation_state"] == "ready"
    assert rotation["log_family"] == "audit"
    assert rotation["rotation_period"] == "daily"
    assert rotation["retention_preview"]["record_type"] == "log_retention_preview"
    assert rotation["preview_only"] is True


def test_log_rotation_validation():
    assert normalize_log_rotation_state("rotation_recommended") == "rotation_recommended"
    assert normalize_log_rotation_state("bad") == "unknown"
    assert normalize_log_family("worker") == "worker"
    assert normalize_log_family("bad") == "unknown"

    rotation = build_daily_log_rotation_readiness(retention_days=0, max_file_size_mb=0).to_dict()

    assert rotation["rotation_state"] == "degraded"
    assert rotation["validation_summary"]["retention_days_valid"] is False


def test_retention_compression_and_deletion_previews_are_advisory():
    rotation = build_daily_log_rotation_readiness(
        log_family="runtime",
        retention_days=7,
        estimated_log_count=40,
        generated_at=GENERATED_AT,
    ).to_dict()

    assert rotation["rotation_state"] == "retention_pressure"
    assert rotation["retention_preview"]["deletion_performed"] is False
    assert rotation["compression_preview"]["compression_performed"] is False
    assert rotation["deletion_preview"]["advisory_only"] is True
    assert rotation["deletion_preview"]["destructive_action"] is False


def test_last_export_summary_generation():
    summary = build_last_export_summary(
        export_reference="runtime-export",
        export_type="runtime",
        file_count=4,
        total_size_bytes=2048,
        generated_at=GENERATED_AT,
    )

    assert summary["record_type"] == "last_export_summary"
    assert summary["export_type"] == "runtime"
    assert summary["file_count"] == 4
    assert summary["zip_extracted"] is False
    assert summary["private_export_read"] is False


def test_export_validation_summary_generation():
    audit = build_export_audit(
        generated_at=GENERATED_AT,
        export_reference="runtime-export",
        export_type="runtime",
        expected_files=["manifest.json", "runtime.json"],
        observed_files=["manifest.json", "runtime.json"],
        schema_validation_state="valid",
        sensitive_data_scan_state="valid",
        artifact_check_state="valid",
        total_size_bytes=4096,
    ).to_dict()

    assert audit["record_type"] == "export_audit_record"
    assert audit["export_state"] == "valid"
    assert audit["file_count"] == 2
    assert audit["missing_files"] == []
    assert audit["last_export_summary"]["record_type"] == "last_export_summary"


def test_expected_missing_observed_file_summaries():
    audit = build_export_audit(
        expected_files=["manifest.json", "flows.json", "risk.json"],
        observed_files=["manifest.json"],
        schema_validation_state="valid",
        sensitive_data_scan_state="valid",
        artifact_check_state="valid",
    ).to_dict()

    assert audit["export_state"] == "incomplete"
    assert audit["observed_files"] == ["manifest.json"]
    assert audit["missing_files"] == ["flows.json", "risk.json"]
    assert any("missing expected file" in item for item in audit["validation_recommendations"])


def test_schema_sensitive_and_artifact_state_summaries():
    audit = build_export_audit(
        schema_validation_state="invalid",
        sensitive_data_scan_state="degraded",
        artifact_check_state="unknown",
    ).to_dict()

    assert normalize_export_audit_state("valid") == "valid"
    assert normalize_export_audit_state("bad") == "unknown"
    assert normalize_export_type("flows") == "flows"
    assert normalize_export_type("bad") == "unknown"
    assert audit["export_state"] == "invalid"
    assert "run schema validation before sharing export" in audit["validation_recommendations"]
    assert "run sensitive-data scan before sharing export" in audit["validation_recommendations"]
    assert "run artifact/private-file check before sharing export" in audit["validation_recommendations"]


def test_malformed_input_handling():
    event = normalize_audit_event(object()).to_dict()
    rotation = normalize_log_rotation_readiness(object()).to_dict()
    export = normalize_export_audit(object()).to_dict()

    assert event["event_state"] == "invalid"
    assert rotation["rotation_state"] == "degraded"
    assert export["export_state"] == "invalid"


def test_preview_and_destructive_flags_are_fixed():
    event = build_audit_event().to_dict()
    rotation = build_daily_log_rotation_readiness().to_dict()
    export = build_export_audit().to_dict()

    for record in (event, rotation, export):
        assert record["preview_only"] is True
        assert record["destructive_action"] is False
        assert record["export_safe"] is True
        assert record["credential_stored"] is False
        assert record["private_identifier_exported"] is False
        assert record["enforcement_action_created"] is False


def test_no_filesystem_deletion_or_write_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    rotation = build_daily_log_rotation_readiness().to_dict()
    export = build_export_audit(expected_files=["export.json"], observed_files=[]).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert rotation["audit_log_deleted"] is False
    assert rotation["filesystem_written"] is False
    assert rotation["log_file_rotated"] is False
    assert export["zip_extracted"] is False
    assert export["private_export_read"] is False


def test_export_safe_serialization():
    event = build_audit_event(created_at=GENERATED_AT)
    rotation = build_daily_log_rotation_readiness(generated_at=GENERATED_AT)
    export = build_export_audit(generated_at=GENERATED_AT)

    json.loads(deterministic_audit_event_json(event))
    json.loads(deterministic_log_rotation_json(rotation))
    json.loads(deterministic_export_audit_json(export))
    json.dumps(event.to_dict(), sort_keys=True)
    json.dumps(rotation.to_dict(), sort_keys=True)
    json.dumps(export.to_dict(), sort_keys=True)


def test_cross_platform_compatibility():
    for source_mode in ["live", "simulated", "fixture", "replay", "unknown"]:
        event = build_audit_event(source_mode=source_mode, created_at=GENERATED_AT).to_dict()
        assert event["source_mode"] == source_mode

    for family in ["master", "worker", "audit", "export", "runtime", "tui", "unknown"]:
        rotation = build_daily_log_rotation_readiness(log_family=family, generated_at=GENERATED_AT).to_dict()
        assert rotation["log_family"] == family
