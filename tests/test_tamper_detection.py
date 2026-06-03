import json

import pytest

from core_engine.security import (
    IntegrityError,
    IntegrityTargetRecord,
    TamperDetectionError,
    TamperDetectionPreview,
    build_tamper_previews_from_integrity,
    create_integrity_target_record,
    create_tamper_detection_preview,
    summarize_integrity_targets,
    summarize_tamper_detection,
)


def test_integrity_target_generation_for_all_targets():
    summary = summarize_integrity_targets()

    assert summary["target_count"] == 8
    assert summary["export_safe"] is True
    assert summary["preview_only"] is True
    assert summary["file_watcher_started"] is False
    assert summary["real_private_file_hashed"] is False
    assert summary["system_file_modified"] is False
    assert summary["private_path_exposed"] is False
    assert {target["target_name"] for target in summary["targets"]} == {
        "runtime_config",
        "deployment_manifest",
        "node_identity",
        "trust_chain",
        "transport_profile",
        "package_manifest",
        "binary_artifact",
        "history_store",
    }


def test_integrity_state_transitions_and_serialization_are_safe():
    verified = create_integrity_target_record(
        "runtime_config",
        integrity_state="verified",
        last_verified_preview="fixture_timestamp_001",
    )
    drift = create_integrity_target_record("trust_chain", integrity_state="drift_detected")
    unverifiable = create_integrity_target_record("binary_artifact", integrity_state="unverifiable")
    unknown = create_integrity_target_record("history_store")

    assert verified.integrity_state == "verified"
    assert verified.drift_detected is False
    assert drift.drift_detected is True
    assert unverifiable.integrity_state == "unverifiable"
    assert unknown.integrity_state == "unknown"
    assert IntegrityTargetRecord.from_dict(verified.to_dict()) == verified
    serialized = json.dumps(drift.to_dict(), sort_keys=True)
    assert "operator_home" not in serialized
    assert "hostname" not in serialized
    assert "username" not in serialized


def test_integrity_records_reject_malformed_and_unsafe_exports():
    target = create_integrity_target_record("deployment_manifest")

    with pytest.raises(IntegrityError):
        create_integrity_target_record("private_path")
    with pytest.raises(IntegrityError):
        IntegrityTargetRecord(
            target_name="runtime_config",
            target_class="configuration",
            integrity_state="verified",
            verification_mode="digest_preview",
            digest_available=True,
            signature_available=False,
            last_verified_preview="~operator/private.json",
            drift_detected=False,
        )
    with pytest.raises(IntegrityError):
        IntegrityTargetRecord.from_dict({**target.to_dict(), "file_watcher_started": True})
    with pytest.raises(IntegrityError):
        IntegrityTargetRecord.from_dict({**target.to_dict(), "real_private_file_hashed": True})
    with pytest.raises(IntegrityError):
        IntegrityTargetRecord.from_dict({**target.to_dict(), "system_file_modified": True})
    with pytest.raises(IntegrityError):
        IntegrityTargetRecord.from_dict({**target.to_dict(), "private_path_exposed": True})


def test_tamper_preview_generation_and_severity_mapping():
    clean = create_tamper_detection_preview("config_change", detection_state="clean")
    downgrade = create_tamper_detection_preview("transport_downgrade", detection_state="suspicious")
    trust_drift = create_tamper_detection_preview("trust_chain_drift", detection_state="tampered")
    package_mismatch = create_tamper_detection_preview(
        "package_digest_mismatch",
        detection_state="tampered",
        affected_target="binary_artifact",
    )

    assert clean.severity == "info"
    assert clean.operator_action_required is False
    assert downgrade.severity == "high"
    assert downgrade.operator_action_required is True
    assert trust_drift.severity == "critical"
    assert package_mismatch.severity == "critical"
    assert package_mismatch.affected_target == "binary_artifact"


def test_identity_and_trust_chain_drift_warnings_are_operator_review_only():
    identity = create_tamper_detection_preview("identity_rotation_mismatch", detection_state="suspicious")
    trust = create_tamper_detection_preview("trust_chain_drift", detection_state="tampered")

    for preview in (identity, trust):
        exported = preview.to_dict()
        assert exported["operator_action_required"] is True
        assert exported["preview_only"] is True
        assert exported["destructive_action"] is False
        assert exported["live_blocking_enabled"] is False
        assert exported["quarantine_performed"] is False
        assert exported["file_deleted"] is False
        assert exported["rollback_executed"] is False
        assert exported["config_modified"] is False


def test_tamper_preview_serialization_safety_and_malformed_handling():
    preview = create_tamper_detection_preview(
        "history_store_drift",
        detection_state="unverifiable",
        evidence_summary=("history store digest preview is unavailable",),
    )
    exported = preview.to_dict()
    serialized = json.dumps(exported, sort_keys=True)

    assert TamperDetectionPreview.from_dict(exported) == preview
    assert "192.168." not in serialized
    assert "00:11:22" not in serialized
    assert "operator_home" not in serialized
    with pytest.raises(TamperDetectionError):
        create_tamper_detection_preview("unknown_detection")
    with pytest.raises(TamperDetectionError):
        create_tamper_detection_preview("config_change", affected_target="trust_chain")
    with pytest.raises(TamperDetectionError):
        create_tamper_detection_preview("config_change", evidence_summary=("~operator-private/config.json",))
    with pytest.raises(TamperDetectionError):
        TamperDetectionPreview.from_dict({**exported, "preview_only": False})
    with pytest.raises(TamperDetectionError):
        TamperDetectionPreview.from_dict({**exported, "destructive_action": True})
    with pytest.raises(TamperDetectionError):
        TamperDetectionPreview.from_dict({**exported, "live_blocking_enabled": True})
    with pytest.raises(TamperDetectionError):
        TamperDetectionPreview.from_dict({**exported, "quarantine_performed": True})
    with pytest.raises(TamperDetectionError):
        TamperDetectionPreview.from_dict({**exported, "file_deleted": True})
    with pytest.raises(TamperDetectionError):
        TamperDetectionPreview.from_dict({**exported, "rollback_executed": True})
    with pytest.raises(TamperDetectionError):
        TamperDetectionPreview.from_dict({**exported, "config_modified": True})


def test_tamper_summary_from_integrity_isolates_malformed_records():
    clean_target = create_integrity_target_record("runtime_config", integrity_state="verified")
    drift_target = create_integrity_target_record("transport_profile", integrity_state="drift_detected")
    summary = build_tamper_previews_from_integrity([clean_target, drift_target.to_dict(), {"bad": "record"}])

    assert summary["preview_count"] == 2
    assert summary["malformed_record_count"] == 1
    assert summary["by_detection_state"]["clean"] == 1
    assert summary["by_detection_state"]["tampered"] == 1
    assert summary["destructive_action"] is False
    assert summary["live_blocking_enabled"] is False
    assert summary["quarantine_performed"] is False


def test_tamper_detection_summary_is_export_safe():
    summary = summarize_tamper_detection(["config_change", "transport_downgrade", "package_digest_mismatch"])

    assert summary["preview_count"] == 3
    assert summary["by_detection_state"]["unknown"] == 3
    assert summary["by_severity"]["unknown"] == 3
    assert summary["export_safe"] is True
    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert summary["file_deleted"] is False
