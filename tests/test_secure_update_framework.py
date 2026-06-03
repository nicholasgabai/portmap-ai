import json

import pytest

from core_engine.security import (
    RollbackPlanError,
    RollbackPreviewRecord,
    UpdateVerificationError,
    UpdateVerificationRecord,
    create_rollback_preview_record,
    create_update_verification_record,
    summarize_rollback_previews,
    summarize_update_verification,
)


def test_update_verification_record_generation_for_all_targets():
    summary = summarize_update_verification()

    assert summary["record_count"] == 6
    assert summary["export_safe"] is True
    assert summary["preview_only"] is True
    assert summary["update_downloaded"] is False
    assert summary["installer_executed"] is False
    assert summary["file_modified"] is False
    assert summary["migration_executed"] is False
    assert summary["private_key_material_present"] is False
    assert summary["signing_material_generated"] is False
    assert summary["live_signature_trust_enabled"] is False
    assert {record["update_target"] for record in summary["records"]} == {
        "release_manifest",
        "package_digest",
        "signature_status",
        "migration_manifest",
        "compatibility_manifest",
        "rollback_manifest",
    }


def test_update_verification_state_transitions_and_serialization():
    verified = create_update_verification_record(
        "release_manifest",
        current_version="1.2.0",
        target_version="1.3.0",
        verification_state="verified",
    )
    degraded = create_update_verification_record("signature_status", verification_state="degraded")
    blocked = create_update_verification_record("compatibility_manifest", verification_state="blocked")
    unavailable = create_update_verification_record("package_digest", verification_state="unavailable")
    unknown = create_update_verification_record("rollback_manifest")

    assert verified.verification_state == "verified"
    assert verified.operator_action_required is False
    assert degraded.operator_action_required is True
    assert blocked.compatibility_state == "blocked"
    assert unavailable.digest_state == "unavailable"
    assert unknown.verification_state == "unknown"
    assert UpdateVerificationRecord.from_dict(verified.to_dict()) == verified
    serialized = json.dumps(verified.to_dict(), sort_keys=True)
    assert "signing-material-placeholder" not in serialized
    assert "hostname" not in serialized
    assert "username" not in serialized


def test_update_verification_migration_and_rollback_flags():
    migration = create_update_verification_record(
        "migration_manifest",
        current_version="1.0.0",
        target_version="1.1.0",
        verification_state="verified",
    )
    rollback = create_update_verification_record(
        "rollback_manifest",
        current_version="1.1.0",
        target_version="1.0.0",
        verification_state="degraded",
    )

    assert migration.migration_required is True
    assert migration.rollback_available is False
    assert rollback.migration_required is False
    assert rollback.rollback_available is True
    assert rollback.operator_action_required is True


def test_update_verification_rejects_malformed_versions_and_unsafe_flags():
    record = create_update_verification_record("package_digest", verification_state="verified")

    with pytest.raises(UpdateVerificationError):
        create_update_verification_record("unknown_manifest")
    with pytest.raises(UpdateVerificationError):
        create_update_verification_record("release_manifest", current_version="release candidate")
    with pytest.raises(UpdateVerificationError):
        create_update_verification_record("release_manifest", target_version="https-example")
    with pytest.raises(UpdateVerificationError):
        create_update_verification_record("release_manifest", advisory_notes=("~operator update note",))
    with pytest.raises(UpdateVerificationError):
        UpdateVerificationRecord.from_dict({**record.to_dict(), "update_downloaded": True})
    with pytest.raises(UpdateVerificationError):
        UpdateVerificationRecord.from_dict({**record.to_dict(), "installer_executed": True})
    with pytest.raises(UpdateVerificationError):
        UpdateVerificationRecord.from_dict({**record.to_dict(), "file_modified": True})
    with pytest.raises(UpdateVerificationError):
        UpdateVerificationRecord.from_dict({**record.to_dict(), "migration_executed": True})
    with pytest.raises(UpdateVerificationError):
        UpdateVerificationRecord.from_dict({**record.to_dict(), "private_key_material_present": True})
    with pytest.raises(UpdateVerificationError):
        UpdateVerificationRecord.from_dict({**record.to_dict(), "signing_material_generated": True})
    with pytest.raises(UpdateVerificationError):
        UpdateVerificationRecord.from_dict({**record.to_dict(), "live_signature_trust_enabled": True})


def test_rollback_preview_generation_for_all_types():
    summary = summarize_rollback_previews()

    assert summary["record_count"] == 6
    assert summary["export_safe"] is True
    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert summary["restore_executed"] is False
    assert summary["file_deleted"] is False
    assert summary["file_overwritten"] is False
    assert summary["config_modified"] is False
    assert summary["migration_executed"] is False
    assert {record["rollback_name"] for record in summary["records"]} == {
        "config_rollback",
        "package_rollback",
        "migration_rollback",
        "identity_rollback",
        "trust_chain_rollback",
        "history_store_rollback",
    }


def test_rollback_state_transitions_backup_and_compatibility_flags():
    ready = create_rollback_preview_record("config_rollback", rollback_state="ready")
    degraded = create_rollback_preview_record("package_rollback", rollback_state="degraded")
    blocked = create_rollback_preview_record("migration_rollback", rollback_state="blocked")
    unavailable = create_rollback_preview_record("identity_rollback", rollback_state="unavailable")
    unknown = create_rollback_preview_record("trust_chain_rollback")

    assert ready.rollback_state == "ready"
    assert ready.backup_required is True
    assert ready.compatibility_required is False
    assert degraded.backup_required is True
    assert degraded.compatibility_required is True
    assert blocked.rollback_state == "blocked"
    assert unavailable.rollback_state == "unavailable"
    assert unknown.rollback_state == "unknown"
    assert RollbackPreviewRecord.from_dict(ready.to_dict()) == ready


def test_rollback_preview_export_safety_and_destructive_action_guards():
    record = create_rollback_preview_record("history_store_rollback", rollback_state="degraded")
    exported = record.to_dict()
    serialized = json.dumps(exported, sort_keys=True)

    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert "password" not in serialized
    assert "token" not in serialized
    assert "hostname" not in serialized
    with pytest.raises(RollbackPlanError):
        create_rollback_preview_record("full_disk_restore")
    with pytest.raises(RollbackPlanError):
        create_rollback_preview_record("config_rollback", operator_steps=("~operator restore step",))
    with pytest.raises(RollbackPlanError):
        RollbackPreviewRecord.from_dict({**exported, "preview_only": False})
    with pytest.raises(RollbackPlanError):
        RollbackPreviewRecord.from_dict({**exported, "destructive_action": True})
    with pytest.raises(RollbackPlanError):
        RollbackPreviewRecord.from_dict({**exported, "restore_executed": True})
    with pytest.raises(RollbackPlanError):
        RollbackPreviewRecord.from_dict({**exported, "file_deleted": True})
    with pytest.raises(RollbackPlanError):
        RollbackPreviewRecord.from_dict({**exported, "file_overwritten": True})
    with pytest.raises(RollbackPlanError):
        RollbackPreviewRecord.from_dict({**exported, "config_modified": True})
    with pytest.raises(RollbackPlanError):
        RollbackPreviewRecord.from_dict({**exported, "migration_executed": True})


def test_secure_update_summaries_accept_serialized_records():
    update = create_update_verification_record("compatibility_manifest", verification_state="blocked")
    rollback = create_rollback_preview_record("package_rollback", rollback_state="blocked")

    update_summary = summarize_update_verification([update.to_dict()])
    rollback_summary = summarize_rollback_previews([rollback.to_dict()])

    assert update_summary["record_count"] == 1
    assert update_summary["by_verification_state"]["blocked"] == 1
    assert update_summary["operator_action_required"] is True
    assert rollback_summary["record_count"] == 1
    assert rollback_summary["by_rollback_state"]["blocked"] == 1
    assert rollback_summary["destructive_action"] is False
