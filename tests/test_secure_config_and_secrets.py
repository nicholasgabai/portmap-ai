import json

import pytest

from core_engine.security import (
    SecretManagementPreview,
    SecretsManagementError,
    SecureConfigError,
    SecureConfigProfile,
    create_secret_management_preview,
    create_secure_config_profile,
    summarize_secret_management_previews,
    summarize_secure_config_profiles,
)


def test_secure_config_profile_generation_covers_states():
    development = create_secure_config_profile("development")
    staging = create_secure_config_profile("staging")
    production = create_secure_config_profile("production")
    edge = create_secure_config_profile("edge")
    ephemeral = create_secure_config_profile("ephemeral_runtime")

    assert development.export_safety == "insecure"
    assert development.encryption_required is False
    assert staging.export_safety == "recommended"
    assert production.export_safety == "required"
    assert edge.secret_storage_mode == "memory_only"
    assert ephemeral.export_safety == "degraded"
    assert all(profile.to_dict()["credentials_stored"] is False for profile in [development, staging, production, edge, ephemeral])
    assert all(profile.to_dict()["live_encryption_enabled"] is False for profile in [development, staging, production, edge, ephemeral])


def test_secure_config_export_serialization_rejects_live_side_effects():
    profile = create_secure_config_profile("production")
    exported = profile.to_dict()
    serialized = json.dumps(exported, sort_keys=True)

    assert SecureConfigProfile.from_dict(exported) == profile
    assert "real-secret" not in serialized
    assert exported["os_keychain_integrated"] is False
    assert exported["plaintext_secret_persistence_allowed"] is False
    with pytest.raises(SecureConfigError):
        create_secure_config_profile("personal_laptop")
    with pytest.raises(SecureConfigError):
        SecureConfigProfile.from_dict({**exported, "credentials_stored": True})
    with pytest.raises(SecureConfigError):
        SecureConfigProfile.from_dict({**exported, "plaintext_secret_persistence_allowed": True})
    with pytest.raises(SecureConfigError):
        SecureConfigProfile.from_dict({**exported, "os_keychain_integrated": True})


def test_secure_config_summary_is_export_safe():
    summary = summarize_secure_config_profiles(["development", "staging", "production", "edge", "ephemeral_runtime"])

    assert summary["profile_count"] == 5
    assert summary["by_export_safety"]["insecure"] == 1
    assert summary["by_export_safety"]["degraded"] == 1
    assert summary["by_export_safety"]["recommended"] == 2
    assert summary["by_export_safety"]["required"] == 1
    assert summary["dry_run_only"] is True
    assert summary["credentials_stored"] is False


def test_secret_management_preview_defaults_and_rotation_readiness():
    orchestrator = create_secret_management_preview("orchestrator_token")
    enrollment = create_secret_management_preview("worker_enrollment_secret")
    mtls = create_secret_management_preview("future_mtls_material")
    api = create_secret_management_preview("api_session_token")
    runtime_key = create_secret_management_preview("runtime_encryption_key")

    assert orchestrator.storage_mode == "memory_only"
    assert orchestrator.plaintext_allowed is False
    assert enrollment.expiration_supported is True
    assert mtls.storage_mode == "external_secret_provider_ready"
    assert mtls.rotation_ready is True
    assert api.expiration_supported is True
    assert runtime_key.storage_mode == "encrypted_storage_ready"
    assert runtime_key.rotation_ready is True
    assert all(item.to_dict()["credential_stored"] is False for item in [orchestrator, enrollment, mtls, api, runtime_key])


def test_secret_preview_rejects_plaintext_and_side_effects():
    preview = create_secret_management_preview("api_session_token", storage_mode="ephemeral")
    exported = preview.to_dict()

    assert SecretManagementPreview.from_dict(exported) == preview
    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["plaintext_persisted"] is False
    with pytest.raises(SecretsManagementError):
        create_secret_management_preview("database_password")
    with pytest.raises(SecretsManagementError):
        create_secret_management_preview("api_session_token", storage_mode="plaintext_file")
    with pytest.raises(SecretsManagementError):
        SecretManagementPreview.from_dict({**exported, "plaintext_allowed": True})
    with pytest.raises(SecretsManagementError):
        SecretManagementPreview.from_dict({**exported, "secret_generated": True})
    with pytest.raises(SecretsManagementError):
        SecretManagementPreview.from_dict({**exported, "os_credential_store_modified": True})
    with pytest.raises(SecretsManagementError):
        SecretManagementPreview.from_dict({**exported, "live_secret_exchange_performed": True})


def test_secret_management_summary_has_no_plaintext_persistence():
    summary = summarize_secret_management_previews()
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["preview_count"] == 5
    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert summary["secret_generated"] is False
    assert summary["credential_stored"] is False
    assert summary["plaintext_persisted"] is False
    assert summary["os_credential_store_modified"] is False
    assert "BEGIN" not in serialized
    assert "real-secret" not in serialized
