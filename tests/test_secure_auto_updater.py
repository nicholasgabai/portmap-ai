from __future__ import annotations

import json
import socket

from core_engine.packaging import (
    build_auto_updater_readiness,
    build_update_channel,
    deterministic_auto_updater_json,
    deterministic_update_channel_json,
    empty_auto_updater_readiness,
    normalize_auto_updater_state,
    normalize_release_tier,
    normalize_update_channel,
    normalize_update_channel_type,
    normalize_update_method,
)


GENERATED_AT = "2026-06-11T12:00:00+00:00"


def test_update_channel_creation_is_safe():
    channel = build_update_channel(
        channel_name="Stable",
        channel_type="stable",
        release_tier="production",
        update_frequency="manual",
    ).to_dict()

    assert channel["record_type"] == "update_channel"
    assert channel["channel_type"] == "stable"
    assert channel["release_tier"] == "production"
    assert channel["rollback_available"] is True
    assert channel["signature_required"] is True
    assert channel["checksum_required"] is True
    assert channel["preview_only"] is True
    assert channel["destructive_action"] is False
    assert channel["network_called"] is False
    assert channel["update_downloaded"] is False


def test_channel_and_release_tier_validation():
    assert normalize_update_channel_type("beta") == "beta"
    assert normalize_update_channel_type("bad") == "unknown"
    assert normalize_release_tier("testing") == "testing"
    assert normalize_release_tier("bad") == "unknown"

    channel = build_update_channel(channel_id="Bad Channel; curl x", channel_type="bad", release_tier="bad").to_dict()

    assert channel["channel_id"] == "bad-channel-curl-x"
    assert channel["channel_type"] == "unknown"
    assert channel["release_tier"] == "unknown"


def test_stable_beta_preview_development_and_offline_channels():
    channels = [
        build_update_channel(channel_name="Stable", channel_type="stable", release_tier="production"),
        build_update_channel(channel_name="Beta", channel_type="beta", release_tier="validation"),
        build_update_channel(channel_name="Preview", channel_type="preview", release_tier="testing"),
        build_update_channel(channel_name="Development", channel_type="development", release_tier="development"),
        build_update_channel(channel_name="Offline", channel_type="offline", release_tier="production", update_frequency="operator supplied"),
    ]
    readiness = build_auto_updater_readiness(update_channels=channels, generated_at=GENERATED_AT).to_dict()

    counts = readiness["validation_summary"]["channel_summary"]["type_counts"]
    assert counts["stable"] == 1
    assert counts["beta"] == 1
    assert counts["preview"] == 1
    assert counts["development"] == 1
    assert counts["offline"] == 1


def test_version_validation_summary():
    readiness = build_auto_updater_readiness(
        version_validation={"current_version_preview": "1.0.0", "target_version_preview": "1.1.0"},
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["version_validation"]["current_version_preview"] == "1.0.0"
    assert readiness["version_validation"]["target_version_preview"] == "1.1.0"
    assert readiness["version_validation"]["version_compatible"] is True
    assert readiness["validation_summary"]["version_compatible"] is True


def test_checksum_validation_summary():
    readiness = build_auto_updater_readiness(
        checksum_validation={"checksum_available": True, "checksum_algorithm_preview": "sha256"},
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["checksum_validation"]["checksum_required"] is True
    assert readiness["checksum_validation"]["checksum_available"] is True
    assert readiness["checksum_validation"]["checksum_verified"] is False
    assert readiness["validation_summary"]["checksum_verified"] is False


def test_signature_validation_summary_does_not_verify_real_signature():
    readiness = build_auto_updater_readiness(
        signature_validation={"signature_available": True, "signing_identity_preview": "release signer"},
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["signature_validation"]["signature_required"] is True
    assert readiness["signature_validation"]["signature_available"] is True
    assert readiness["signature_validation"]["signature_verified"] is False
    assert readiness["signature_validation"]["real_signature_verified"] is False
    assert readiness["validation_summary"]["signature_verified"] is False


def test_staged_rollout_preview_is_bounded_and_manual():
    readiness = build_auto_updater_readiness(
        staged_rollout_preview={"rollout_percentages": [-5, 10, 50, 120], "operator_approval_required": True},
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["staged_rollout_preview"]["rollout_percentages"] == [0, 10, 50, 100]
    assert readiness["staged_rollout_preview"]["operator_approval_required"] is True
    assert readiness["staged_rollout_preview"]["automatic_rollout_enabled"] is False


def test_rollback_and_update_previews_are_present():
    readiness = build_auto_updater_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["rollback_preview"]["preview_type"] == "rollback"
    assert readiness["update_preview"]["preview_type"] == "install"
    assert readiness["rollback_preview"]["destructive_action"] is False
    assert readiness["update_preview"]["command_executed"] is False


def test_update_methods_and_offline_path():
    for method in ["manual_preview", "package_manager_preview", "container_preview", "bundled_updater_preview", "offline_preview"]:
        readiness = build_auto_updater_readiness(update_method=method, generated_at=GENERATED_AT).to_dict()
        assert readiness["update_method"] == method
        assert readiness["updater_state"] == "ready"

    offline = build_auto_updater_readiness(
        update_method="offline_preview",
        update_channels=[build_update_channel(channel_type="offline", release_tier="production")],
        generated_at=GENERATED_AT,
    ).to_dict()
    assert offline["update_channels"][0]["channel_type"] == "offline"
    assert offline["network_called"] is False
    assert offline["update_server_contacted"] is False


def test_malformed_input_handling():
    channel = normalize_update_channel(object()).to_dict()
    blocked = build_auto_updater_readiness(
        target_platform="bad",
        update_method="invalid",
        generated_at=GENERATED_AT,
    ).to_dict()

    assert channel["channel_type"] == "unknown"
    assert channel["preview_only"] is True
    assert normalize_update_method("bad") == "unknown"
    assert normalize_auto_updater_state("bad") == "unknown"
    assert blocked["updater_state"] == "unavailable"


def test_empty_readiness_summary_is_unavailable():
    readiness = empty_auto_updater_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["updater_state"] == "unavailable"
    assert readiness["update_method"] == "unknown"


def test_preview_and_destructive_flags_are_fixed():
    readiness = build_auto_updater_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["preview_only"] is True
    assert readiness["destructive_action"] is False
    for channel in readiness["update_channels"]:
        assert channel["preview_only"] is True
        assert channel["destructive_action"] is False
    for key in ["rollback_preview", "update_preview"]:
        assert readiness[key]["preview_only"] is True
        assert readiness[key]["destructive_action"] is False


def test_no_network_activity(monkeypatch):
    calls: list[tuple[object, ...]] = []

    def fake_create_connection(*args, **kwargs):
        calls.append(args)
        raise AssertionError("network should not be used")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    readiness = build_auto_updater_readiness(generated_at=GENERATED_AT).to_dict()

    assert calls == []
    assert readiness["network_called"] is False
    assert readiness["update_server_contacted"] is False
    assert readiness["update_downloaded"] is False


def test_no_filesystem_changes(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    readiness = build_auto_updater_readiness(generated_at=GENERATED_AT).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert readiness["filesystem_written"] is False
    assert readiness["package_modified"] is False
    assert readiness["update_executed"] is False
    assert readiness["update_installed"] is False


def test_export_safe_serialization():
    channel = build_update_channel(channel_type="preview", release_tier="testing")
    readiness = build_auto_updater_readiness(generated_at=GENERATED_AT)

    json.loads(deterministic_update_channel_json(channel))
    json.loads(deterministic_auto_updater_json(readiness))
    json.dumps(readiness.to_dict(), sort_keys=True)


def test_cross_platform_compatibility():
    for target in ["cross_platform", "windows", "macos", "linux", "raspberry_pi", "linux_arm", "container"]:
        readiness = build_auto_updater_readiness(target_platform=target, generated_at=GENERATED_AT).to_dict()
        assert readiness["target_platform"] == target
        assert readiness["updater_state"] == "ready"


def test_missing_required_validation_degrades_readiness():
    readiness = build_auto_updater_readiness(
        checksum_validation={"checksum_available": False},
        signature_validation={"signature_available": False},
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["updater_state"] == "degraded"
    assert readiness["checksum_validation"]["checksum_verified"] is False
    assert readiness["signature_validation"]["real_signature_verified"] is False
