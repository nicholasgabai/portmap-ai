import json
import re

import pytest

from core_engine.runtime import (
    RuntimeProfileError,
    default_runtime_profile,
    edge_device_runtime_profile,
    export_runtime_profile,
    get_builtin_runtime_profile,
    import_runtime_profile,
    load_runtime_profile,
    load_runtime_profile_file,
    merge_runtime_profiles,
    save_runtime_profile_file,
    summarize_runtime_profile,
    validate_runtime_profile,
)


PRIVATE_IDENTIFIER_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


def test_default_runtime_profile_has_safe_defaults():
    profile = default_runtime_profile(generated_at="2026-01-01T00:00:00+00:00")
    payload = profile.to_dict()

    assert payload["profile_id"] == "runtime-default"
    assert payload["runtime_mode"] == "dry-run"
    assert payload["api"]["bind_host"] == "127.0.0.1"
    assert payload["api"]["read_only"] is True
    assert payload["storage"]["backend"] == "sqlite"
    assert payload["export"]["redaction_required"] is True
    assert payload["automatic_changes"] is False
    assert payload["administrator_controlled"] is True
    assert payload["raw_payload_stored"] is False


def test_edge_device_profile_overrides_resource_defaults():
    profile = edge_device_runtime_profile(generated_at="2026-01-01T00:00:00+00:00")
    payload = profile.to_dict()

    assert payload["profile_id"] == "runtime-edge-device"
    assert payload["profile_type"] == "edge-device"
    assert payload["scheduler"]["poll_interval_seconds"] == 15
    assert payload["scheduler"]["jobs"]["health_check"]["interval_seconds"] == 180
    assert payload["metadata"]["resource_profile"] == "edge-device"


def test_operator_profile_merge_preserves_base_defaults():
    merged = merge_runtime_profiles(
        default_runtime_profile(generated_at="2026-01-01T00:00:00+00:00"),
        {
            "profile_id": "operator-profile",
            "name": "Operator Profile",
            "runtime_mode": "local-write",
            "api": {"enabled": True, "port": 9300},
            "scheduler": {"jobs": {"event_flush": {"enabled": True}}},
        },
    )
    payload = merged.to_dict()

    assert payload["profile_id"] == "operator-profile"
    assert payload["runtime_mode"] == "local-write"
    assert payload["api"]["bind_host"] == "127.0.0.1"
    assert payload["api"]["port"] == 9300
    assert payload["scheduler"]["jobs"]["event_flush"]["enabled"] is True
    assert payload["scheduler"]["jobs"]["event_flush"]["interval_seconds"] == 120


def test_profile_validation_accepts_embedded_node_configs():
    profile = merge_runtime_profiles(
        default_runtime_profile(generated_at="2026-01-01T00:00:00+00:00"),
        {
            "profile_id": "with-node-config",
            "name": "With Node Config",
            "node_configs": {
                "worker": {
                    "node_role": "worker",
                    "node_id": "worker-alpha",
                    "master_ip": "127.0.0.1",
                    "port": 9000,
                }
            },
        },
    )

    result = validate_runtime_profile(profile)

    assert result["ok"] is True


def test_profile_validation_rejects_invalid_values():
    payload = default_runtime_profile(generated_at="2026-01-01T00:00:00+00:00").to_dict()
    payload["runtime_mode"] = "external-sync"
    payload["api"]["port"] = 70000

    result = validate_runtime_profile(payload)

    assert result["ok"] is False
    assert "runtime_mode must be one of" in "\n".join(result["errors"])
    assert "api.port must be an integer between 1 and 65535" in result["errors"]
    with pytest.raises(RuntimeProfileError):
        import_runtime_profile(json.dumps(payload))


def test_profile_summary_is_operator_readable():
    profile = default_runtime_profile(generated_at="2026-01-01T00:00:00+00:00")

    summary = summarize_runtime_profile(profile)

    assert summary["profile_id"] == "runtime-default"
    assert summary["component_count"] > 0
    assert summary["enabled_jobs"] == ["health_check"]
    assert summary["api_port"] == 9200
    assert summary["validation"]["ok"] is True


def test_builtin_profile_loader_aliases_raspberry_pi():
    profile = get_builtin_runtime_profile("raspberry-pi")

    assert profile.profile_id == "runtime-edge-device"
    with pytest.raises(RuntimeProfileError):
        get_builtin_runtime_profile("missing")


def test_json_import_export_round_trip():
    profile = default_runtime_profile(generated_at="2026-01-01T00:00:00+00:00")

    text = export_runtime_profile(profile)
    loaded = import_runtime_profile(text)

    assert loaded.to_dict() == profile.to_dict()


def test_profile_file_load_save_and_merge(tmp_path):
    output = tmp_path / "profiles" / "operator.json"
    operator_payload = {
        "profile_id": "operator-file",
        "name": "Operator File",
        "api": {"enabled": True},
        "export": {"create_archive": True},
    }
    operator_path = tmp_path / "operator-input.json"
    operator_path.write_text(json.dumps(operator_payload), encoding="utf-8")

    loaded = load_runtime_profile(operator_path=operator_path)
    result = save_runtime_profile_file(loaded, output)
    reloaded = load_runtime_profile_file(output)

    assert loaded.profile_id == "operator-file"
    assert loaded.api["enabled"] is True
    assert loaded.export["create_archive"] is True
    assert result["ok"] is True
    assert reloaded.to_dict() == loaded.to_dict()


def test_load_runtime_profile_without_operator_uses_builtin():
    profile = load_runtime_profile(builtin="edge-device")

    assert profile.profile_id == "runtime-edge-device"


def test_runtime_profile_output_does_not_contain_private_identifiers():
    profile = merge_runtime_profiles(
        default_runtime_profile(generated_at="2026-01-01T00:00:00+00:00"),
        {"profile_id": "sanitized-profile", "name": "Sanitized Profile", "metadata": {"note": "fixture only"}},
    )
    payload = json.dumps(profile.to_dict(), sort_keys=True)

    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(payload)
