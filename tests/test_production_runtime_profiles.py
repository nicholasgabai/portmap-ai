import json
import re

import pytest

from core_engine.deployment import (
    DEPLOYMENT_PROFILE_NAMES,
    build_deployment_profile_catalog,
    build_deployment_runtime_profile,
    deployment_runtime_profile_to_dict,
    export_deployment_runtime_profile,
    list_deployment_runtime_profiles,
    production_runtime_profile,
    summarize_deployment_runtime_profile,
    validate_deployment_runtime_profile,
)


PRIVATE_IDENTIFIER_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/Users/"),
    re.compile(r"/home/"),
]


FIXED_TIME = "2026-01-01T00:00:00+00:00"


def test_all_deployment_runtime_profiles_are_safe_metadata_records():
    profiles = list_deployment_runtime_profiles(generated_at=FIXED_TIME)

    assert {profile["profile_name"] for profile in profiles} == DEPLOYMENT_PROFILE_NAMES
    for profile in profiles:
        assert profile["metadata_only"] is True
        assert profile["dry_run"] is True
        assert profile["service_installed"] is False
        assert profile["firewall_rules_changed"] is False
        assert profile["credentials_stored"] is False
        assert profile["host_identifier_included"] is False
        assert profile["ip_address_included"] is False
        assert profile["mac_address_included"] is False
        assert profile["resource_budget"]["min_memory_mb"] > 0
        assert profile["platform_support"]


def test_profile_summary_is_dashboard_and_api_safe():
    profile = production_runtime_profile(generated_at=FIXED_TIME)

    summary = summarize_deployment_runtime_profile(profile)

    assert summary["profile_name"] == "production"
    assert summary["safety_mode"] == "review-required"
    assert summary["telemetry_level"] == "enhanced"
    assert summary["operator_summary"]
    assert summary["dashboard_safe"] is True
    assert summary["api_compatible"] is True


def test_profile_catalog_is_deterministic_for_fixed_time():
    first = build_deployment_profile_catalog(generated_at=FIXED_TIME)
    second = build_deployment_profile_catalog(generated_at=FIXED_TIME)

    assert first == second
    assert first["profile_names"] == ["development", "edge", "lab", "production", "staging"]
    assert first["profile_count"] == 5


def test_supported_profile_validation_for_production_linux_inputs():
    result = validate_deployment_runtime_profile(
        "production",
        platform_info={"system": "Linux", "release": "linux-release-placeholder", "machine": "x86_64", "python_version": "3.11.5"},
        available_memory_mb=8192,
        available_disk_mb=32768,
        packet_capture_readiness={"summary": {"status": "supported"}},
        firewall_provider_readiness={"summary": {"status": "supported"}},
        deployment_mode="master",
        generated_at=FIXED_TIME,
    )

    assert result["state"] == "supported"
    assert result["summary"]["supported_count"] == 6
    assert result["operator_advisory"]["operator_review_required"] is False
    assert result["export"]["state"] == "supported"


def test_degraded_profile_validation_for_missing_resources_and_readiness():
    result = validate_deployment_runtime_profile(
        "staging",
        platform_info={"system": "Darwin", "release": "macos-release-placeholder", "machine": "arm64", "python_version": "3.11.5"},
        available_memory_mb=None,
        available_disk_mb=4096,
        packet_capture_readiness=None,
        firewall_provider_readiness="unknown",
        deployment_mode="orchestrator",
        generated_at=FIXED_TIME,
    )

    assert result["state"] == "degraded"
    check_states = result["export"]["check_states"]
    assert check_states["memory"] == "degraded"
    assert check_states["packet_capture_readiness"] == "degraded"
    assert check_states["firewall_provider_readiness"] == "degraded"
    assert result["operator_advisory"]["operator_review_required"] is True


def test_unsupported_profile_validation_for_edge_on_windows():
    result = validate_deployment_runtime_profile(
        "edge",
        platform_info={"system": "Windows", "release": "windows-release-placeholder", "machine": "AMD64", "python_version": "3.11.5"},
        available_memory_mb=256,
        available_disk_mb=128,
        packet_capture_readiness={"summary": {"status": "unavailable"}},
        firewall_provider_readiness={"summary": {"status": "supported"}},
        deployment_mode="orchestrator",
        generated_at=FIXED_TIME,
    )

    assert result["state"] == "unsupported"
    check_states = result["export"]["check_states"]
    assert check_states["operating_system"] == "unsupported"
    assert check_states["memory"] == "unsupported"
    assert check_states["disk"] == "unsupported"
    assert check_states["deployment_mode"] == "unsupported"


def test_profile_serialization_is_export_safe_and_sanitized():
    profile = build_deployment_runtime_profile("lab", generated_at=FIXED_TIME)
    payload = deployment_runtime_profile_to_dict(profile)
    text = export_deployment_runtime_profile(payload)
    loaded = json.loads(text)

    assert loaded == payload
    assert loaded["export_safe"] is True
    assert loaded["raw_payload_stored"] is False
    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(text)


def test_invalid_profile_name_is_rejected():
    with pytest.raises(ValueError):
        build_deployment_runtime_profile("unsafe")
