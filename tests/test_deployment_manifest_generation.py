import json
import re

import pytest

from core_engine.deployment import (
    DEPLOYMENT_MANIFEST_MODES,
    NODE_PROFILE_NAMES,
    build_deployment_manifest,
    build_deployment_manifest_catalog,
    build_node_deployment_profile,
    build_node_profile_catalog,
    deployment_manifest_to_dict,
    export_deployment_manifest,
    list_node_deployment_profiles,
)


FIXED_TIME = "2026-01-01T00:00:00+00:00"

PRIVATE_IDENTIFIER_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/Users/"),
    re.compile(r"/home/"),
    re.compile(r"\\\\Users\\\\"),
]


def test_node_deployment_profiles_cover_cross_platform_targets():
    profiles = list_node_deployment_profiles(generated_at=FIXED_TIME)

    assert {profile["profile_name"] for profile in profiles} == NODE_PROFILE_NAMES
    for profile in profiles:
        assert profile["metadata_only"] is True
        assert profile["dry_run_only"] is True
        assert profile["deployment_action_performed"] is False
        assert profile["credentials_generated"] is False
        assert profile["estimated_resource_envelope"]["recommended_memory_mb"] > 0
        assert profile["deployment_suitability"]


def test_node_profile_catalog_is_deterministic():
    first = build_node_profile_catalog(generated_at=FIXED_TIME)
    second = build_node_profile_catalog(generated_at=FIXED_TIME)

    assert first == second
    assert first["profile_names"] == [
        "lab-node",
        "lightweight-worker",
        "linux-server",
        "macos-workstation",
        "raspberry-pi-edge",
        "windows-workstation",
    ]


def test_manifest_catalog_contains_all_modes_and_is_deterministic():
    first = build_deployment_manifest_catalog(generated_at=FIXED_TIME)
    second = build_deployment_manifest_catalog(generated_at=FIXED_TIME)

    assert first == second
    assert set(first["deployment_modes"]) == DEPLOYMENT_MANIFEST_MODES
    assert first["manifest_count"] == 6
    assert first["dry_run_only"] is True


def test_edge_manifest_is_sanitized_and_export_safe():
    manifest = build_deployment_manifest("edge", generated_at=FIXED_TIME)
    serialized = json.dumps(manifest, sort_keys=True)

    assert manifest["deployment_mode"] == "edge"
    assert manifest["runtime_profile"]["profile_name"] == "edge"
    assert manifest["node_profile"]["profile_name"] == "raspberry-pi-edge"
    assert manifest["service_provider_mode"] == "raspberry-pi-systemd-edge"
    assert manifest["dry_run_only"] is True
    assert manifest["metadata_only"] is True
    assert manifest["export_safe"] is True
    assert manifest["credentials_generated"] is False
    assert manifest["real_paths_included"] is False
    assert "<operator-approved-export-dir>/edge-manifest.json" == manifest["export_paths"]["manifest_output_path"]
    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(serialized)


def test_production_preview_manifest_uses_production_profile_and_service_preview():
    manifest = build_deployment_manifest("production_preview", generated_at=FIXED_TIME)

    assert manifest["deployment_mode"] == "production_preview"
    assert manifest["runtime_profile"]["profile_name"] == "production"
    assert manifest["node_profile"]["profile_name"] == "linux-server"
    assert manifest["service_provider_mode"] == "linux-systemd"
    assert "service_lifecycle_preview" in manifest["required_components"]
    assert manifest["deployment_readiness"]["state"] in {"supported", "degraded"}
    assert manifest["service_installed"] is False
    assert manifest["deployment_package_created"] is False


def test_manifest_degraded_transition_for_mismatched_node_profile():
    manifest = build_deployment_manifest(
        "orchestrator",
        node_profile="lightweight-worker",
        generated_at=FIXED_TIME,
    )

    assert manifest["deployment_readiness"]["state"] == "unsupported"
    assert manifest["deployment_readiness"]["check_states"]["node_suitability"] == "unsupported"


def test_manifest_degraded_transition_for_windows_service_preview_without_admin():
    manifest = build_deployment_manifest(
        "standalone",
        service_provider={
            "provider": "windows-service-control-manager",
            "platform": "windows",
            "state": "degraded",
            "required_permissions": ["manual_admin_review"],
            "warnings": ["windows_service_preview_only"],
            "service_installed": False,
            "windows_service_registered": False,
        },
        generated_at=FIXED_TIME,
    )

    assert manifest["deployment_readiness"]["state"] == "degraded"
    assert manifest["deployment_readiness"]["check_states"]["service_provider"] == "degraded"
    assert manifest["advisory_notes"]


def test_manifest_serialization_is_export_safe_and_minimal():
    manifest = build_deployment_manifest("lab", generated_at=FIXED_TIME)
    payload = deployment_manifest_to_dict(manifest)
    text = export_deployment_manifest(manifest)

    assert json.loads(text) == payload
    assert payload["deployment_mode"] == "lab"
    assert payload["dry_run_only"] is True
    assert payload["config_written"] is False
    assert payload["credentials_generated"] is False
    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(text)


def test_invalid_manifest_and_node_profile_names_are_rejected():
    with pytest.raises(ValueError):
        build_deployment_manifest("cloud")
    with pytest.raises(ValueError):
        build_node_deployment_profile("private-node")
