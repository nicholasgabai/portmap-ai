from __future__ import annotations

import json

from core_engine.packaging import (
    build_container_deployment_readiness,
    build_container_profile_preview,
    deterministic_container_deployment_json,
    deterministic_container_profile_json,
    empty_container_deployment_readiness,
    normalize_container_deployment_method,
    normalize_container_deployment_state,
    normalize_container_profile_preview,
    normalize_container_profile_type,
    normalize_container_runtime,
    sanitize_environment_preview,
    sanitize_image_reference_preview,
)


GENERATED_AT = "2026-06-11T12:00:00+00:00"


def test_container_profile_creation_is_safe():
    profile = build_container_profile_preview(
        profile_name="single node preview",
        profile_type="single_node_preview",
        container_runtime="docker",
        image_reference_preview="portmap-ai:preview",
        rollback_available=True,
        uninstall_available=True,
    ).to_dict()

    assert profile["record_type"] == "container_profile_preview"
    assert profile["profile_type"] == "single_node_preview"
    assert profile["container_runtime"] == "docker"
    assert profile["rollback_available"] is True
    assert profile["uninstall_available"] is True
    assert profile["preview_only"] is True
    assert profile["destructive_action"] is False
    assert profile["image_built"] is False
    assert profile["container_started"] is False
    assert profile["compose_file_written"] is False


def test_profile_type_and_runtime_validation():
    assert normalize_container_profile_type("worker_only_preview") == "worker_only_preview"
    assert normalize_container_profile_type("bad") == "unknown"
    assert normalize_container_runtime("podman") == "podman"
    assert normalize_container_runtime("bad") == "unknown"

    profile = build_container_profile_preview(profile_type="danger", container_runtime="daemon").to_dict()

    assert profile["profile_type"] == "unknown"
    assert profile["container_runtime"] == "unknown"


def test_image_env_volume_and_network_preview_sanitization():
    image = sanitize_image_reference_preview("repo/portmap:latest; docker run x | whoami && echo test")
    env = sanitize_environment_preview({"PORTMAP_MODE": "preview", "API_TOKEN": "secret-value"})
    profile = build_container_profile_preview(
        image_reference_preview="repo/portmap:latest; docker run x | whoami",
        volume_layout_preview={"mount;bad": "/data | bad"},
        network_layout_preview={"network|bad": "bridge && host"},
        environment_preview={"PASSWORD": "cleartext", "PORTMAP_MODE": "preview"},
    ).to_dict()

    assert ";" not in image
    assert "|" not in image
    assert "&" not in image
    assert env["API_TOKEN"] == "<redacted>"
    assert profile["environment_preview"]["PASSWORD"] == "<redacted>"
    assert profile["volume_layout_preview"]["mount-bad"] == "/data bad"
    assert profile["network_layout_preview"]["network-bad"] == "bridge host"


def test_docker_preview_readiness_defaults_to_ready():
    readiness = build_container_deployment_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["record_type"] == "container_deployment_readiness"
    assert readiness["deployment_state"] == "ready"
    assert readiness["target_platform"] == "cross_platform"
    assert readiness["deployment_method"] == "docker_preview"
    assert readiness["runtime_readiness"]["container_runtime"] == "docker"
    assert readiness["preview_only"] is True
    assert readiness["destructive_action"] is False
    assert readiness["docker_api_called"] is False
    assert readiness["image_build_executed"] is False
    assert readiness["registry_published"] is False
    assert readiness["container_started"] is False
    assert readiness["compose_file_written"] is False
    assert readiness["filesystem_written"] is False


def test_compose_preview_uses_multi_service_profile():
    readiness = build_container_deployment_readiness(
        deployment_method="compose_preview",
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["deployment_method"] == "compose_preview"
    assert readiness["runtime_readiness"]["container_runtime"] == "compose"
    assert readiness["container_profiles"][0]["profile_type"] == "multi_service_preview"
    assert readiness["compose_readiness"]["compose_applicable"] is True
    assert readiness["compose_readiness"]["compose_file_written"] is False


def test_podman_preview_runtime_summary():
    readiness = build_container_deployment_readiness(
        deployment_method="podman_preview",
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["deployment_method"] == "podman_preview"
    assert readiness["runtime_readiness"]["container_runtime"] == "podman"
    assert readiness["podman_api_called"] is False


def test_worker_orchestrator_and_edge_profile_previews():
    profiles = [
        build_container_profile_preview(profile_type="worker_only_preview", container_runtime="docker"),
        build_container_profile_preview(profile_type="orchestrator_preview", container_runtime="containerd_preview"),
        build_container_profile_preview(profile_type="edge_preview", container_runtime="podman"),
    ]
    readiness = build_container_deployment_readiness(
        deployment_method="compose_preview",
        container_profiles=profiles,
        generated_at=GENERATED_AT,
    ).to_dict()

    types = {profile["profile_type"] for profile in readiness["container_profiles"]}
    assert types == {"worker_only_preview", "orchestrator_preview", "edge_preview"}
    assert readiness["validation_summary"]["profile_summary"]["profile_count"] == 3
    assert readiness["container_profiles"][2]["resource_limits_preview"]["memory_limit_mb"] == 256


def test_resource_limits_summary_is_preview_only():
    profile = build_container_profile_preview(
        resource_limits_preview={"cpu_limit": "2.0", "memory_limit_mb": 1024, "storage_limit_mb": 2048}
    ).to_dict()

    assert profile["resource_limits_preview"]["cpu_limit"] == "2.0"
    assert profile["resource_limits_preview"]["memory_limit_mb"] == 1024
    assert profile["resource_limits_preview"]["preview_only"] is True
    assert profile["resource_limits_preview"]["destructive_action"] is False


def test_rollback_and_uninstall_previews_are_present():
    readiness = build_container_deployment_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["rollback_preview"]["preview_type"] == "rollback"
    assert readiness["uninstall_preview"]["preview_type"] == "uninstall"
    assert readiness["rollback_preview"]["destructive_action"] is False
    assert readiness["uninstall_preview"]["filesystem_written"] is False


def test_validation_summary_counts_profiles_and_previews():
    readiness = build_container_deployment_readiness(generated_at=GENERATED_AT).to_dict()
    validation = readiness["validation_summary"]

    assert validation["record_type"] == "container_deployment_validation_summary"
    assert validation["profile_summary"]["profile_count"] == 1
    assert validation["profile_summary"]["type_counts"]["single_node_preview"] == 1
    assert validation["preview_summary"]["preview_count"] == 2
    assert validation["preview_summary"]["type_counts"]["rollback"] == 1
    assert validation["preview_summary"]["type_counts"]["uninstall"] == 1
    assert validation["image_build_ready"] is True
    assert validation["preview_only"] is True


def test_malformed_input_handling():
    profile = normalize_container_profile_preview(object()).to_dict()
    blocked = build_container_deployment_readiness(
        target_platform="invalid",
        deployment_method="invalid",
        generated_at=GENERATED_AT,
    ).to_dict()

    assert profile["profile_type"] == "unknown"
    assert profile["preview_only"] is True
    assert normalize_container_deployment_method("bad") == "unknown"
    assert normalize_container_deployment_state("bad") == "unknown"
    assert blocked["deployment_state"] == "unavailable"


def test_empty_readiness_summary_is_unavailable():
    readiness = empty_container_deployment_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["deployment_state"] == "unavailable"
    assert readiness["deployment_method"] == "unknown"


def test_preview_and_destructive_flags_are_fixed():
    readiness = build_container_deployment_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["preview_only"] is True
    assert readiness["destructive_action"] is False
    for profile in readiness["container_profiles"]:
        assert profile["preview_only"] is True
        assert profile["destructive_action"] is False
    for key in ["rollback_preview", "uninstall_preview"]:
        assert readiness[key]["preview_only"] is True
        assert readiness[key]["destructive_action"] is False


def test_no_docker_podman_or_filesystem_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    readiness = build_container_deployment_readiness(generated_at=GENERATED_AT).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert readiness["docker_api_called"] is False
    assert readiness["podman_api_called"] is False
    assert readiness["container_runtime_api_called"] is False
    assert readiness["image_created"] is False
    assert readiness["container_started"] is False
    assert readiness["compose_file_written"] is False
    assert readiness["filesystem_written"] is False


def test_export_safe_serialization():
    profile = build_container_profile_preview(profile_type="edge_preview", container_runtime="podman")
    readiness = build_container_deployment_readiness(generated_at=GENERATED_AT)

    json.loads(deterministic_container_profile_json(profile))
    json.loads(deterministic_container_deployment_json(readiness))
    json.dumps(readiness.to_dict(), sort_keys=True)


def test_cross_platform_targets_are_supported_without_runtime_changes():
    for target in ["linux", "macos", "windows", "raspberry_pi", "linux_arm"]:
        readiness = build_container_deployment_readiness(target_platform=target, generated_at=GENERATED_AT).to_dict()
        assert readiness["target_platform"] == target
        assert readiness["deployment_state"] == "ready"


def test_runtime_unavailable_degrades_without_api_calls():
    readiness = build_container_deployment_readiness(
        runtime_readiness={"runtime_available": False},
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["deployment_state"] == "degraded"
    assert readiness["runtime_readiness"]["api_called"] is False
