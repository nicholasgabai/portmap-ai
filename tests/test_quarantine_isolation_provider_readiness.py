import json

import pytest

from core_engine.remediation import (
    IsolationProviderError,
    QuarantineReadinessError,
    build_provider_matrix,
    build_provider_readiness,
    build_quarantine_preview,
    build_quarantine_readiness_summary,
    deterministic_provider_readiness_json,
    deterministic_quarantine_readiness_json,
    provider_readiness_to_dict,
    quarantine_preview_to_dict,
    sanitize_command_preview,
    sanitize_target_reference,
)


NOW = "2026-06-06T12:00:00+00:00"


def test_provider_readiness_generation_and_export_safety():
    provider = build_provider_readiness("generic_manual_operator", platform_family="unknown", now=NOW)
    exported = provider_readiness_to_dict(provider)

    assert exported["provider_name"] == "generic_manual_operator"
    assert exported["readiness_state"] == "ready"
    assert exported["supported_actions"] == ["manual_review"]
    assert exported["dry_run_supported"] is True
    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["firewall_changes"] is False
    assert exported["service_changes"] is False
    assert exported["process_changes"] is False
    assert json.loads(deterministic_provider_readiness_json(exported)) == exported


def test_platform_specific_provider_states():
    macos = build_provider_readiness("macos_pf", platform_family="macos", now=NOW)
    linux_nft = build_provider_readiness("linux_nftables", platform_family="linux", now=NOW)
    linux_ufw = build_provider_readiness("linux_ufw", platform_family="linux", now=NOW)
    linux_iptables = build_provider_readiness("linux_iptables", platform_family="linux", now=NOW)
    windows = build_provider_readiness("windows_defender_firewall", platform_family="windows", now=NOW)
    raspberry = build_provider_readiness("raspberry_pi_edge", platform_family="raspberry_pi", now=NOW)

    assert macos.readiness_state == "ready"
    assert "block_port_preview" in macos.supported_actions
    assert linux_nft.readiness_state == "ready"
    assert "rate_limit_preview" in linux_nft.supported_actions
    assert linux_ufw.readiness_state == "ready"
    assert "block_destination_preview" in linux_ufw.supported_actions
    assert linux_iptables.readiness_state == "ready"
    assert windows.readiness_state == "ready"
    assert "quarantine_service_preview" in windows.supported_actions
    assert raspberry.readiness_state == "degraded"
    assert raspberry.elevation_required is True


def test_unsupported_provider_degrades_to_manual_review():
    provider = build_provider_readiness("unknown_vendor", platform_family="linux", now=NOW)
    exported = provider_readiness_to_dict(provider)

    assert exported["provider_name"] == "generic_manual_operator"
    assert exported["readiness_state"] == "unknown"
    assert exported["supported_actions"] == ["manual_review"]
    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False


def test_quarantine_preview_generation_approval_rollback_and_blast_radius():
    provider = build_provider_readiness("linux_nftables", platform_family="linux", now=NOW)
    preview = build_quarantine_preview(
        preview_type="block_port_preview",
        target_class="port",
        target_reference="tcp-22-fixture",
        provider=provider,
        now=NOW,
    )
    exported = quarantine_preview_to_dict(preview)

    assert exported["preview_type"] == "block_port_preview"
    assert exported["target_reference"] == "tcp-22-fixture"
    assert exported["provider_name"] == "linux_nftables"
    assert exported["readiness_state"] == "ready"
    assert exported["approval_required"] is True
    assert exported["rollback_required"] is True
    assert "network metadata" in exported["blast_radius_summary"]
    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["node_isolation_performed"] is False
    assert json.loads(deterministic_quarantine_readiness_json(exported)) == exported


def test_provider_action_unavailable_creates_safety_blocker():
    provider = build_provider_readiness("linux_ufw", platform_family="linux", now=NOW)
    preview = build_quarantine_preview(
        preview_type="isolate_node_preview",
        target_class="node",
        target_reference="node-fixture",
        provider=provider,
        now=NOW,
    )

    assert preview.readiness_state == "degraded"
    assert "provider_action_unavailable" in preview.safety_blockers
    assert preview.preview_only is True
    assert preview.destructive_action is False


def test_command_and_target_previews_are_sanitized():
    example_address = "192" + ".0.2.10"
    example_mac = "00" + ":11:22:33:44:55"
    example_path = "/" + "Users/example/private"
    command = sanitize_command_preview(
        f"pfctl block {example_address} --token example-token {example_path} {example_mac}"
    )
    target = sanitize_target_reference(f"admin@example.invalid {example_address} {example_path}")

    assert example_address not in command
    assert "example-token" not in command
    assert "/" + "Users/" not in command
    assert example_mac not in command
    assert target.startswith("redacted-target-")
    assert "example.invalid" not in target
    assert example_address not in target
    assert "/" + "Users/" not in target


def test_preview_summary_and_matrix_are_export_safe():
    matrix = build_provider_matrix("windows", now=NOW)
    provider = build_provider_readiness("windows_defender_firewall", platform_family="windows", now=NOW)
    previews = [
        build_quarantine_preview(
            preview_type="manual_review",
            target_class="unknown",
            target_reference="review-fixture",
            provider=provider,
            now=NOW,
        ),
        build_quarantine_preview(
            preview_type="block_destination_preview",
            target_class="destination",
            target_reference="dest-fixture",
            provider=provider,
            now=NOW,
        ),
    ]
    summary = build_quarantine_readiness_summary(previews)
    serialized = json.dumps(
        {
            "matrix": [provider_readiness_to_dict(row) for row in matrix],
            "summary": summary,
            "previews": [quarantine_preview_to_dict(row) for row in previews],
        },
        sort_keys=True,
    )

    assert len(matrix) == 7
    assert summary["preview_count"] == 2
    assert summary["approval_required_count"] == 2
    assert summary["rollback_required_count"] == 1
    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert "192.168." not in serialized
    assert "/" + "Users/" not in serialized
    assert "PRIVATE" + " KEY" not in serialized


def test_malformed_input_handling_and_safety_invariants():
    with pytest.raises(IsolationProviderError):
        build_provider_readiness("macos_pf", platform_family="macos", now=NOW).__class__(
            provider_name="macos_pf",
            platform_family="macos",
            supported_actions=["execute_now"],
        )
    with pytest.raises(QuarantineReadinessError):
        build_quarantine_preview(
            preview_type="block_port_preview",
            target_class="port",
            target_reference="target-fixture",
            provider=build_provider_readiness("macos_pf", platform_family="macos", now=NOW),
            now=NOW,
        ).__class__(
            preview_id="preview-bad",
            preview_type="block_port_preview",
            target_class="port",
            target_reference="target-fixture",
            provider_name="macos_pf",
            readiness_state="ready",
            preview_only=False,
        )


def test_cross_platform_unavailable_provider_does_not_create_side_effects():
    provider = build_provider_readiness("windows_defender_firewall", platform_family="macos", now=NOW)
    preview = build_quarantine_preview(
        preview_type="block_port_preview",
        target_class="port",
        target_reference="tcp-443-fixture",
        provider=provider,
        now=NOW,
    )
    exported_provider = provider_readiness_to_dict(provider)
    exported_preview = quarantine_preview_to_dict(preview)

    assert exported_provider["readiness_state"] == "unavailable"
    assert exported_preview["readiness_state"] == "unavailable"
    assert "provider_state:unavailable" in exported_preview["safety_blockers"]
    assert exported_preview["preview_only"] is True
    assert exported_preview["destructive_action"] is False
    assert exported_preview["firewall_changes"] is False
    assert exported_preview["service_changes"] is False
    assert exported_preview["process_changes"] is False
