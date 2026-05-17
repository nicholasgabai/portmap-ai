import json
import re
import sys
from pathlib import Path

import pytest

from core_engine.plugins.manifest import (
    PluginManifestError,
    build_manifest_event,
    build_manifest_finding,
    build_manifest_storage_record,
    normalize_plugin_manifest,
    summarize_manifest_result,
    validate_plugin_manifest,
)
from core_engine.plugins.registry import (
    PluginRegistryError,
    collect_plugin_manifests,
    create_plugin_registry,
    get_plugin,
    list_plugins,
    load_manifest_file,
    register_plugin,
    summarize_registry,
)
from core_engine.plugins.runner import (
    build_execution_correlation_record,
    build_execution_event,
    build_execution_finding,
    build_execution_storage_record,
    build_execution_timeline_entry,
    run_plugin,
    summarize_execution_result,
)


PRIVATE_IDENTIFIER_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


def _manifest(**overrides):
    data = {
        "plugin_id": "plugin.sample.inventory",
        "name": "Sample Inventory Utility",
        "version": "1.0.0",
        "description": "Produces a sanitized local inventory summary.",
        "command": [sys.executable, "-c", "print('sample plugin output')"],
        "capabilities": ["inventory_summary", "metadata_review"],
        "permissions": ["execute_local", "read_metadata"],
        "outputs": ["text", "metadata"],
        "metadata": {"owner": "operator-placeholder"},
    }
    data.update(overrides)
    return data


def test_plugin_manifest_validation_and_normalization():
    result = validate_plugin_manifest(_manifest())

    assert result["ok"] is True
    assert result["classification"] == "valid"
    assert result["summary"]["severity"] == "info"
    assert result["raw_payload_stored"] is False
    assert result["automatic_changes"] is False
    assert result["administrator_controlled"] is True

    normalized = normalize_plugin_manifest(_manifest())
    assert normalized["plugin_id"] == "plugin.sample.inventory"
    assert normalized["lifecycle_state"] == "registered"
    assert normalized["permissions"] == ["execute_local", "read_metadata"]


def test_invalid_manifest_rejection():
    result = validate_plugin_manifest(_manifest(permissions=["execute_local", "remote_control"]))

    assert result["ok"] is False
    assert result["classification"] == "invalid"
    assert "unsupported values" in result["errors"][0]
    with pytest.raises(PluginManifestError):
        normalize_plugin_manifest(_manifest(command=[]))


def test_manifest_operational_records():
    result = validate_plugin_manifest(_manifest())

    summary = summarize_manifest_result(result)
    event = build_manifest_event(result)
    finding = build_manifest_finding(result)
    storage = build_manifest_storage_record(result)

    assert summary["recommended_review"] is False
    assert event["event_type"] == "system_notice"
    assert event["metadata"]["diagnostic_type"] == "plugin_manifest"
    assert finding["category"] == "plugin_registry"
    assert storage["payload"]["plugin_id"] == "plugin.sample.inventory"
    assert storage["raw_payload_stored"] is False


def test_registry_load_register_list_and_summarize(tmp_path):
    manifest_path = tmp_path / "sample-plugin.json"
    manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
    registry = create_plugin_registry(allowlisted_paths=[tmp_path])

    loaded = load_manifest_file(manifest_path)
    entry = register_plugin(registry, loaded, plugin_path=manifest_path)

    assert entry["state"] == "enabled"
    assert entry["source_path_ref"].startswith("path-")
    assert registry["plugin_count"] == 1
    assert get_plugin(registry, "plugin.sample.inventory")["plugin_id"] == "plugin.sample.inventory"
    assert len(list_plugins(registry)) == 1

    summary = summarize_registry(registry)
    assert summary["plugin_count"] == 1
    assert summary["state_counts"]["enabled"] == 1
    assert "inventory_summary" in summary["capabilities"]


def test_registry_rejects_non_allowlisted_path(tmp_path):
    registry = create_plugin_registry(allowlisted_paths=[tmp_path / "allowed"])
    manifest_path = tmp_path / "outside-plugin.json"
    manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")

    with pytest.raises(PluginRegistryError):
        register_plugin(registry, _manifest(), plugin_path=manifest_path)


def test_collect_plugin_manifests(tmp_path):
    (tmp_path / "one.json").write_text(json.dumps(_manifest()), encoding="utf-8")
    (tmp_path / "two.json").write_text(
        json.dumps(_manifest(plugin_id="plugin.sample.policy", capabilities=["policy_review"])),
        encoding="utf-8",
    )

    result = collect_plugin_manifests(tmp_path)

    assert result["ok"] is True
    assert result["manifest_count"] == 2
    assert all(row["ok"] for row in result["validation_results"])
    assert result["automatic_changes"] is False


def test_plugin_runner_dry_run_does_not_execute():
    result = run_plugin(_manifest(command=[sys.executable, "-c", "raise SystemExit(77)"]), dry_run=True)

    assert result["ok"] is True
    assert result["status"] == "dry_run"
    assert result["return_code"] is None
    assert result["stdout_summary"] == ""
    assert result["integration_hooks"]["scheduler_ready"] is True


def test_plugin_runner_executes_with_output_limits():
    result = run_plugin(
        _manifest(command=[sys.executable, "-c", "print('abcdef')"]),
        dry_run=False,
        stdout_limit=4,
    )

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["return_code"] == 0
    assert result["stdout_summary"] == "abcd"
    assert result["stdout_truncated"] is True


def test_plugin_runner_timeout_is_isolated():
    result = run_plugin(
        _manifest(command=[sys.executable, "-c", "import time; time.sleep(1)"]),
        dry_run=False,
        timeout_seconds=0.01,
    )

    assert result["ok"] is False
    assert result["status"] == "timed_out"
    assert result["summary"]["recommended_review"] is True
    assert result["automatic_changes"] is False


def test_plugin_runner_requires_execute_local_permission_for_execution():
    result = run_plugin(
        _manifest(permissions=["read_metadata"]),
        dry_run=False,
    )

    assert result["ok"] is False
    assert result["status"] == "unsupported"
    assert "execute_local" in result["errors"][0]


def test_plugin_runner_environment_allowlist():
    result = run_plugin(
        _manifest(command=[sys.executable, "-c", "import os; print(os.getenv('SAMPLE_ALLOWED', 'missing'))"]),
        dry_run=False,
        env={"SAMPLE_ALLOWED": "visible", "SAMPLE_BLOCKED": "hidden"},
        env_allowlist=["SAMPLE_ALLOWED"],
    )

    assert result["status"] == "completed"
    assert result["stdout_summary"].strip() == "visible"
    assert "hidden" not in result["stdout_summary"]


def test_execution_operational_records():
    result = run_plugin(_manifest(), dry_run=True)

    summary = summarize_execution_result(result)
    event = build_execution_event(result)
    finding = build_execution_finding(result)
    storage = build_execution_storage_record(result)
    timeline = build_execution_timeline_entry(result)
    correlation = build_execution_correlation_record(result)

    assert summary["severity"] == "info"
    assert event["event_type"] == "system_notice"
    assert event["metadata"]["diagnostic_type"] == "plugin_execution"
    assert finding["category"] == "plugin_execution"
    assert storage["payload"]["status"] == "dry_run"
    assert timeline["category"] == "plugin_execution"
    assert correlation["score"] == 0.0
    assert all(row["raw_payload_stored"] is False for row in [event, finding, storage, timeline, correlation])


def test_sample_records_do_not_contain_private_identifiers():
    result = run_plugin(_manifest(), dry_run=True)
    records = [
        validate_plugin_manifest(_manifest()),
        build_manifest_event(validate_plugin_manifest(_manifest())),
        build_execution_event(result),
        build_execution_storage_record(result),
    ]
    payload = json.dumps(records, sort_keys=True)

    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(payload)
