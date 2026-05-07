import json

from core_engine.config_validation import (
    format_validation_result,
    require_valid_config,
    validate_config,
    validate_config_file,
)


def test_validate_packaged_default_configs():
    from core_engine import stack_launcher

    for path in (
        stack_launcher.DEFAULT_ORCHESTRATOR_CFG,
        stack_launcher.DEFAULT_MASTER_CFG,
        stack_launcher.DEFAULT_WORKER_CFG,
    ):
        result = validate_config_file(path)
        assert result.ok, result.to_dict()


def test_validate_rejects_invalid_role_and_port():
    result = validate_config({"node_role": "router", "port": 70000})

    assert not result.ok
    assert "node_role must be one of" in "\n".join(result.errors)
    assert "port must be between 1 and 65535" in result.errors


def test_validate_rejects_unexpected_role():
    result = validate_config({"node_role": "worker", "node_id": "w1"}, expected_role="master")

    assert not result.ok
    assert "expected node_role master, got worker" in result.errors


def test_validate_worker_requires_node_id():
    result = validate_config({"node_role": "worker", "master_ip": "127.0.0.1", "port": 9000})

    assert not result.ok
    assert "worker configs require node_id" in result.errors


def test_validate_legacy_worker_keys_warn_but_pass():
    result = validate_config({
        "mode": "worker",
        "worker_id": "worker-legacy",
        "master_ip": None,
        "port": None,
        "scan_interval": 0,
    })

    assert result.ok
    assert "mode is a legacy key; prefer node_role" in result.warnings
    assert "worker_id is a legacy key; prefer node_id" in result.warnings
    assert "worker master_ip is empty; config is standalone/offline only" in result.warnings


def test_validate_accepts_env_substituted_numeric_strings():
    result = validate_config(
        {
            "node_role": "worker",
            "node_id": "worker-1",
            "master_ip": "127.0.0.1",
            "port": "9000",
            "scan_interval": "5",
            "timeout": "3",
        },
        {
            "remediation_mode": "prompt",
            "remediation_threshold": "0.8",
            "log_max_bytes": "0",
            "log_backup_count": "5",
        },
    )

    assert result.ok, result.to_dict()


def test_validate_rejects_bad_settings_values():
    result = validate_config(
        {"node_role": "orchestrator", "bind_ip": "127.0.0.1", "port": 9100},
        {
            "remediation_mode": "auto",
            "remediation_threshold": 2,
            "tls": {"enabled": "yes"},
            "firewall": {"plugin": "", "options": "bad"},
            "remediation_safety": {"active_enforcement_enabled": "yes"},
            "expected_services": [{"port": 0, "program": 123}],
        },
    )

    assert not result.ok
    text = "\n".join(result.errors)
    assert "remediation_mode must be prompt or silent" in text
    assert "remediation_threshold must be between 0 and 1" in text
    assert "tls.enabled must be a boolean" in text
    assert "firewall.plugin must be a non-empty string" in text
    assert "firewall.options must be an object" in text
    assert "remediation_safety.active_enforcement_enabled must be a boolean" in text
    assert "port must be between 1 and 65535" in text
    assert "expected_services[0].program must be a string" in text


def test_validate_rejects_bad_stale_node_window():
    result = validate_config({"node_role": "orchestrator", "node_stale_after": -1})

    assert not result.ok
    assert "node_stale_after must be 0 or greater" in result.errors


def test_validate_auth_token_types_and_dev_warning():
    bad = validate_config(
        {"node_role": "orchestrator", "bind_ip": "127.0.0.1", "port": 9100, "auth_token": 123},
        {"orchestrator_token": 456},
    )

    assert "auth_token must be a string" in bad.errors
    assert "orchestrator_token must be a string" in bad.errors

    warning = validate_config(
        {"node_role": "orchestrator", "bind_ip": "127.0.0.1", "port": 9100, "auth_token": "test-token"}
    )

    assert warning.ok
    assert any("default development orchestrator token" in item for item in warning.warnings)


def test_validate_config_file_reports_json_errors(tmp_path):
    config = tmp_path / "bad.json"
    config.write_text("{bad")

    result = validate_config_file(str(config))

    assert not result.ok
    assert "Failed to load node config" in result.errors[0]


def test_format_validation_result_includes_errors_and_warnings():
    result = validate_config({"mode": "worker", "worker_id": "w1", "master_ip": None, "port": None})

    formatted = format_validation_result(result)

    assert formatted.startswith("OK")
    assert "warning:" in formatted


def test_validate_config_file_merges_settings(tmp_path, monkeypatch):
    settings_path = tmp_path / "data" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(json.dumps({"remediation_mode": "invalid"}))
    monkeypatch.setattr("core_engine.config_loader.DEFAULT_SETTINGS_FILE", settings_path)

    config = tmp_path / "orchestrator.json"
    config.write_text(json.dumps({"node_role": "orchestrator", "bind_ip": "127.0.0.1", "port": 9100}))

    result = validate_config_file(str(config))

    assert not result.ok
    assert "remediation_mode must be prompt or silent" in result.errors


def test_require_valid_config_raises_readable_error():
    try:
        require_valid_config({"node_role": "worker", "port": 99999}, expected_role="worker")
    except ValueError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected ValueError")

    assert message.startswith("ERROR")
    assert "port must be between 1 and 65535" in message
