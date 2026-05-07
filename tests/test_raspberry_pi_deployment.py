import json
from pathlib import Path

from core_engine.config_loader import load_node_config
from core_engine.config_validation import validate_config_file


def test_raspberry_pi_profile_loads_low_resource_defaults(tmp_path, monkeypatch):
    config_path = tmp_path / "worker.json"
    config_path.write_text(json.dumps({
        "node_role": "worker",
        "node_id": "pi-worker",
        "profile": "raspberry_pi",
    }))

    monkeypatch.setenv("PORTMAP_SCAN_INTERVAL", "30")
    monkeypatch.setenv("PORTMAP_MASTER_HOST", "192.168.1.20")

    config, _ = load_node_config(str(config_path), include_settings=False)

    assert config["profile"] == "raspberry_pi"
    assert config["scan_interval"] == "30"
    assert config["master_ip"] == "192.168.1.20"
    assert config["timeout"] == "5"
    assert config["log_max_bytes"] == "1048576"


def test_raspberry_pi_profile_validates_with_worker_config(tmp_path):
    config_path = tmp_path / "worker.json"
    config_path.write_text(json.dumps({
        "node_role": "worker",
        "node_id": "pi-worker",
        "profile": "raspberry_pi",
    }))

    result = validate_config_file(str(config_path), include_settings=False, expected_role="worker")

    assert result.ok, result.to_dict()


def test_systemd_templates_use_packaged_cli_and_user_runtime_paths():
    stack = Path("deploy/systemd/portmap-ai-stack.service").read_text()
    worker = Path("deploy/systemd/portmap-ai-worker.service").read_text()

    assert "/usr/bin/env portmap stack" in stack
    assert "--no-dashboard" in stack
    assert "--watch-config" in stack
    assert "Restart=on-failure" in stack
    assert "network-online.target" in stack
    assert "%h/.portmap-ai/exports" in stack
    assert "EnvironmentFile=-%h/.portmap-ai/portmap-ai.env" in stack

    assert "/usr/bin/env portmap-worker" in worker
    assert "%h/.portmap-ai/data/worker.json" in worker
    assert "Restart=on-failure" in worker
    assert "PORTMAP_ORCHESTRATOR_URL" in worker
    assert "PORTMAP_ORCHESTRATOR_TOKEN=test-token" not in worker
    assert "EnvironmentFile=-%h/.portmap-ai/portmap-ai.env" in worker


def test_systemd_install_script_is_user_scoped_not_system_wide():
    script = Path("scripts/install_systemd_user.sh").read_text()

    assert ".config/systemd/user" in script
    assert "systemctl --user daemon-reload" in script
    assert "systemctl --user enable" in script
    assert "portmap-ai.env" in script
    assert "secrets.token_urlsafe" in script
    assert "chmod 600" in script
    assert "sudo" not in script
