import json
from pathlib import Path

from core_engine.config_loader import DATA_DIR, load_node_config, load_settings, save_settings


def test_load_settings_creates_defaults(tmp_path, monkeypatch):
    settings_path = tmp_path / "data" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(json.dumps({"remediation_mode": "silent"}))

    monkeypatch.setattr("core_engine.config_loader.DEFAULT_SETTINGS_FILE", settings_path)
    settings = load_settings(defaults={"remediation_threshold": 0.75})
    assert settings["remediation_mode"] == "silent"
    assert settings["remediation_mode"] == "silent"
    assert settings["remediation_threshold"] == 0.75


def test_load_node_config_merges_settings(tmp_path, monkeypatch):
    config_path = tmp_path / "worker.json"
    config_path.write_text(json.dumps({"node_id": "worker-x", "master_ip": "10.0.0.1"}))

    settings_path = tmp_path / "data" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(json.dumps({"enable_autolearn": True, "remediation_threshold": 0.6}))

    monkeypatch.setattr("core_engine.config_loader.DEFAULT_SETTINGS_FILE", settings_path)

    config, settings = load_node_config(str(config_path))

    assert config["node_id"] == "worker-x"
    assert config["master_ip"] == "10.0.0.1"
    assert settings["enable_autolearn"] is True
    assert settings["remediation_threshold"] == 0.6


def test_profile_and_env_substitution(tmp_path, monkeypatch):
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir(parents=True)
    profile_dir.joinpath("lab.json").write_text(json.dumps({
        "master_ip": "${MASTER_IP:192.168.0.10}",
        "timeout": 3
    }))

    monkeypatch.setattr("core_engine.config_loader.PROFILE_DIR", profile_dir)

    config_path = tmp_path / "worker.json"
    config_path.write_text(json.dumps({
        "profile": "lab",
        "port": 9101
    }))

    monkeypatch.setenv("MASTER_IP", "172.16.0.5")

    config, _ = load_node_config(str(config_path))

    assert config["profile"] == "lab"
    assert config["master_ip"] == "172.16.0.5"
    assert config["timeout"] == 3
    assert config["port"] == 9101


def test_settings_env_substitution(tmp_path, monkeypatch):
    settings_path = tmp_path / "data" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(json.dumps({
        "orchestrator_token": "${TOKEN:default-token}",
        "log_max_bytes": "${LOG_BYTES:0}"
    }))

    monkeypatch.setattr("core_engine.config_loader.DEFAULT_SETTINGS_FILE", settings_path)
    monkeypatch.setenv("TOKEN", "test-123")

    settings = load_settings()
    assert settings["orchestrator_token"] == "test-123"
    assert settings["log_max_bytes"] == "0"


def test_secret_env_substitution_reads_named_environment(tmp_path, monkeypatch):
    settings_path = tmp_path / "data" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(json.dumps({"orchestrator_token": "${secret:PORTMAP_SECRET_TOKEN}"}))

    monkeypatch.setattr("core_engine.config_loader.DEFAULT_SETTINGS_FILE", settings_path)
    monkeypatch.setenv("PORTMAP_SECRET_TOKEN", "from-secret-env")

    settings = load_settings()

    assert settings["orchestrator_token"] == "from-secret-env"


def test_load_node_config_uses_env_orchestrator_defaults_when_settings_missing(tmp_path, monkeypatch):
    config_path = tmp_path / "worker.json"
    config_path.write_text(json.dumps({"node_id": "worker-x"}))

    missing_settings = tmp_path / "data" / "missing-settings.json"
    monkeypatch.setattr("core_engine.config_loader.DEFAULT_SETTINGS_FILE", missing_settings)
    monkeypatch.setenv("PORTMAP_ORCHESTRATOR_URL", "http://127.0.0.1:9555")
    monkeypatch.setenv("PORTMAP_ORCHESTRATOR_TOKEN", "env-token")

    _, settings = load_node_config(str(config_path))

    assert settings["orchestrator_url"] == "http://127.0.0.1:9555"
    assert settings["orchestrator_token"] == "env-token"


def test_save_settings_persists_expected_services(tmp_path, monkeypatch):
    settings_path = tmp_path / "data" / "settings.json"
    monkeypatch.setattr("core_engine.config_loader.DEFAULT_SETTINGS_FILE", settings_path)

    save_settings({"expected_services": [{"port": 3306, "program": "mysqld"}]})

    settings = load_settings()
    assert settings["expected_services"] == [{"port": 3306, "program": "mysqld"}]
