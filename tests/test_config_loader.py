import json
from pathlib import Path

from core_engine.config_loader import DATA_DIR, load_node_config, load_settings


def test_load_settings_creates_defaults(tmp_path, monkeypatch):
    settings_path = tmp_path / "data" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(json.dumps({"remediation_mode": "silent"}))

    monkeypatch.setattr("core_engine.config_loader.DEFAULT_SETTINGS_FILE", settings_path)
    settings = load_settings()
    assert settings["remediation_mode"] == "silent"
    assert "remediation_threshold" not in settings


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
