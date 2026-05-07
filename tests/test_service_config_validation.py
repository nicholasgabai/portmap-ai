import json

import pytest

from core_engine import master_node, orchestrator, worker_node


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setattr("core_engine.config_loader.DEFAULT_SETTINGS_FILE", tmp_path / "missing-settings.json")


def test_orchestrator_startup_rejects_role_mismatch(tmp_path, capsys):
    config = tmp_path / "bad-orchestrator.json"
    config.write_text(json.dumps({
        "node_role": "master",
        "bind_ip": "127.0.0.1",
        "port": 9100,
        "auth_token": "token",
    }))

    with pytest.raises(SystemExit) as excinfo:
        orchestrator.run_orchestrator(str(config), orchestrator.parse_level("INFO"))

    assert excinfo.value.code == 1
    assert "expected node_role orchestrator, got master" in capsys.readouterr().out


def test_master_startup_rejects_invalid_port(tmp_path, capsys):
    config = tmp_path / "bad-master.json"
    config.write_text(json.dumps({
        "node_role": "master",
        "master_ip": "127.0.0.1",
        "port": 99999,
    }))

    with pytest.raises(SystemExit) as excinfo:
        master_node.run_master_node(str(config), master_node.parse_level("INFO"))

    assert excinfo.value.code == 1
    assert "port must be between 1 and 65535" in capsys.readouterr().out


def test_worker_startup_rejects_invalid_config(tmp_path, capsys):
    config = tmp_path / "bad-worker.json"
    config.write_text(json.dumps({
        "node_role": "worker",
        "node_id": "worker-1",
        "master_ip": "127.0.0.1",
        "port": 99999,
    }))

    with pytest.raises(SystemExit) as excinfo:
        worker_node.main(["--config", str(config)])

    assert excinfo.value.code == 1
    assert "port must be between 1 and 65535" in capsys.readouterr().out
