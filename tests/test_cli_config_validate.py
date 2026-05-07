import json

from cli import main as cli_main


def test_cli_config_validate_success(tmp_path, capsys):
    config = tmp_path / "worker.json"
    config.write_text(json.dumps({
        "node_role": "worker",
        "node_id": "worker-1",
        "master_ip": "127.0.0.1",
        "port": 9000,
    }))

    result = cli_main.main(["config", "validate", str(config)])

    assert result == 0
    assert "OK" in capsys.readouterr().out


def test_cli_config_validate_failure_json(tmp_path, capsys):
    config = tmp_path / "bad.json"
    config.write_text(json.dumps({"node_role": "worker", "port": 99999}))

    result = cli_main.main(["config", "validate", str(config), "--output", "json"])

    assert result == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["ok"] is False
    assert any("port must be between" in error for error in payload[0]["errors"])


def test_cli_config_validate_role_mismatch(tmp_path, capsys):
    config = tmp_path / "worker.json"
    config.write_text(json.dumps({
        "node_role": "worker",
        "node_id": "worker-1",
        "master_ip": "127.0.0.1",
        "port": 9000,
    }))

    result = cli_main.main(["config", "validate", str(config), "--role", "master"])

    assert result == 1
    assert "expected node_role master, got worker" in capsys.readouterr().out
