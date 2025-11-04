import json
import logging
from pathlib import Path

import pytest

from core_engine.agent_service import BackgroundAgent


@pytest.fixture
def temp_logs(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    data_dir = tmp_path / "data"
    log_dir.mkdir()
    data_dir.mkdir()

    monkeypatch.setattr("core_engine.config_loader.LOG_DIR", log_dir)
    monkeypatch.setattr("core_engine.config_loader.DATA_DIR", data_dir)
    monkeypatch.setattr("core_engine.logging_utils.LOG_DIR", log_dir)
    return log_dir, data_dir


def make_config(tmp_path, **overrides):
    cfg = {
        "node_role": "worker",
        "node_id": "worker-test",
        "master_ip": "127.0.0.1",
        "port": 9000,
        "scan_interval": 5,
        "orchestrator_url": "http://orchestrator",
        "orchestrator_token": "token",
    }
    cfg.update(overrides)
    path = tmp_path / "worker.json"
    path.write_text(json.dumps(cfg))
    return path


def test_process_commands_updates_interval(tmp_path, temp_logs, monkeypatch):
    config_path = make_config(tmp_path)

    monkeypatch.setattr("socket.gethostbyname", lambda host: "127.0.0.1")

    agent = BackgroundAgent(str(config_path), log_level=logging.INFO)
    triggered = {}

    def fake_firewall(connection, decision):
        triggered["decision"] = decision
        triggered["port"] = connection.get("port")

    monkeypatch.setattr("core_engine.agent_service.execute_firewall_action", fake_firewall)

    monkeypatch.setattr(agent, "_call_orchestrator", lambda endpoint, payload: {"commands": []})

    extra_scan = agent._process_commands([
        {"type": "set_interval", "value": 15},
        {"type": "set_autolearn", "value": True},
        {"type": "scan_now"},
        {
            "type": "apply_remediation",
            "decision": "block",
            "connection": {"program": "dummy", "port": 443},
            "reason": "unit-test",
        },
    ])

    assert agent.interval == 15
    assert agent.autolearn is True
    assert extra_scan is True
    assert triggered["decision"] == "block"
    assert triggered["port"] == 443

    for handler in list(agent.logger.handlers):
        handler.close()
        agent.logger.removeHandler(handler)


def test_register_handles_errors(tmp_path, temp_logs, monkeypatch):
    config_path = make_config(tmp_path)

    monkeypatch.setattr("socket.gethostbyname", lambda host: "127.0.0.1")
    agent = BackgroundAgent(str(config_path), log_level=logging.INFO)

    calls = {}

    def fake_call(endpoint, payload):
        calls.setdefault(endpoint, []).append(payload)
        if endpoint == "/register":
            raise RuntimeError("boom")
        return {"commands": []}

    monkeypatch.setattr(agent, "_call_orchestrator", fake_call)
    agent._register_with_orchestrator()
    assert "/register" in calls

    response = agent._send_heartbeat()
    assert response.get("commands") == []

    for handler in list(agent.logger.handlers):
        handler.close()
        agent.logger.removeHandler(handler)
