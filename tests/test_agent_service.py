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
    log_dir, _ = temp_logs

    monkeypatch.setattr("socket.gethostbyname", lambda host: "127.0.0.1")

    agent = BackgroundAgent(str(config_path), log_level=logging.INFO)
    triggered = {}

    def fake_firewall(connection, decision, reason="", dry_run=False):
        triggered["decision"] = decision
        triggered["port"] = connection.get("port")
        triggered["reason"] = reason
        triggered["dry_run"] = dry_run

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
            "dry_run": True,
        },
    ])

    assert agent.interval == 15
    assert agent.autolearn is True
    assert extra_scan is True
    assert triggered["decision"] == "block"
    assert triggered["port"] == 443
    assert triggered["reason"] == "unit-test"
    assert triggered["dry_run"] is True

    audit_records = [
        json.loads(line)
        for line in (log_dir / "command_events.jsonl").read_text().splitlines()
    ]
    statuses = [(record["command_type"], record["status"]) for record in audit_records]
    assert ("set_interval", "applied") in statuses
    assert ("set_autolearn", "applied") in statuses
    assert ("scan_now", "applied") in statuses
    assert ("apply_remediation", "applied") in statuses

    for handler in list(agent.logger.handlers):
        handler.close()
        agent.logger.removeHandler(handler)


def test_apply_remediation_forces_dry_run_without_safety_confirmation(tmp_path, temp_logs, monkeypatch):
    config_path = make_config(tmp_path)
    agent = BackgroundAgent(str(config_path), log_level=logging.INFO)
    agent.settings["firewall"] = {"options": {"dry_run": False}}
    triggered = {}

    def fake_firewall(connection, decision, reason="", dry_run=False):
        triggered["decision"] = decision
        triggered["dry_run"] = dry_run

    monkeypatch.setattr("core_engine.agent_service.execute_firewall_action", fake_firewall)

    agent._process_commands([
        {
            "type": "apply_remediation",
            "decision": "block",
            "connection": {"program": "dummy", "port": 443},
            "reason": "unit-test",
            "dry_run": False,
        },
    ])

    assert triggered == {"decision": "block", "dry_run": True}

    for handler in list(agent.logger.handlers):
        handler.close()
        agent.logger.removeHandler(handler)


def test_apply_remediation_allows_confirmed_active_policy(tmp_path, temp_logs, monkeypatch):
    config_path = make_config(tmp_path)
    agent = BackgroundAgent(str(config_path), log_level=logging.INFO)
    agent.settings["firewall"] = {"options": {"dry_run": False}}
    agent.settings["remediation_safety"] = {
        "active_enforcement_enabled": True,
        "confirmation_token": "confirm-123",
    }
    triggered = {}

    def fake_firewall(connection, decision, reason="", dry_run=False):
        triggered["decision"] = decision
        triggered["dry_run"] = dry_run

    monkeypatch.setattr("core_engine.agent_service.execute_firewall_action", fake_firewall)

    agent._process_commands([
        {
            "type": "apply_remediation",
            "decision": "block",
            "connection": {"program": "dummy", "port": 443},
            "reason": "unit-test",
            "dry_run": False,
            "confirmed": True,
            "confirmation_token": "confirm-123",
        },
    ])

    assert triggered == {"decision": "block", "dry_run": False}

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


def test_heartbeat_reregisters_after_orchestrator_state_loss(tmp_path, temp_logs, monkeypatch):
    config_path = make_config(tmp_path)
    agent = BackgroundAgent(str(config_path), log_level=logging.INFO)
    calls = []

    def fake_call(endpoint, payload):
        calls.append(endpoint)
        if endpoint == "/heartbeat":
            raise RuntimeError("HTTP 404 Not Found: unknown node")
        return {"node": {"node_id": agent.node_id}}

    monkeypatch.setattr(agent, "_call_orchestrator", fake_call)

    response = agent._send_heartbeat()

    assert response == {}
    assert calls == ["/heartbeat", "/register"]

    for handler in list(agent.logger.handlers):
        handler.close()
        agent.logger.removeHandler(handler)
