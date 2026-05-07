import logging

import pytest

from core_engine.firewall_hooks import configure_firewall, execute_firewall_action, get_plugin


@pytest.fixture(autouse=True)
def reset_plugin():
    configure_firewall({"plugin": "noop"})
    yield


def test_noop_plugin_logs(caplog):
    caplog.set_level(logging.INFO)
    configure_firewall({"plugin": "noop"})
    execute_firewall_action({"program": "svc", "port": 80}, "block", reason="unit-test")
    assert "FIREWALL noop" in caplog.text


def test_linux_iptables_dry_run(caplog, monkeypatch):
    caplog.set_level(logging.INFO)
    monkeypatch.setattr("shutil.which", lambda name: "/sbin/iptables")
    configure_firewall({
        "plugin": "linux_iptables",
        "options": {"dry_run": True, "log_command": True}
    })
    plugin = get_plugin()
    assert plugin.name == "linux_iptables"
    execute_firewall_action({"program": "svc", "port": 443, "protocol": "tcp"}, "block", reason="policy")
    assert "iptables" in caplog.text
