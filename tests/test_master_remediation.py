from core_engine.master_node import build_remediation_command


class DummyDecision:
    def __init__(self, action, reason, score, mode):
        self.action = action
        self.reason = reason
        self.score = score
        self.mode = mode


def test_build_remediation_command_auto_remediate():
    payload = {
        "node_id": "worker-1",
        "ports": [
            {"program": "svc", "port": 22, "score": 0.4},
            {"program": "app", "port": 8443, "score": 0.9},
        ],
    }
    decision = DummyDecision("auto_remediate", "threshold_exceeded", 0.9, "silent")
    command = build_remediation_command(payload, decision)
    assert command["decision"] == "block"
    assert command["connection"]["port"] == 8443
    assert command["dry_run"] is True
    assert command["metadata"]["enforcement"] == "dry_run"


def test_build_remediation_command_keeps_active_firewall_in_dry_run_without_confirmation():
    payload = {
        "node_id": "worker-1",
        "ports": [{"program": "app", "port": 8443, "score": 0.9}],
    }
    decision = DummyDecision("auto_remediate", "threshold_exceeded", 0.9, "silent")
    command = build_remediation_command(
        payload,
        decision,
        settings={"firewall": {"plugin": "linux_iptables", "options": {"dry_run": False}}},
    )
    assert command["dry_run"] is True
    assert command["metadata"]["enforcement"] == "dry_run"
    assert command["metadata"]["safety_reason"] == "active_enforcement_disabled"


def test_build_remediation_command_monitor_returns_none():
    payload = {"ports": []}
    decision = DummyDecision("monitor", "low_score", 0.2, "prompt")
    assert build_remediation_command(payload, decision) is None
