import json

from core_engine import dispatcher


class DummyLogger:
    def __init__(self):
        self.messages = []

    def info(self, msg, *args, **kwargs):
        self.messages.append(("info", msg % args if args else msg))

    def warning(self, msg, *args, **kwargs):
        self.messages.append(("warning", msg % args if args else msg))

    def error(self, msg, *args, **kwargs):
        self.messages.append(("error", msg % args if args else msg))

    def debug(self, msg, *args, **kwargs):
        self.messages.append(("debug", msg % args if args else msg))


def test_dispatch_alert_returns_remediation(tmp_path, monkeypatch):
    log_path = tmp_path / "master.log"
    monkeypatch.setattr(dispatcher, "MASTER_LOG", log_path)
    remediation_log = tmp_path / "remediation.jsonl"
    monkeypatch.setattr(dispatcher, "REMEDIATION_LOG", remediation_log)

    payload = {"node_id": "worker-1", "score": 0.9, "ports": []}
    logger = DummyLogger()
    decision = dispatcher.dispatch_alert(
        payload,
        logger=logger,
        settings={"remediation_mode": "silent", "remediation_threshold": 0.75},
    )

    assert decision is not None
    assert decision.action == "auto_remediate"

    contents = log_path.read_text().strip().splitlines()
    assert contents, "master log should contain at least one entry"
    logged_entry = json.loads(contents[-1])
    assert logged_entry["node_id"] == "worker-1"
    assert logged_entry["score"] == 0.9

    remediation_lines = remediation_log.read_text().strip().splitlines()
    assert remediation_lines
    remediation_event = json.loads(remediation_lines[-1])
    assert remediation_event["node_id"] == "worker-1"
    assert remediation_event["action"] == "auto_remediate"
