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
    audit_dir = tmp_path / "logs"
    audit_dir.mkdir()
    monkeypatch.setattr("core_engine.config_loader.LOG_DIR", audit_dir)

    payload = {
        "node_id": "worker-1",
        "score": 0.9,
        "ports": [
            {
                "port": 3306,
                "program": "postgres",
                "score": 0.9,
                "score_factors": ["sensitive_port:3306", "listening_socket"],
            }
        ],
    }
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
    assert logged_entry["event_type"] == "worker_telemetry"
    assert logged_entry["node_id"] == "worker-1"
    assert logged_entry["score"] == 0.9
    assert logged_entry["risk_score"] == 0.9
    assert logged_entry["score_factors"] == ["sensitive_port:3306", "listening_socket"]

    remediation_lines = remediation_log.read_text().strip().splitlines()
    assert remediation_lines
    remediation_event = json.loads(remediation_lines[-1])
    assert remediation_event["event_type"] == "remediation_decision"
    assert remediation_event["node_id"] == "worker-1"
    assert remediation_event["action"] == "auto_remediate"
    assert remediation_event["risk_score"] == 0.9
    assert remediation_event["program"] == "postgres"
    assert remediation_event["port"] == 3306
    assert remediation_event["score_factors"] == ["sensitive_port:3306", "listening_socket"]
    assert remediation_event["dry_run"] is True
    assert remediation_event["enforcement"] == "dry_run"

    audit_events = [
        json.loads(line)
        for line in (audit_dir / "audit_events.jsonl").read_text().splitlines()
    ]
    assert audit_events[-1]["event_type"] == "remediation_decision"
    assert audit_events[-1]["node_id"] == "worker-1"
