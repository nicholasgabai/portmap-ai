import json

from core_engine import command_audit
from core_engine.worker_node import _process_commands


class DummyLogger:
    def __init__(self):
        self.messages = []

    def info(self, msg, *args, **kwargs):
        self.messages.append(("info", msg % args if args else msg))

    def warning(self, msg, *args, **kwargs):
        self.messages.append(("warning", msg % args if args else msg))


def test_record_command_event_writes_jsonl(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    monkeypatch.setattr("core_engine.config_loader.LOG_DIR", log_dir)

    event = command_audit.record_command_event(
        "worker-1",
        {"type": "scan_now"},
        "applied",
        result={"extra_scan": True},
    )

    path = log_dir / command_audit.COMMAND_AUDIT_FILENAME
    stored = json.loads(path.read_text().strip())
    assert stored["event_type"] == "command_event"
    assert stored["node_id"] == "worker-1"
    assert stored["action"] == "scan_now"
    assert stored["command_type"] == "scan_now"
    assert stored["status"] == "applied"
    assert stored["result"] == {"extra_scan": True}
    assert event["timestamp"].endswith("Z")

    audit_log = log_dir / command_audit.AUDIT_EVENTS_FILENAME
    audit_event = json.loads(audit_log.read_text().strip())
    assert audit_event["event_type"] == "command_event"
    assert audit_event["node_id"] == "worker-1"
    assert audit_event["action"] == "scan_now"


def test_worker_process_commands_records_outcomes(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    monkeypatch.setattr("core_engine.config_loader.LOG_DIR", log_dir)

    runtime = {"node_id": "worker-1", "interval": 5, "autolearn": False}
    extra_scan = _process_commands(
        DummyLogger(),
        runtime,
        [
            {"type": "scan_now"},
            {"type": "set_interval", "value": 15},
            {"type": "set_autolearn", "value": True},
            {"type": "reload_config"},
        ],
    )

    assert extra_scan is True
    assert runtime["interval"] == 15
    assert runtime["autolearn"] is True

    records = [
        json.loads(line)
        for line in (log_dir / command_audit.COMMAND_AUDIT_FILENAME).read_text().splitlines()
    ]
    statuses = [(record["command_type"], record["status"]) for record in records]
    assert ("scan_now", "received") in statuses
    assert ("scan_now", "applied") in statuses
    assert ("set_interval", "applied") in statuses
    assert ("set_autolearn", "applied") in statuses
    assert ("reload_config", "ignored") in statuses
