import json

from core_engine import audit_events


def test_record_audit_event_writes_common_jsonl(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    monkeypatch.setattr("core_engine.config_loader.LOG_DIR", log_dir)

    event = audit_events.record_audit_event(
        "remediation_decision",
        node_id="worker-1",
        action="monitor",
        status="decided",
        risk_score=0.2,
        source="test",
        details={"port": 443},
    )

    path = log_dir / audit_events.AUDIT_EVENTS_FILENAME
    stored = json.loads(path.read_text().strip())
    assert stored["event_type"] == "remediation_decision"
    assert stored["node_id"] == "worker-1"
    assert stored["risk_score"] == 0.2
    assert stored["details"] == {"port": 443}
    assert event["timestamp"].endswith("Z")


def test_filter_audit_events_by_node_and_type(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    path = log_dir / audit_events.AUDIT_EVENTS_FILENAME
    path.write_text(
        "\n".join([
            json.dumps({"timestamp": "2026-01-01T00:00:00Z", "event_type": "command_event", "node_id": "w1"}),
            json.dumps({"timestamp": "2026-01-01T00:00:01Z", "event_type": "remediation_decision", "node_id": "w1"}),
            json.dumps({"timestamp": "2026-01-01T00:00:02Z", "event_type": "remediation_decision", "node_id": "w2"}),
        ])
        + "\n"
    )

    events = audit_events.filter_audit_events(
        log_dir=log_dir,
        filenames=[audit_events.AUDIT_EVENTS_FILENAME],
        node_id="w1",
        event_type="remediation_decision",
    )

    assert len(events) == 1
    assert events[0]["node_id"] == "w1"
    assert events[0]["event_type"] == "remediation_decision"
