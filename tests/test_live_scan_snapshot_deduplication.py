import json
import logging
import socket
from types import SimpleNamespace

from core_engine import dispatcher, platform_utils, worker_node
from core_engine.modules import scanner
from core_engine.telemetry import build_behavior_baseline_report
from gui import app as gui_app


GENERATED_AT = "2026-01-01T00:00:00+00:00"


def _conn(*, port=8080, remote_port=53000, pid=123, status="LISTEN", process="sample-service"):
    return SimpleNamespace(
        laddr=SimpleNamespace(ip="203.0.113.10", port=port),
        raddr=SimpleNamespace(ip="198.51.100.20", port=remote_port) if remote_port else (),
        pid=pid,
        status=status,
        type=socket.SOCK_STREAM,
    )


def test_repeated_scanner_calls_with_identical_live_fixture_do_not_grow(monkeypatch):
    fake_psutil = SimpleNamespace(
        net_connections=lambda kind="inet": [_conn(), _conn()],
        Process=lambda pid: SimpleNamespace(name=lambda: "sample-service"),
    )
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)

    first = scanner.basic_scan()
    second = scanner.basic_scan()
    third = scanner.basic_scan()

    assert len(first) == 1
    assert len(second) == 1
    assert len(third) == 1
    assert first[0]["scan_snapshot_key"] == second[0]["scan_snapshot_key"] == third[0]["scan_snapshot_key"]
    assert first[0]["source_mode"] == "live"


def test_stale_transient_observations_are_pruned_between_scan_cycles(monkeypatch):
    calls = {"count": 0}

    def fake_connections(kind="inet"):
        calls["count"] += 1
        if calls["count"] == 1:
            return [_conn(status="TIME_WAIT", pid=None), _conn(port=8443, remote_port=None, status="LISTEN")]
        return [_conn(port=8443, remote_port=None, status="LISTEN")]

    fake_psutil = SimpleNamespace(
        net_connections=fake_connections,
        Process=lambda pid: SimpleNamespace(name=lambda: "sample-service"),
    )
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)

    first = scanner.basic_scan()
    second = scanner.basic_scan()

    assert len(first) == 1
    assert len(second) == 1
    assert first[0]["status"] == "LISTEN"
    assert second[0]["status"] == "LISTEN"


def test_duplicate_socket_rows_collapse_into_one_observation():
    rows = [
        {"program": "sample-service", "port": 443, "local": "203.0.113.10:443", "remote": "-", "protocol": "TCP", "status": "LISTEN", "source_mode": "live"},
        {"program": "sample-service", "port": 443, "local": "203.0.113.11:443", "remote": "-", "protocol": "TCP", "status": "LISTEN", "source_mode": "live"},
        {"program": "sample-service", "port": 443, "local": "203.0.113.10:443", "remote": "-", "protocol": "TCP", "status": "LISTEN", "source_mode": "live"},
    ]

    snapshot = scanner.normalize_scan_snapshot(rows, node_id="worker-placeholder")

    assert len(snapshot) == 1
    assert snapshot[0]["current_snapshot"] is True


def test_worker_payload_is_current_bounded_snapshot_and_scoring_is_stable(monkeypatch):
    monkeypatch.setattr(worker_node, "get_score", lambda connection, use_ml=False: 0.42)
    duplicated = [
        {"program": "sample-service", "port": 443, "local": "203.0.113.10:443", "remote": "-", "protocol": "TCP", "status": "LISTEN", "source_mode": "live"},
        {"program": "sample-service", "port": 443, "local": "203.0.113.11:443", "remote": "-", "protocol": "TCP", "status": "LISTEN", "source_mode": "live"},
    ]

    first = worker_node.build_payload("worker-placeholder", duplicated, logging.getLogger("test.worker"), autolearn=False)
    second = worker_node.build_payload("worker-placeholder", duplicated + duplicated, logging.getLogger("test.worker"), autolearn=False)

    assert len(first["ports"]) == 1
    assert len(second["ports"]) == 1
    assert first["score"] == second["score"] == 0.42
    assert first["scan_snapshot"]["observation_count"] == 1
    assert second["scan_snapshot"]["observation_count"] == 1
    assert first["scan_snapshot"]["snapshot_id"] == second["scan_snapshot"]["snapshot_id"]


def test_dispatcher_logs_deduplicated_current_snapshot(tmp_path, monkeypatch):
    log_path = tmp_path / "master_events.log"
    monkeypatch.setattr(dispatcher, "MASTER_LOG", log_path)
    monkeypatch.setattr(dispatcher, "REMEDIATION_LOG", tmp_path / "remediation.jsonl")
    payload = {
        "node_id": "worker-placeholder",
        "score": 0.5,
        "ports": [
            {"program": "sample-service", "port": 443, "local": "203.0.113.10:443", "remote": "-", "protocol": "TCP", "status": "LISTEN", "source_mode": "live"},
            {"program": "sample-service", "port": 443, "local": "203.0.113.11:443", "remote": "-", "protocol": "TCP", "status": "LISTEN", "source_mode": "live"},
        ],
    }

    dispatcher.dispatch_alert(payload)
    entry = json.loads(log_path.read_text().splitlines()[-1])

    assert entry["current_snapshot"] is True
    assert entry["source_mode"] == "live"
    assert len(entry["ports_sample"]) == 1
    assert entry["scan_snapshot_id"].startswith("scan-snapshot-")


def test_tui_latest_scan_view_only_uses_current_snapshot_per_node():
    rows = gui_app._scan_rows_from_telemetry(
        [
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "event_type": "worker_telemetry",
                "node_id": "worker-placeholder",
                "ports_sample": [{"program": "old-service", "port": 8080, "protocol": "TCP", "status": "LISTEN", "source_mode": "live"}],
            },
            {
                "timestamp": "2026-01-01T00:01:00Z",
                "event_type": "worker_telemetry",
                "node_id": "worker-placeholder",
                "ports_sample": [{"program": "new-service", "port": 8443, "protocol": "TCP", "status": "LISTEN", "source_mode": "live"}],
            },
        ],
        limit=10,
    )

    assert len(rows) == 1
    assert rows[0]["program"] == "new-service"
    assert rows[0]["port"] == 8443


def test_historical_baselines_can_store_historical_summaries_separately():
    report = build_behavior_baseline_report(
        flow_observations=[
            {
                "flow_ref": "flow-a",
                "first_seen": "2026-01-01T00:00:00+00:00",
                "last_seen": "2026-01-01T00:01:00+00:00",
                "transport_protocol": "tcp",
                "service_port_hint": {"service_port": 443, "service_name": "https"},
                "flow_digest": "digest-a",
            },
            {
                "flow_ref": "flow-a",
                "first_seen": "2026-01-01T00:02:00+00:00",
                "last_seen": "2026-01-01T00:03:00+00:00",
                "transport_protocol": "tcp",
                "service_port_hint": {"service_port": 443, "service_name": "https"},
                "flow_digest": "digest-a",
            },
        ],
        generated_at=GENERATED_AT,
    )

    assert report["record_type"] == "behavior_baseline_report"
    assert report["input_observation_count"] > 1
    assert report["packet_capture_stored"] is False
    assert report["raw_payload_stored"] is False


def test_dummy_labels_remain_fixture_only_and_source_mode_is_preserved(monkeypatch):
    fake_psutil = SimpleNamespace(net_connections=lambda kind="inet": (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)

    assert scanner.basic_scan() == []
    fixture = scanner.basic_scan(source_mode="fixture")

    assert {row["program"] for row in fixture} == {"dummy_app", "dummy_db"}
    assert {row["source_mode"] for row in fixture} == {"fixture"}
