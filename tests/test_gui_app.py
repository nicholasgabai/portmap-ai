import json
from pathlib import Path

import pytest

pytest.importorskip("textual")

from gui import app as gui_app
from gui import visualization


def _timestamp(date, *parts):
    return f"{date}T{':'.join(parts)}Z"


def test_compute_metrics():
    metrics = gui_app._compute_metrics(
        [{"node_id": "n1", "status": "online", "last_seen": 10}],
        [{"action": "block"}],
    )
    assert metrics["online_nodes"] == 1
    assert metrics["counts"]["block"] == 1


def test_format_score_factors():
    text = gui_app._format_score_factors(
        {"score_factors": ["sensitive_port:3306", "public_remote_ip", "payload_present"]}
    )
    assert text == "sensitive_port:3306, public_remote_ip..."


def test_format_score_factors_explains_monitor_without_factors():
    text = gui_app._format_score_factors(
        {"action": "monitor", "reason": "score<0.75", "score_factors": []}
    )
    assert text == "below_threshold"


def test_format_command_result():
    assert gui_app._format_command_result({"result": {"extra_scan": True}}) == "extra_scan=True"
    assert gui_app._format_command_result({"error": "unknown command"}) == "unknown command"
    assert gui_app._format_command_result({}) == "-"


def test_format_risk_score():
    assert gui_app._format_risk_score(0.91234) == "0.912"
    assert gui_app._format_risk_score("-") == "-"
    assert gui_app._format_risk_score("high") == "high"


def test_scan_rows_from_telemetry_extracts_ports_sample():
    rows = gui_app._scan_rows_from_telemetry(
        [
            {
                "timestamp": _timestamp("2026-05-05", "12", "00", "00"),
                "event_type": "worker_telemetry",
                "node_id": "worker-1",
                "risk_score": 0.8,
                "score_factors": ["public_remote_ip"],
                "ports_sample": [
                    {
                        "program": "postgres",
                        "port": 5432,
                        "protocol": "TCP",
                        "status": "LISTEN",
                        "score": 0.91,
                        "score_factors": ["sensitive_port:5432"],
                        "ai_provider": "heuristic",
                    }
                ],
            }
        ]
    )

    assert rows == [
        {
            "timestamp": _timestamp("2026-05-05", "12", "00", "00"),
            "node_id": "worker-1",
            "program": "postgres",
            "port": 5432,
            "protocol": "TCP",
            "status": "LISTEN",
            "score": 0.91,
            "score_factors": ["sensitive_port:5432"],
            "risk_explanation": "",
            "ai_provider": "heuristic",
        }
    ]


def test_expected_service_helpers():
    event = {
        "port": 3306,
        "protocol": "MySQL",
        "program": "mysqld",
    }
    service = gui_app._service_from_event(event)
    assert service == {
        "port": 3306,
        "protocol": "MySQL",
        "program": "mysqld",
        "reason": "dashboard allowlist",
    }
    settings = {"expected_services": []}
    assert gui_app._merge_expected_service(settings, service) is True
    assert gui_app._merge_expected_service(settings, service) is False
    assert gui_app._remove_expected_service(settings, service) is True
    assert settings["expected_services"] == []


def test_operator_help_text_defines_key_terms(tmp_path):
    text = gui_app._operator_help_text(
        tmp_path / "exports",
        {"plugin": "noop", "enforcement": "dry_run"},
    )
    assert "Start here:" in text
    assert "monitor: observed but not risky enough to act" in text
    assert "Signals: short explanations" in text
    assert "Scan Results: latest sampled ports" in text
    assert "Expected Services: move normal services" in text
    assert "Command Outcomes: whether queued commands" in text
    assert "Risk Timeline: recent score buckets" in text
    assert "Topology Edges: passive flow relationships" in text
    assert "Traffic Flows: bidirectional session summaries" in text
    assert "Firewall plugin: noop" in text
    assert "Enforcement mode: dry_run" in text
    assert str(tmp_path / "exports") in text


def test_resolve_firewall_status_defaults_safe():
    status = gui_app._resolve_firewall_status({})
    assert status == {"plugin": "noop", "enforcement": "dry_run"}


def test_resolve_firewall_status_detects_active_mode():
    status = gui_app._resolve_firewall_status({
        "firewall": {"plugin": "linux_iptables", "options": {"dry_run": False}}
    })
    assert status == {"plugin": "linux_iptables", "enforcement": "active"}


def test_load_nodes_no_state(monkeypatch, tmp_path):
    monkeypatch.setattr(gui_app, "ORCHESTRATOR_STATE", tmp_path / "state.json")
    monkeypatch.setattr(gui_app, "load_settings", lambda defaults=None: {})
    dashboard = gui_app.PortMapDashboard()
    assert dashboard._load_nodes() == []


def test_load_command_events(monkeypatch, tmp_path):
    path = tmp_path / "command_events.jsonl"
    path.write_text(
        "\n".join([
            json.dumps({"node_id": "n1", "command_type": "scan_now", "status": "received"}),
            "not json",
            json.dumps({"node_id": "n1", "command_type": "scan_now", "status": "applied"}),
        ])
    )
    monkeypatch.setattr(gui_app, "COMMAND_AUDIT_LOG", path)
    dashboard = gui_app.PortMapDashboard()
    events = dashboard._load_command_events(limit=3)
    assert [event["status"] for event in events] == ["received", "applied"]


def test_load_scan_results_prefers_worker_telemetry(monkeypatch, tmp_path):
    master_events = tmp_path / "master_events.log"
    master_events.write_text(
        json.dumps(
            {
                "event_type": "worker_telemetry",
                "timestamp": _timestamp("2026-05-05", "12", "00", "00"),
                "node_id": "worker-1",
                "ports_sample": [{"program": "nginx", "port": 443, "score": 0.4}],
            }
        )
    )
    monkeypatch.setattr(gui_app, "MASTER_EVENTS_LOG", master_events)

    dashboard = gui_app.PortMapDashboard()
    rows = dashboard._load_scan_results(
        [{"node_id": "worker-2", "program": "postgres", "port": 5432, "risk_score": 0.9}],
        limit=5,
    )

    assert rows[0]["node_id"] == "worker-1"
    assert rows[0]["program"] == "nginx"


def test_load_scan_results_falls_back_to_remediation_events(monkeypatch, tmp_path):
    monkeypatch.setattr(gui_app, "MASTER_EVENTS_LOG", tmp_path / "missing.log")
    dashboard = gui_app.PortMapDashboard()

    rows = dashboard._load_scan_results(
        [
            {
                "timestamp": _timestamp("2026-05-05", "12", "00", "00"),
                "node_id": "worker-2",
                "program": "postgres",
                "port": 5432,
                "protocol": "TCP",
                "risk_score": 0.9,
                "score_factors": ["sensitive_port:5432"],
            }
        ],
        limit=5,
    )

    assert rows[0]["node_id"] == "worker-2"
    assert rows[0]["score"] == 0.9
    assert rows[0]["score_factors"] == ["sensitive_port:5432"]


def test_visualization_builds_risk_timeline():
    timeline = visualization.build_risk_timeline(
        [
            {"timestamp": 10, "risk_score": 0.2, "action": "monitor"},
            {"timestamp": 20, "risk_score": 0.82, "action": "prompt_operator"},
            {"timestamp": 310, "risk_score": 0.95, "action": "block"},
            {"timestamp": _timestamp("2026-05-10", "12", "00", "00"), "risk_score": 0.51, "action": "monitor"},
        ],
        bucket_seconds=300,
    )

    assert len(timeline) == 3
    assert timeline[0]["event_count"] == 2
    assert timeline[0]["buckets"]["high"] == 1
    assert timeline[1]["buckets"]["critical"] == 1
    assert timeline[2]["buckets"]["medium"] == 1
    assert "L/M/H/C=1/0/1/0" in visualization.render_risk_timeline(timeline)


def test_visualization_builds_topology_and_flow_rows():
    report = visualization.build_flow_visualization(
        [
            {
                "timestamp": 1,
                "protocol": "TCP",
                "src_ip": "203.0.113.5",
                "src_port": 51515,
                "dst_ip": "203.0.113.10",
                "dst_port": 443,
                "payload_bytes": 120,
                "application_protocol": "https",
            }
        ]
    )

    edges = visualization.topology_edge_rows(report["topology"])
    flows = visualization.flow_rows(report["flows"])
    summary = visualization.visualization_summary(
        nodes=[{"node_id": "worker-1"}],
        risk_timeline=[],
        flows=report["flows"],
        topology=report["topology"],
    )

    assert edges[0]["src_ip"] == "203.0.113.5"
    assert edges[0]["application_protocols"] == "HTTPS"
    assert "203.0.113.5:51515 -> 203.0.113.10:443" == flows[0]["flow"]
    assert summary["flow_count"] == 1
    assert summary["raw_payload_stored"] is False
    assert summary["automatic_changes"] is False


def test_load_flow_visualization_reads_flow_events(monkeypatch, tmp_path):
    flow_log = tmp_path / "flow_events.jsonl"
    flow_log.write_text(
        json.dumps(
            {
                "timestamp": 1,
                "protocol": "TCP",
                "src_ip": "203.0.113.5",
                "src_port": 51515,
                "dst_ip": "203.0.113.10",
                "dst_port": 443,
                "payload_bytes": 120,
            }
        )
    )
    monkeypatch.setattr(gui_app, "FLOW_EVENTS_LOG", flow_log)
    monkeypatch.setattr(gui_app, "MASTER_EVENTS_LOG", tmp_path / "missing.log")

    dashboard = gui_app.PortMapDashboard()
    report = dashboard._load_flow_visualization(limit=5)

    assert report["flows"][0]["payload_bytes"] == 120
    assert report["topology"]["edges"][0]["packet_count"] == 1


def test_flow_events_from_master_events_extracts_nested_rows():
    rows = gui_app._flow_events_from_master_events(
        [
            {"event_type": "worker_telemetry", "flows": [{"src_ip": "203.0.113.1", "dst_ip": "203.0.113.2"}]},
            {"event_type": "traffic_flow", "src_ip": "203.0.113.3", "dst_ip": "203.0.113.4"},
        ]
    )

    assert [row["src_ip"] for row in rows] == ["203.0.113.1", "203.0.113.3"]


def test_load_orchestrator_health_reads_health_and_metrics(monkeypatch):
    dashboard = gui_app.PortMapDashboard()
    dashboard.orchestrator_url = "http://orchestrator"
    dashboard.orchestrator_token = "token"

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(self.payload).encode("utf-8")

    def fake_urlopen(req, timeout):
        assert req.headers["Authorization"] == "Bearer token"
        if req.full_url.endswith("/healthz"):
            return FakeResponse({"status": "ok"})
        if req.full_url.endswith("/metrics"):
            return FakeResponse({"registers": 1, "heartbeats": 2, "commands_queued": 3})
        raise AssertionError(req.full_url)

    monkeypatch.setattr(gui_app.request, "urlopen", fake_urlopen)

    health = dashboard._load_orchestrator_health()

    assert health == {
        "url": "http://orchestrator",
        "status": "ok",
        "metrics": {"registers": 1, "heartbeats": 2, "commands_queued": 3},
    }


def test_queue_command_posts_to_orchestrator(monkeypatch, tmp_path):
    monkeypatch.setattr(gui_app, "ORCHESTRATOR_STATE", tmp_path / "state.json")
    monkeypatch.setattr(gui_app, "REMEDIATION_LOG", tmp_path / "remediation.jsonl")

    monkeypatch.setattr(gui_app, "load_settings", lambda defaults=None: {})
    dashboard = gui_app.PortMapDashboard()
    dashboard.orchestrator_url = "http://orchestrator"
    dashboard.orchestrator_token = "token"

    calls = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout):
        calls["url"] = req.full_url
        calls["data"] = json.loads(req.data.decode("utf-8"))
        assert req.headers["Authorization"] == "Bearer token"
        return FakeResponse()

    monkeypatch.setattr(gui_app.request, "urlopen", fake_urlopen)

    dashboard._queue_command("node-1", {"type": "scan_now"})

    assert calls["url"].endswith("/commands")
    assert calls["data"]["node_id"] == "node-1"
