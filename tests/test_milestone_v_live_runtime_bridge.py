import json

from core_engine.dispatcher import dispatch_alert
from core_engine.runtime.milestone_v_bridge import build_milestone_v_runtime_bridge
from gui import app as gui_app
from gui import visualization


GENERATED_AT = "2026-06-03T12:00:00+00:00"


def _live_row(*, local_port, remote_port, protocol="TCP", program="", service_name="", status="ESTABLISHED"):
    return {
        "program": program,
        "pid": 0,
        "port": local_port,
        "service_name": service_name,
        "protocol": protocol,
        "status": status,
        "local": f"192.0.2.10:{local_port}",
        "remote": f"198.51.100.20:{remote_port}",
        "source_mode": "live",
        "data_source": "local_socket_inventory",
        "attribution_status": "unattributed" if not program else "matched",
    }


def test_live_like_socket_observations_create_milestone_v_runtime_summaries():
    report = build_milestone_v_runtime_bridge(
        [
            _live_row(local_port=51515, remote_port=22, protocol="TCP"),
            _live_row(local_port=51516, remote_port=443, protocol="TCP"),
            _live_row(local_port=51517, remote_port=53, protocol="UDP"),
        ],
        node_id="worker-fixture",
        generated_at=GENERATED_AT,
    )

    counters = report["runtime_counters"]
    assert counters["observations_seen"] == 3
    assert counters["sessions_reconstructed"] == 3
    assert counters["flows_reconstructed"] == 3
    assert counters["metadata_correlations"] == 3
    assert counters["process_correlations"] == 3
    assert counters["relationship_edges"] >= 1
    assert counters["attribution_candidates"] >= 3
    assert counters["drift_records"] == 3
    assert counters["topology_records"] >= 1
    assert report["operator_summary"]["source_modes"] == ["live"]
    assert {event["dst_port"] for event in report["flow_events"]} == {22, 53, 443}
    assert all(event["source_mode"] == "live" for event in report["flow_events"])
    assert all(event["raw_payload_stored"] is False for event in report["flow_events"])
    assert all(event["pcap_generated"] is False for event in report["flow_events"])


def test_repeated_identical_live_observations_do_not_duplicate_flows_or_edges():
    row = _live_row(local_port=51515, remote_port=22, protocol="TCP")
    report = build_milestone_v_runtime_bridge(
        [row, dict(row), dict(row)],
        node_id="worker-fixture",
        generated_at=GENERATED_AT,
    )

    assert report["runtime_counters"]["observations_seen"] == 1
    assert len(report["flow_events"]) == 1
    assert len(report["topology_edges"]) == 1


def test_live_dummy_labels_remain_unknown_unattributed_in_bridge_outputs():
    report = build_milestone_v_runtime_bridge(
        [
            _live_row(
                local_port=51515,
                remote_port=22,
                protocol="TCP",
                program="dummy_app",
                service_name="dummy_db",
            )
        ],
        node_id="worker-fixture",
        generated_at=GENERATED_AT,
    )

    flow_pair = report["api_status"]["flows"]["flow_pairs"][0]
    process_row = report["api_status"]["process_correlations"]["process_correlations"][0]
    assert flow_pair["process_attribution"] in {"Unknown", "Unattributed"}
    assert flow_pair["service_attribution"] == "Unattributed"
    assert process_row["process_attribution"] == "Unknown"
    assert process_row["service_attribution"] == "Unattributed"


def test_fixture_dummy_labels_are_preserved_for_explicit_fixture_mode():
    row = _live_row(local_port=8080, remote_port=443, protocol="TCP", program="dummy_app", service_name="dummy_db")
    row["source_mode"] = "fixture"
    row["data_source"] = "fixture"

    report = build_milestone_v_runtime_bridge([row], node_id="worker-fixture", generated_at=GENERATED_AT)

    flow_pair = report["api_status"]["flows"]["flow_pairs"][0]
    assert flow_pair["process_attribution"] == "dummy_app"
    assert flow_pair["service_attribution"] == "dummy_db"


def test_dispatcher_writes_milestone_v_summaries_for_tui_flow_views(monkeypatch, tmp_path):
    master_log = tmp_path / "master_events.log"
    monkeypatch.setattr("core_engine.dispatcher.MASTER_LOG", master_log)

    dispatch_alert(
        {
            "node_id": "worker-fixture",
            "score": 0.2,
            "ports": [_live_row(local_port=51515, remote_port=22, protocol="TCP")],
        },
        settings=None,
    )

    event = json.loads(master_log.read_text().splitlines()[0])
    assert event["milestone_v_counters"]["sessions_reconstructed"] == 1
    assert event["milestone_v_counters"]["flows_reconstructed"] == 1
    assert event["milestone_v_counters"]["relationship_edges"] == 1
    assert event["milestone_v"]["metadata_only"] is True
    assert event["flows"][0]["source_mode"] == "live"

    flow_events = gui_app._flow_events_from_master_events([event])
    report = visualization.build_flow_visualization(flow_events)
    assert report["flows"]
    assert report["topology"]["edges"]
    assert report["raw_payload_stored"] is False


def test_socket_only_bridge_documents_expected_icmp_limitations():
    report = build_milestone_v_runtime_bridge([], node_id="worker-fixture", generated_at=GENERATED_AT)

    limitations = report["operator_summary"]["socket_only_limitations"]
    assert any("ICMP ping may not appear" in item for item in limitations)
