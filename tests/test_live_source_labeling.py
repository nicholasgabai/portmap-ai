import json
from types import SimpleNamespace

from core_engine import platform_utils
from core_engine.modules import scanner
from core_engine.telemetry import (
    build_live_telemetry_operator_summary,
    build_packet_ingestion_window,
    build_process_service_attribution_report,
    deterministic_live_telemetry_json,
    deterministic_service_attribution_json,
    enrich_flow_records,
    reconstruct_flows_from_packet_window,
)
from gui import app as gui_app


GENERATED_AT = "2026-01-01T00:00:00+00:00"


def _live_like_unresolved_flows():
    window = build_packet_ingestion_window(
        packets=[
            {
                "timestamp": "2026-01-01T00:00:01+00:00",
                "interface_name": "en0",
                "source_node_id": "node-pi-placeholder",
                "source_ip": "203.0.113.10",
                "destination_ip": "198.51.100.20",
                "source_port": 53000,
                "destination_port": 22,
                "transport": "tcp",
                "size_bytes": 128,
                "packet_sequence": 1,
            },
            {
                "timestamp": "2026-01-01T00:00:02+00:00",
                "interface_name": "en0",
                "source_node_id": "node-pi-placeholder",
                "source_ip": "198.51.100.20",
                "destination_ip": "203.0.113.10",
                "source_port": 22,
                "destination_port": 53000,
                "transport": "tcp",
                "size_bytes": 160,
                "packet_sequence": 2,
            },
        ],
        duration_seconds=2,
        generated_at=GENERATED_AT,
    )
    flows = reconstruct_flows_from_packet_window(window, generated_at=GENERATED_AT)["flows"]
    return enrich_flow_records(flows, local_cidrs=["203.0.113.0/24"], generated_at=GENERATED_AT)["observations"]


def test_default_live_scan_does_not_emit_dummy_rows_on_collection_failure(monkeypatch):
    fake_psutil = SimpleNamespace(net_connections=lambda kind="inet": (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)

    assert scanner.basic_scan() == []


def test_fixture_scan_can_still_emit_dummy_rows(monkeypatch):
    fake_psutil = SimpleNamespace(net_connections=lambda kind="inet": (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)

    rows = scanner.basic_scan(source_mode="fixture")

    assert {row["program"] for row in rows} == {"dummy_app", "dummy_db"}
    assert {row["source_mode"] for row in rows} == {"fixture"}


def test_live_like_unresolved_attribution_displays_unattributed():
    report = build_process_service_attribution_report(
        enriched_flows=_live_like_unresolved_flows(),
        socket_records=[],
        process_records=[],
        source_mode="live",
        generated_at=GENERATED_AT,
    )
    attribution = report["attributions"][0]

    assert attribution["source_mode"] == "live"
    assert attribution["process_attribution"]["status"] == "unmatched"
    assert attribution["operator_display"]["process_display_name"] == "Unattributed"
    assert "dummy_app" not in deterministic_service_attribution_json(report)
    assert "dummy_db" not in deterministic_service_attribution_json(report)


def test_export_serialization_preserves_source_mode():
    report = build_process_service_attribution_report(
        enriched_flows=_live_like_unresolved_flows(),
        source_mode="replay",
        generated_at=GENERATED_AT,
    )
    telemetry = build_live_telemetry_operator_summary(
        flows=[],
        process_service_attribution_report=report,
        source_mode="replay",
        generated_at=GENERATED_AT,
    )
    payload = json.loads(deterministic_live_telemetry_json(telemetry))

    assert payload["source_mode"] == "replay"
    assert payload["api_status"]["source_mode"] == "replay"
    assert payload["panels"]["process_service_attribution"]["source_mode"] == "replay"
    assert payload["summary"]["source_modes"] == ["replay", "unknown"]


def test_tui_rows_do_not_mislabel_live_dummy_values():
    rows = gui_app._scan_rows_from_telemetry(
        [
            {
                "timestamp": GENERATED_AT,
                "event_type": "worker_telemetry",
                "node_id": "worker-placeholder",
                "source_mode": "live",
                "ports_sample": [
                    {
                        "program": "dummy_app",
                        "port": 8080,
                        "protocol": "TCP",
                        "status": "LISTEN",
                    }
                ],
            }
        ]
    )

    assert rows[0]["program"] == "Unattributed"
    assert rows[0]["source_mode"] == "live"


def test_tui_rows_preserve_fixture_dummy_values():
    rows = gui_app._scan_rows_from_telemetry(
        [
            {
                "timestamp": GENERATED_AT,
                "event_type": "worker_telemetry",
                "node_id": "worker-placeholder",
                "source_mode": "fixture",
                "ports_sample": [
                    {
                        "program": "dummy_db",
                        "port": 3306,
                        "protocol": "TCP",
                        "status": "LISTEN",
                    }
                ],
            }
        ]
    )

    assert rows[0]["program"] == "dummy_db"
    assert rows[0]["source_mode"] == "fixture"
