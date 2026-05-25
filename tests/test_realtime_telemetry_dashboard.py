import re

from core_engine.runtime import build_runtime_health_summary
from core_engine.telemetry import (
    build_live_telemetry_operator_summary,
    build_live_topology,
    build_packet_ingestion_window,
    deterministic_live_telemetry_json,
    enumerate_local_interfaces,
    extract_protocol_metadata_report,
    reconstruct_flows_from_packet_window,
)
from gui.web import (
    build_empty_live_telemetry_dashboard_view,
    build_live_telemetry_dashboard_view,
    live_telemetry_api_response,
    render_live_telemetry_sections,
)


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile("/" + "home/"),
    re.compile("/" + "Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
]


GENERATED_AT = "2026-01-01T00:00:00+00:00"


def _interface_inventory():
    return enumerate_local_interfaces(
        interfaces={
            "en0": [
                {
                    "family": "AF_INET",
                    "address": "203.0.113.5",
                    "netmask": "255.255.255.0",
                    "broadcast": "203.0.113.255",
                }
            ],
            "lo0": [{"family": "AF_INET", "address": "127.0.0.1"}],
        },
        generated_at=GENERATED_AT,
    )


def _packet_window():
    packets = [
        {
            "timestamp": "2026-01-01T00:00:01+00:00",
            "interface_name": "en0",
            "source_ip": "203.0.113.10",
            "destination_ip": "198.51.100.20",
            "source_port": 53000,
            "destination_port": 80,
            "transport": "tcp",
            "size_bytes": 120,
            "packet_sequence": 1,
        },
        {
            "timestamp": "2026-01-01T00:00:02+00:00",
            "interface_name": "en0",
            "source_ip": "198.51.100.20",
            "destination_ip": "203.0.113.10",
            "source_port": 80,
            "destination_port": 53000,
            "transport": "tcp",
            "size_bytes": 160,
            "packet_sequence": 2,
        },
        {
            "timestamp": "2026-01-01T00:00:03+00:00",
            "interface_name": "en0",
            "source_ip": "203.0.113.10",
            "destination_ip": "198.51.100.30",
            "source_port": 53001,
            "destination_port": 443,
            "transport": "tcp",
            "size_bytes": 200,
            "packet_sequence": 3,
        },
        {
            "timestamp": "2026-01-01T00:00:04+00:00",
            "interface_name": "en0",
            "source_ip": "198.51.100.30",
            "destination_ip": "203.0.113.10",
            "source_port": 443,
            "destination_port": 53001,
            "transport": "tcp",
            "size_bytes": 220,
            "packet_sequence": 4,
        },
    ]
    return build_packet_ingestion_window(packets=packets, duration_seconds=4, generated_at=GENERATED_AT)


def _telemetry_inputs():
    packet_window = _packet_window()
    flows = reconstruct_flows_from_packet_window(packet_window, generated_at=GENERATED_AT)["flows"]
    http_flow = next(flow for flow in flows if flow["service_association"]["service_name"] == "http")
    tls_flow = next(flow for flow in flows if flow["service_association"]["service_name"] == "https")
    protocol_report = extract_protocol_metadata_report(
        flows=flows,
        metadata_by_flow_id={
            http_flow["flow_id"]: {"http": {"method": "GET", "host": "example.test", "path": "/status"}},
            tls_flow["flow_id"]: {"tls": {"tls_version": "TLS 1.3", "sni": "example.test", "alpn": "h2"}},
        },
        generated_at=GENERATED_AT,
    )
    live_topology = build_live_topology(
        flows=flows,
        protocol_records=protocol_report["records"],
        cluster_node_id="node-alpha",
        federation_scope="trusted-local",
        generated_at=GENERATED_AT,
    )
    runtime_health = build_runtime_health_summary(
        dashboard_provider={"status": "ok", "ready": True},
        scheduler={"scheduler_status": "running", "failed_job_count": 0, "executed_job_count": 2},
        generated_at=GENERATED_AT,
    )
    federation_diagnostics = {
        "record_type": "federation_diagnostics",
        "status": "ok",
        "generated_at": GENERATED_AT,
        "summary": {
            "trusted_peer_count": 2,
            "readiness_score": 90,
            "rejected_update_count": 0,
            "duplicate_event_count": 0,
        },
        "local_only": True,
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }
    return {
        "interface_inventory": _interface_inventory(),
        "packet_window": packet_window,
        "flows": flows,
        "protocol_report": protocol_report,
        "live_topology": live_topology,
        "runtime_health": runtime_health,
        "federation_diagnostics": federation_diagnostics,
        "resource_usage": {"cpu_percent": 12.5, "memory_mb": 128, "storage_mb": 64, "status": "ok"},
        "generated_at": GENERATED_AT,
        "last_updated_at": GENERATED_AT,
    }


def test_live_telemetry_operator_summary_builds_dashboard_api_panels():
    model = build_live_telemetry_operator_summary(**_telemetry_inputs())

    assert model["record_type"] == "live_telemetry_operator_summary"
    assert model["status"] == "ok"
    assert set(model["panels"]) == {
        "interfaces",
        "packet_rate",
        "flow_rate",
        "live_topology",
        "protocol_distribution",
        "resource_usage",
        "federation_rollup",
    }
    assert model["panels"]["interfaces"]["metrics"]["interface_count"] == 2
    assert model["panels"]["packet_rate"]["metrics"]["metadata_record_count"] == 4
    assert model["panels"]["packet_rate"]["metrics"]["packets_per_second"] == 1.0
    assert model["panels"]["flow_rate"]["metrics"]["flow_count"] == 2
    assert model["panels"]["live_topology"]["metrics"]["node_count"] == 3
    assert model["panels"]["protocol_distribution"]["by_protocol"] == {"http": 1, "tls": 1}
    assert model["panels"]["resource_usage"]["metrics"]["memory_mb"] == 128
    assert model["panels"]["federation_rollup"]["metrics"]["federation_aware"] is True
    assert model["api_status"]["record_type"] == "live_telemetry_api"
    assert model["raw_payload_rendered"] is False
    assert model["packet_replay_enabled"] is False
    assert model["automatic_blocking"] is False
    assert model["tui_replaced"] is False


def test_live_telemetry_web_view_sections_and_api_response_are_compatible():
    view = build_live_telemetry_dashboard_view(**_telemetry_inputs())
    api = live_telemetry_api_response(view)
    rendered = render_live_telemetry_sections(view)

    assert view["sections"][0]["title"] == "Interfaces"
    assert len(view["sections"]) == 8
    assert api["record_type"] == "live_telemetry_dashboard_api_response"
    assert api["summary"]["flow_count"] == 2
    assert "Packet Rate" in rendered
    assert view["parallel_dashboard_schema_created"] is False


def test_update_interval_controls_are_bounded_without_starting_loop():
    model = build_live_telemetry_operator_summary(
        **_telemetry_inputs(),
        requested_update_interval_seconds=120,
    )

    controls = model["update_controls"]
    assert controls["requested_update_interval_seconds"] == 120
    assert controls["effective_update_interval_seconds"] == 60
    assert controls["bounded"] is False
    assert controls["update_loop_started"] is False
    assert model["health_summary"]["status"] == "review_required"


def test_empty_and_stale_state_rendering_models_are_explicit():
    empty = build_empty_live_telemetry_dashboard_view(generated_at=GENERATED_AT)
    inputs = _telemetry_inputs()
    inputs["generated_at"] = "2026-01-01T00:10:00+00:00"
    inputs["last_updated_at"] = "2026-01-01T00:00:00+00:00"
    stale = build_live_telemetry_dashboard_view(
        **inputs,
        stale_after_seconds=300,
    )

    assert empty["summary"]["empty_state"] is True
    assert empty["empty_state"]["status"] == "empty"
    assert stale["stale_state"]["stale"] is True
    assert stale["stale_state"]["status"] == "stale"
    assert stale["health_summary"]["status"] == "review_required"


def test_live_telemetry_serialization_is_deterministic_and_private_safe():
    model = build_live_telemetry_operator_summary(**_telemetry_inputs())
    payload = deterministic_live_telemetry_json(model)

    assert payload == deterministic_live_telemetry_json(model)
    assert "payload_bytes" not in payload
    assert "raw_payload_rendered\":false" in payload
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
