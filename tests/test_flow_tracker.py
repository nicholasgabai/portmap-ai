from core_engine.modules.flow_tracker import (
    build_flow_report,
    event_to_flow_event,
    flow_key,
    reconstruct_flows,
    topology_from_flows,
)


def test_event_to_flow_event_accepts_capture_metadata():
    event = {
        "timestamp": 1.5,
        "protocol": "TCP",
        "src_ip": "203.0.113.5",
        "dst_ip": "203.0.113.10",
        "src_port": 51515,
        "dst_port": 443,
        "payload_bytes": 128,
        "captured_len": 182,
        "dissection": {"protocol": "TLS", "evidence": ["port_443"]},
    }

    flow_event = event_to_flow_event(event)

    assert flow_event.src_ip == "203.0.113.5"
    assert flow_event.dst_port == 443
    assert flow_event.transport == "TCP"
    assert flow_event.application_protocol == "TLS"
    assert flow_event.payload_bytes == 128
    assert flow_event.captured_bytes == 182
    assert flow_event.evidence == ["port_443"]


def test_event_to_flow_event_accepts_dpi_result_shape():
    event = {
        "protocol": "HTTP",
        "headers": {
            "network": {
                "src_ip": "203.0.113.5",
                "dst_ip": "203.0.113.10",
                "src_port": 51515,
                "dst_port": 80,
                "transport": "TCP",
            }
        },
        "payload": {"length": 42},
        "findings": [{"type": "cleartext_login_flow"}],
    }

    flow_event = event_to_flow_event(event)

    assert flow_event.application_protocol == "HTTP"
    assert flow_event.payload_bytes == 42
    assert flow_event.findings == ["cleartext_login_flow"]


def test_flow_key_is_bidirectional():
    left = {
        "protocol": "TCP",
        "src_ip": "203.0.113.5",
        "src_port": 51515,
        "dst_ip": "203.0.113.10",
        "dst_port": 443,
    }
    right = {
        "protocol": "TCP",
        "src_ip": "203.0.113.10",
        "src_port": 443,
        "dst_ip": "203.0.113.5",
        "dst_port": 51515,
    }

    assert flow_key(left) == flow_key(right)


def test_reconstruct_flows_tracks_directional_counters_and_protocols():
    events = [
        {
            "timestamp": 1,
            "protocol": "TCP",
            "src_ip": "203.0.113.5",
            "src_port": 51515,
            "dst_ip": "203.0.113.10",
            "dst_port": 443,
            "payload_bytes": 100,
            "dissection": {"protocol": "TLS"},
        },
        {
            "timestamp": 2,
            "protocol": "TCP",
            "src_ip": "203.0.113.10",
            "src_port": 443,
            "dst_ip": "203.0.113.5",
            "dst_port": 51515,
            "payload_bytes": 200,
            "dpi": {"protocol": "TLS", "findings": [{"type": "truncated_tls_record"}]},
        },
    ]

    flows = reconstruct_flows(events)

    assert len(flows) == 1
    flow = flows[0]
    assert flow["packet_count"] == 2
    assert flow["payload_bytes"] == 300
    assert flow["directions"]["initiator_to_responder"] == {"packets": 1, "payload_bytes": 100}
    assert flow["directions"]["responder_to_initiator"] == {"packets": 1, "payload_bytes": 200}
    assert flow["application_protocols"] == ["TLS"]
    assert flow["findings"] == ["truncated_tls_record"]
    assert flow["duration_seconds"] == 1
    assert flow["flow_id"]


def test_reconstruct_flows_splits_idle_windows():
    events = [
        {"timestamp": 1, "protocol": "TCP", "src_ip": "203.0.113.1", "src_port": 1111, "dst_ip": "203.0.113.2", "dst_port": 80},
        {"timestamp": 10, "protocol": "TCP", "src_ip": "203.0.113.1", "src_port": 1111, "dst_ip": "203.0.113.2", "dst_port": 80},
    ]

    flows = reconstruct_flows(events, window_seconds=5)

    assert len(flows) == 2
    assert all(flow["packet_count"] == 1 for flow in flows)


def test_build_flow_report_includes_topology_and_omits_raw_payloads():
    report = build_flow_report([
        {
            "timestamp": 1,
            "protocol": "UDP",
            "src_ip": "203.0.113.20",
            "src_port": 5353,
            "dst_ip": "224.0.0.251",
            "dst_port": 5353,
            "payload_bytes": 50,
            "dissection": {"protocol": "DNS"},
        }
    ])

    assert report["ok"] is True
    assert report["raw_payload_stored"] is False
    assert report["flow_count"] == 1
    assert report["topology"]["nodes"][0]["ip"] == "203.0.113.20"
    assert report["topology"]["edges"][0]["application_protocols"] == ["DNS"]


def test_topology_from_flows_aggregates_shared_edges():
    flows = [
        {
            "initiator": {"ip": "203.0.113.1", "port": 1111},
            "responder": {"ip": "203.0.113.2", "port": 80},
            "packet_count": 2,
            "payload_bytes": 30,
            "transports": ["TCP"],
            "application_protocols": ["HTTP"],
        },
        {
            "initiator": {"ip": "203.0.113.1", "port": 2222},
            "responder": {"ip": "203.0.113.2", "port": 443},
            "packet_count": 3,
            "payload_bytes": 70,
            "transports": ["TCP"],
            "application_protocols": ["TLS"],
        },
    ]

    topology = topology_from_flows(flows)

    assert topology["nodes"][0]["packet_count"] == 5
    assert topology["edges"][0]["flow_count"] == 2
    assert topology["edges"][0]["payload_bytes"] == 100
    assert topology["edges"][0]["application_protocols"] == ["HTTP", "TLS"]
