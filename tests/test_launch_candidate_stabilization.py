import json
from pathlib import Path

from core_engine.attribution.probabilistic_apps import build_probabilistic_application_model
from core_engine.launch_candidate import (
    LaunchCandidateStabilizer,
    build_launch_candidate_summary,
    deterministic_launch_candidate_json,
    safe_load_json,
    summarize_startup_paths,
    validate_launch_config,
)
from core_engine.protocols import classify_packets, summarize_conversations
from core_engine.timeline import build_packet_timeline
from core_engine.visualization import build_network_snapshot, build_protocol_distribution, build_timeline_model


def _packet(**overrides):
    data = {
        "packet_id": "packet-a",
        "session_id": "session-a",
        "observed_at": "2026-06-14T12:00:00+00:00",
        "interface": "mock0",
        "direction": "outbound",
        "length": 64,
        "captured_length": 64,
        "link_type": "ethernet",
        "eth_src": "aa:bb:cc:dd:ee:ff",
        "eth_dst": "11:22:33:44:55:66",
        "ether_type": "0x0800",
        "ip_version": 4,
        "src_ip": "192.168.1.10",
        "dst_ip": "203.0.113.10",
        "ttl": 64,
        "protocol": "TCP",
        "src_port": 51515,
        "dst_port": 443,
        "tcp_flags": ["SYN"],
        "payload_length": 0,
        "tags": ["fixture"],
        "metadata": {"safe": "yes"},
    }
    data.update(overrides)
    return data


def _packets():
    return [
        _packet(packet_id="packet-b", observed_at="2026-06-14T12:00:03+00:00", dst_port=443, length=70),
        _packet(packet_id="packet-a", observed_at="2026-06-14T12:00:00+00:00", dst_port=443, length=60),
        _packet(
            packet_id="packet-c",
            session_id="session-b",
            observed_at="2026-06-14T12:00:01+00:00",
            protocol="UDP",
            dst_ip="198.51.100.53",
            src_port=53000,
            dst_port=53,
            length=80,
        ),
    ]


def _derived():
    packets = _packets()
    records = classify_packets(packets)
    conversations = summarize_conversations(packets)
    timeline = build_packet_timeline(packets, protocol_records=records, conversations=conversations)
    visualizations = [
        build_timeline_model(timeline),
        build_protocol_distribution(records, conversations=conversations),
        build_network_snapshot(events=timeline, protocol_records=records, conversations=conversations),
    ]
    return packets, records, conversations, timeline, visualizations


def _behavior_inputs():
    observation = {
        "asset": "local-node",
        "service": "https",
        "port": 443,
        "protocol": "tcp",
        "flow_key": "tcp|192.168.1.10|51515|203.0.113.10|443",
        "risk_score": 0.31,
    }
    classification = build_probabilistic_application_model(
        {
            "service_name": "nginx",
            "process_name": "nginx",
            "program": "nginx",
            "port": 443,
            "protocol": "tcp",
            "state": "LISTEN",
        },
        generated_at="2026-07-01T00:00:00Z",
    )
    profile = {
        "profile_id": "profile-nginx",
        "profile_name": "nginx",
        "observation_count": 4,
        "stability_score": 0.8,
        "stability_label": "stable",
    }
    return observation, classification, profile


def test_startup_empty_state_and_missing_paths(tmp_path):
    missing = tmp_path / "missing"
    summary = build_launch_candidate_summary(startup_paths=[missing], generated_at="2026-07-01T00:00:00Z")

    assert summary["status"] == "review"
    assert summary["startup_summary"]["missing_count"] == 1
    assert "startup_paths_missing" in summary["diagnostics"]
    assert "empty_packet_state" in summary["diagnostics"]
    assert summary["packet_intelligence_summary"]["packet_count"] == 0


def test_configuration_defaults_and_safe_fallbacks():
    summary = validate_launch_config(
        {
            "refresh_interval_seconds": 0,
            "max_rows": -10,
            "packet_intelligence_enabled": True,
            "unknown_option": "ignored",
        }
    )

    assert summary["effective_config"]["refresh_interval_seconds"] == 1
    assert summary["effective_config"]["max_rows"] == 1
    assert summary["effective_config"]["packet_intelligence_enabled"] is True
    assert summary["diagnostics"] == ["ignored_unknown_config:unknown_option"]


def test_safe_json_loading_handles_missing_and_invalid_files(tmp_path):
    missing = safe_load_json(tmp_path / "missing.json")
    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("{invalid", encoding="utf-8")
    invalid = safe_load_json(invalid_path)

    assert missing["status"] == "missing"
    assert invalid["status"] == "invalid"
    assert invalid["data"] == {}


def test_packet_pipeline_integration_and_json_serialization():
    packets, records, conversations, timeline, visualizations = _derived()
    summary = build_launch_candidate_summary(
        packets=packets,
        protocol_records=records,
        conversations=conversations,
        timeline_events=timeline,
        visualization_models=visualizations,
        generated_at="2026-07-01T00:00:00Z",
    )

    assert summary["packet_intelligence_summary"]["packet_count"] == 3
    assert summary["packet_intelligence_summary"]["protocol_count"] == 3
    assert summary["packet_intelligence_summary"]["timeline_event_count"] == len(timeline)
    assert summary["packet_intelligence_summary"]["visualization_summary"]["visualization_model_count"] == 3
    json.dumps(summary, sort_keys=True)
    assert deterministic_launch_candidate_json(summary) == deterministic_launch_candidate_json(summary)


def test_packet_summary_cache_behavior():
    packets, records, conversations, timeline, visualizations = _derived()
    stabilizer = LaunchCandidateStabilizer()

    first = stabilizer.build_summary(
        packets=packets,
        protocol_records=records,
        conversations=conversations,
        timeline_events=timeline,
        visualization_models=visualizations,
        generated_at="2026-07-01T00:00:00Z",
    )
    second = stabilizer.build_summary(
        packets=list(reversed(packets)),
        protocol_records=list(reversed(records)),
        conversations=list(reversed(conversations)),
        timeline_events=list(reversed(timeline)),
        visualization_models=list(reversed(visualizations)),
        generated_at="2026-07-01T00:00:00Z",
    )

    assert first == second
    assert stabilizer.cache_misses == 1
    assert stabilizer.cache_hits == 1
    assert second["cache"]["packet_summary_entries"] == 1


def test_behavior_graph_ai_and_risk_summary_stability():
    observation, classification, profile = _behavior_inputs()
    summary = build_launch_candidate_summary(
        behavior_observation=observation,
        classification_model=classification,
        learning_profile=profile,
        risk_cards=[{"card_id": "risk-a", "title": "Observed HTTPS", "risk_score": 0.42}],
        ai_summaries=[{"summary_id": "ai-a", "confidence": 0.82}],
        generated_at="2026-07-01T00:00:00Z",
    )

    assert summary["behavior_graph_summary"]["node_count"] > 0
    assert summary["risk_summary"]["highest_risk_score"] == 0.42
    assert summary["ai_summary"]["average_confidence"] == 0.82
    assert "empty_behavior_graph_state" not in summary["diagnostics"]
    assert "empty_risk_state" not in summary["diagnostics"]
    assert "empty_ai_summary_state" not in summary["diagnostics"]


def test_risk_summary_deterministic_ordering():
    cards = [
        {"card_id": "risk-b", "title": "B", "risk_score": 0.8},
        {"card_id": "risk-a", "title": "A", "risk_score": 0.8},
    ]
    first = build_launch_candidate_summary(risk_cards=cards)
    second = build_launch_candidate_summary(risk_cards=list(reversed(cards)))

    assert first["risk_summary"] == second["risk_summary"]
    assert first["risk_summary"]["risk_ids"] == ["risk-a", "risk-b"]


def test_multiple_repeated_executions_are_deterministic():
    packets, records, conversations, timeline, visualizations = _derived()
    kwargs = {
        "packets": packets,
        "protocol_records": records,
        "conversations": conversations,
        "timeline_events": timeline,
        "visualization_models": visualizations,
        "generated_at": "2026-07-01T00:00:00Z",
    }
    outputs = [build_launch_candidate_summary(**kwargs) for _ in range(3)]

    assert outputs[0] == outputs[1] == outputs[2]


def test_no_mutation_and_payload_redaction():
    packets = [_packet(packet_id="payload-safe", payload="hidden", raw_bytes=b"hidden", metadata={"payload_body": "secret", "safe": "yes"})]
    original = json.loads(json.dumps(packets, default=str))

    summary = build_launch_candidate_summary(packets=packets, generated_at="2026-07-01T00:00:00Z")
    rendered = json.dumps(summary, sort_keys=True)

    assert json.loads(json.dumps(packets, default=str)) == original
    assert "secret" not in rendered
    assert "hidden" not in rendered
    assert "payload_body" not in rendered


def test_startup_path_summary_is_deterministic(tmp_path):
    available = tmp_path / "available"
    available.mkdir()
    missing = tmp_path / "missing"

    first = summarize_startup_paths([missing, available])
    second = summarize_startup_paths([available, missing])

    assert first == second
    assert [row["status"] for row in first["paths"]] == ["available", "missing"]
