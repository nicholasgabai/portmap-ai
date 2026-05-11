from pathlib import Path

from ai_agent.baseline_store import empty_baseline, load_baseline, save_baseline
from ai_agent.behavior_model import (
    analyze_behavior,
    analyze_events,
    normalize_observation,
    summarize_device_profile,
    update_baseline,
)


def test_normalize_observation_accepts_flow_record():
    event = {
        "timestamp": 1,
        "initiator": {"ip": "203.0.113.5", "port": 51515},
        "responder": {"ip": "203.0.113.10", "port": 443},
        "transports": ["TCP"],
        "application_protocols": ["TLS"],
        "payload_bytes": 128,
    }

    observation = normalize_observation(event)

    assert observation["device_id"] == "203.0.113.5"
    assert observation["peer"] == "203.0.113.10"
    assert observation["port"] == 443
    assert observation["application"] == "TLS"
    assert observation["payload_bytes"] == 128


def test_update_baseline_builds_device_profile_counts():
    baseline = update_baseline(empty_baseline(), [
        {
            "timestamp": 1,
            "device_id": "worker-1",
            "metadata": {"protocol": "TCP", "dst_ip": "203.0.113.10", "dst_port": 443},
            "application_protocol": "TLS",
        },
        {
            "timestamp": 3601,
            "device_id": "worker-1",
            "metadata": {"protocol": "TCP", "dst_ip": "203.0.113.10", "dst_port": 443},
            "application_protocol": "TLS",
        },
    ])

    profile = baseline["devices"]["worker-1"]
    assert profile["event_count"] == 2
    assert profile["ports"] == {"443": 2}
    assert profile["peers"] == {"203.0.113.10": 2}
    assert profile["applications"] == {"TLS": 2}
    assert profile["hour_buckets"] == {"0": 1, "1": 1}


def test_analyze_behavior_flags_new_device():
    result = analyze_behavior(
        {"device_id": "new-host", "metadata": {"protocol": "TCP", "dst_ip": "203.0.113.10", "dst_port": 22}},
        empty_baseline(),
    )

    assert result["status"] == "anomalous"
    assert result["score"] == 0.55
    assert result["findings"][0]["type"] == "new_device"
    assert result["raw_payload_stored"] is False


def test_analyze_behavior_detects_new_port_peer_application_and_hour():
    baseline = update_baseline(empty_baseline(), [
        {
            "timestamp": 1,
            "device_id": "worker-1",
            "metadata": {"protocol": "TCP", "dst_ip": "203.0.113.10", "dst_port": 443},
            "application_protocol": "TLS",
        },
        {
            "timestamp": 2,
            "device_id": "worker-1",
            "metadata": {"protocol": "TCP", "dst_ip": "203.0.113.10", "dst_port": 443},
            "application_protocol": "TLS",
        },
        {
            "timestamp": 3,
            "device_id": "worker-1",
            "metadata": {"protocol": "TCP", "dst_ip": "203.0.113.10", "dst_port": 443},
            "application_protocol": "TLS",
        },
    ])

    result = analyze_behavior(
        {
            "timestamp": 3600 * 12,
            "device_id": "worker-1",
            "metadata": {"protocol": "TCP", "dst_ip": "203.0.113.99", "dst_port": 3389},
            "application_protocol": "RDP",
        },
        baseline,
    )

    finding_types = {finding["type"] for finding in result["findings"]}
    assert {"new_destination_port", "new_peer", "new_application_protocol", "unusual_hour"} <= finding_types
    assert result["status"] == "anomalous"


def test_analyze_events_optionally_learns():
    events = [
        {
            "timestamp": 1,
            "device_id": "worker-1",
            "metadata": {"protocol": "TCP", "dst_ip": "203.0.113.10", "dst_port": 443},
            "application_protocol": "TLS",
        }
    ]

    result = analyze_events(events, empty_baseline(), learn=True)

    assert result["baseline_updated"] is True
    assert result["baseline"]["devices"]["worker-1"]["event_count"] == 1
    assert result["analysis_count"] == 1


def test_summarize_device_profile_reports_top_counts():
    baseline = update_baseline(empty_baseline(), [
        {"device_id": "worker-1", "metadata": {"dst_ip": "203.0.113.10", "dst_port": 443}, "application_protocol": "TLS"},
        {"device_id": "worker-1", "metadata": {"dst_ip": "203.0.113.10", "dst_port": 443}, "application_protocol": "TLS"},
        {"device_id": "worker-1", "metadata": {"dst_ip": "203.0.113.11", "dst_port": 80}, "application_protocol": "HTTP"},
    ])

    summary = summarize_device_profile("worker-1", baseline)

    assert summary["top_ports"][0] == {"value": "443", "count": 2}
    assert summary["top_applications"][0] == {"value": "TLS", "count": 2}


def test_baseline_store_round_trips_json(tmp_path):
    path = tmp_path / "behavior.json"
    baseline = update_baseline(empty_baseline(), [{"device_id": "worker-1", "metadata": {"dst_ip": "203.0.113.10", "dst_port": 443}}])

    saved_path = save_baseline(baseline, path)
    loaded = load_baseline(saved_path)

    assert saved_path == Path(path)
    assert loaded["devices"]["worker-1"]["ports"] == {"443": 1}
