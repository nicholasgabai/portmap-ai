from ai_agent.threat_correlation import correlate_events, normalize_event


def test_normalize_event_accepts_behavior_payload_and_flow_shapes():
    behavior = normalize_event({
        "model": "local_behavior_baseline",
        "device_id": "worker-1",
        "score": 0.55,
        "observation": {"peer": "10.0.0.10", "port": 443, "application": "TLS", "timestamp": 1},
        "findings": [{"type": "new_peer"}],
    })
    payload = normalize_event({
        "model": "local_payload_classifier",
        "timestamp": 2,
        "label": "sensitive_cleartext",
        "risk_score": 0.85,
        "network": {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.10", "dst_port": 80},
        "findings": [{"type": "credential_marker"}],
    })
    flow = normalize_event({
        "flow_id": "flow-1",
        "first_seen": 3,
        "initiator": {"ip": "10.0.0.5", "port": 51515},
        "responder": {"ip": "10.0.0.10", "port": 443},
        "findings": ["truncated_tls_record"],
    })

    assert behavior["kind"] == "behavior"
    assert behavior["entity"] == "worker-1"
    assert behavior["peer"] == "10.0.0.10"
    assert payload["kind"] == "payload"
    assert payload["entity"] == "10.0.0.5"
    assert payload["port"] == 80
    assert flow["kind"] == "flow"
    assert flow["event_id"] == "flow-1"


def test_correlate_events_links_repeated_anomalies():
    events = [
        {"timestamp": 1, "device_id": "worker-1", "score": 0.55, "findings": [{"type": "new_peer"}]},
        {"timestamp": 2, "device_id": "worker-1", "score": 0.6, "findings": [{"type": "new_destination_port"}]},
        {"timestamp": 3, "device_id": "worker-1", "score": 0.6, "findings": [{"type": "unusual_hour"}]},
    ]

    result = correlate_events(events)

    assert result["incident_count"] == 1
    assert result["incidents"][0]["type"] == "repeated_anomaly"
    assert result["incidents"][0]["entity"] == "worker-1"
    assert result["raw_payload_stored"] is False


def test_correlate_events_detects_suspicious_scan_behavior():
    events = [
        {"timestamp": index, "device_id": "scanner", "metadata": {"dst_ip": "10.0.0.10", "dst_port": 8000 + index}}
        for index in range(6)
    ]

    result = correlate_events(events, window_seconds=30)

    assert any(incident["type"] == "suspicious_scan_behavior" for incident in result["incidents"])


def test_correlate_events_detects_lateral_movement_indicator():
    events = [
        {
            "timestamp": 1,
            "model": "local_behavior_baseline",
            "device_id": "worker-1",
            "score": 0.55,
            "observation": {"peer": "10.0.0.10", "port": 445},
            "findings": [{"type": "new_peer"}],
        },
        {
            "timestamp": 2,
            "model": "local_behavior_baseline",
            "device_id": "worker-1",
            "score": 0.55,
            "observation": {"peer": "10.0.0.11", "port": 445},
            "findings": [{"type": "new_peer"}],
        },
    ]

    result = correlate_events(events)

    assert any(incident["type"] == "lateral_movement_indicator" for incident in result["incidents"])


def test_correlate_events_detects_payload_behavior_chain():
    events = [
        {
            "timestamp": 1,
            "model": "local_behavior_baseline",
            "device_id": "worker-1",
            "score": 0.55,
            "observation": {"peer": "10.0.0.10", "port": 443},
            "findings": [{"type": "new_peer"}],
        },
        {
            "timestamp": 2,
            "model": "local_payload_classifier",
            "risk_score": 0.85,
            "network": {"src_ip": "worker-1", "dst_ip": "10.0.0.10", "dst_port": 443},
            "findings": [{"type": "credential_marker"}],
        },
    ]

    result = correlate_events(events)

    assert any(incident["type"] == "chained_behavior_payload_risk" for incident in result["incidents"])


def test_correlate_events_splits_by_window():
    events = [
        {"timestamp": 1, "device_id": "worker-1", "score": 0.6, "findings": [{"type": "new_peer"}]},
        {"timestamp": 2, "device_id": "worker-1", "score": 0.6, "findings": [{"type": "new_peer"}]},
        {"timestamp": 100, "device_id": "worker-1", "score": 0.6, "findings": [{"type": "new_peer"}]},
    ]

    result = correlate_events(events, window_seconds=5)

    assert result["incident_count"] == 0


def test_correlate_events_rejects_invalid_window():
    try:
        correlate_events([], window_seconds=0)
    except ValueError as exc:
        assert "window_seconds" in str(exc)
    else:
        raise AssertionError("expected ValueError")
