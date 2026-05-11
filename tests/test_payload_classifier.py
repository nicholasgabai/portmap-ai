from ai_agent.payload_classifier import (
    classify_payload_events,
    classify_payload_observation,
    detect_beaconing,
    detect_exfiltration,
)


def test_classify_payload_observation_flags_cleartext_credentials_without_raw_storage():
    result = classify_payload_observation(
        {
            "protocol": "HTTP",
            "metadata": {"src_ip": "203.0.113.5", "dst_ip": "203.0.113.10", "dst_port": 80},
            "payload_text": "POST /login HTTP/1.1\r\nHost: local\r\n\r\npassword=secret",
        }
    )

    finding_types = {finding["type"] for finding in result["findings"]}
    assert result["label"] == "sensitive_cleartext"
    assert "credential_marker" in finding_types
    assert "cleartext_sensitive_payload" in finding_types
    assert result["risk_score"] == 0.85
    assert result["raw_payload_stored"] is False
    assert "secret" not in str(result)


def test_classify_payload_observation_redacts_optional_preview():
    result = classify_payload_observation(
        {"protocol": "HTTP", "payload_text": "GET /?token=secret HTTP/1.1\r\nHost: local\r\n\r\n"},
        include_payload_preview=True,
    )

    assert result["payload"]["preview_included"] is True
    assert "secret" not in result["payload"]["preview"]
    assert "<redacted>" in result["payload"]["preview"]


def test_classify_payload_observation_flags_injection_and_command_markers():
    result = classify_payload_observation({
        "protocol": "HTTP",
        "payload_text": "q=1 union select password from users; curl http://example.local/x",
    })

    finding_types = {finding["type"] for finding in result["findings"]}
    assert "sql_injection_marker" in finding_types
    assert "command_marker" in finding_types
    assert result["label"] == "suspicious_payload"


def test_classify_payload_observation_accepts_existing_payload_metadata():
    result = classify_payload_observation({
        "protocol": "DNS",
        "metadata": {"dst_ip": "8.8.8.8"},
        "payload": {"length": 8192, "entropy": 7.6, "category": "high_entropy"},
    })

    finding_types = {finding["type"] for finding in result["findings"]}
    assert "high_entropy_payload" in finding_types
    assert "possible_tunneled_payload" in finding_types
    assert "possible_exfiltration_payload" in finding_types
    assert result["payload"]["length"] == 8192


def test_protocol_misuse_detects_http_inside_tls_label():
    result = classify_payload_observation({
        "protocol": "TLS",
        "payload_text": "GET / HTTP/1.1\r\nHost: local\r\n\r\n",
    })

    assert any(finding["type"] == "protocol_misuse" for finding in result["findings"])


def test_detect_beaconing_identifies_regular_small_payloads():
    events = [
        {"timestamp": 10, "session_key": "flow-1", "payload": {"length": 100}},
        {"timestamp": 20, "session_key": "flow-1", "payload": {"length": 120}},
        {"timestamp": 30, "session_key": "flow-1", "payload": {"length": 110}},
        {"timestamp": 40, "session_key": "flow-1", "payload": {"length": 90}},
    ]

    findings = detect_beaconing(events)

    assert findings[0]["type"] == "beaconing_candidate"


def test_detect_exfiltration_aggregates_public_destination_volume():
    classifications = [
        {"network": {"dst_ip": "8.8.8.8"}, "payload": {"length": 700000}},
        {"network": {"dst_ip": "8.8.8.8"}, "payload": {"length": 400000}},
        {"network": {"dst_ip": "203.0.113.10"}, "payload": {"length": 9000000}},
    ]

    findings = detect_exfiltration(classifications)

    assert findings == [
        {
            "type": "possible_exfiltration_volume",
            "severity": "high",
            "evidence": "payload_volume",
            "detail": "1100000 payload bytes observed toward public destination 8.8.8.8",
        }
    ]


def test_classify_payload_events_combines_classifications_and_aggregate_findings():
    result = classify_payload_events([
        {"timestamp": 10, "session_key": "flow-1", "metadata": {"dst_ip": "8.8.8.8"}, "payload": {"length": 100}},
        {"timestamp": 20, "session_key": "flow-1", "metadata": {"dst_ip": "8.8.8.8"}, "payload": {"length": 100}},
        {"timestamp": 30, "session_key": "flow-1", "metadata": {"dst_ip": "8.8.8.8"}, "payload": {"length": 100}},
        {"timestamp": 40, "session_key": "flow-1", "metadata": {"dst_ip": "8.8.8.8"}, "payload": {"length": 100}},
    ])

    assert result["classification_count"] == 4
    assert any(finding["type"] == "beaconing_candidate" for finding in result["aggregate_findings"])
    assert result["raw_payload_stored"] is False
