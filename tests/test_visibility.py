from core_engine.visibility import build_visibility_report, normalize_visibility_policy


def test_visibility_report_summarizes_assets_services_and_flows():
    payload = build_visibility_report(
        assets=[
            {"host": "203.0.113.10", "status": "reachable", "methods": ["arp"]},
            {"host": "203.0.113.11", "status": "unknown", "methods": []},
        ],
        services=[
            {"target": "203.0.113.10", "port": 22, "state": "open", "service": "SSH", "confidence": 0.92},
            {"target": "203.0.113.10", "port": 3306, "state": "open", "service": "MySQL", "confidence": 0.55},
            {"target": "203.0.113.11", "port": 9999, "state": "open", "service": "unknown", "reason": "probe_completed"},
        ],
        flows={
            "flows": [
                {
                    "flow_id": "flow-1",
                    "initiator": {"ip": "203.0.113.10", "port": 51515},
                    "responder": {"ip": "198.51.100.10", "port": 443},
                    "payload_bytes": 2048,
                    "application_protocols": ["HTTPS"],
                    "findings": ["cleartext_sensitive_payload"],
                }
            ]
        },
        policy={"high_payload_bytes": 1024},
    )

    assert payload["automatic_changes"] is False
    assert payload["administrator_controlled"] is True
    assert payload["raw_payload_stored"] is False
    assert payload["summary"]["asset_count"] == 2
    assert payload["summary"]["service_count"] == 3
    assert payload["summary"]["flow_count"] == 1
    assert payload["summary"]["response_workflow_count"] == 3
    assert payload["categories"]["assets"]["statuses"]["unknown"] == 1
    assert payload["categories"]["services"]["by_service"]["SSH"] == 1
    assert {finding["type"] for finding in payload["findings"]} >= {
        "asset_unknown",
        "management_service_open",
        "database_service_open",
        "unknown_open_service",
        "flow_security_findings",
        "high_payload_volume",
    }
    assert all(workflow["approval_required"] for workflow in payload["response_workflows"])
    assert all(workflow["dry_run"] for workflow in payload["response_workflows"])


def test_visibility_policy_normalizes_ports_and_rejects_invalid_values():
    policy = normalize_visibility_policy({"management_ports": ["22", 22, 3389], "database_ports": [3306]})

    assert policy["management_ports"] == [22, 3389]
    assert policy["database_ports"] == [3306]

    try:
        normalize_visibility_policy({"management_ports": [0]})
    except ValueError as exc:
        assert "between 1 and 65535" in str(exc)
    else:
        raise AssertionError("expected ValueError")
