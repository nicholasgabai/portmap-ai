from ai_agent.recommendation_engine import generate_recommendations, recommend_incident


def _incident(**overrides):
    base = {
        "incident_id": "inc-1",
        "type": "chained_behavior_payload_risk",
        "severity": "high",
        "score": 0.9,
        "entity": "worker-1",
        "event_count": 3,
        "peers": ["203.0.113.10"],
        "ports": [443],
        "findings": ["new_peer", "credential_marker"],
        "explanation": "payload and behavior anomalies appeared in the same correlation window",
        "supporting_evidence": [
            {"event_id": "evt-1", "kind": "behavior", "score": 0.55, "severity": "medium", "summary": "new_peer"},
            {"event_id": "evt-2", "kind": "payload", "score": 0.85, "severity": "high", "summary": "credential_marker"},
        ],
    }
    base.update(overrides)
    return base


def test_recommend_incident_generates_advisory_and_dry_run_actions():
    recommendations = recommend_incident(_incident())

    actions = {item["action"] for item in recommendations}
    assert {"investigate", "collect_host_evidence", "rotate_exposed_credentials", "block_peer", "isolate_device"} <= actions
    block = next(item for item in recommendations if item["action"] == "block_peer")
    assert block["approval_required"] is True
    assert block["dry_run"] is True
    assert block["remediation_command"]["dry_run"] is True
    assert block["remediation_command"]["confirmed"] is False
    assert block["remediation_command"]["metadata"]["requires_operator_approval"] is True


def test_suspicious_scan_recommends_scan_source_review():
    recommendations = recommend_incident(_incident(type="suspicious_scan_behavior", score=0.65, findings=["new_destination_port"], peers=[]))

    assert any(item["action"] == "review_scan_source" for item in recommendations)
    assert not any(item["action"] == "block_peer" for item in recommendations)


def test_lateral_movement_recommends_segmentation_review():
    recommendations = recommend_incident(_incident(type="lateral_movement_indicator", score=0.75, findings=["new_peer"], peers=["203.0.113.10", "203.0.113.11"]))

    assert any(item["action"] == "review_segmentation" for item in recommendations)


def test_payload_exfiltration_recommends_egress_review():
    recommendations = recommend_incident(_incident(type="chained_behavior_payload_risk", score=0.7, findings=["possible_exfiltration_payload"], peers=[]))

    assert any(item["action"] == "review_egress_policy" for item in recommendations)


def test_generate_recommendations_accepts_multiple_incidents_and_dedupes():
    report = generate_recommendations([_incident(), _incident()])

    ids = [item["recommendation_id"] for item in report["recommendations"]]
    assert report["ok"] is True
    assert len(ids) == len(set(ids))
    assert report["automatic_changes"] is False
    assert report["raw_payload_stored"] is False


def test_generate_recommendations_rejects_negative_thresholds():
    try:
        generate_recommendations([], review_threshold=-1)
    except ValueError as exc:
        assert "thresholds" in str(exc)
    else:
        raise AssertionError("expected ValueError")
