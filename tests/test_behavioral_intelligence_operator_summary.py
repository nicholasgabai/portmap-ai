import re

from core_engine.telemetry import (
    build_behavioral_intelligence_operator_view,
    build_behavioral_intelligence_summary,
    build_live_telemetry_operator_summary,
    deterministic_behavior_operator_view_json,
    deterministic_behavioral_intelligence_json,
)


GENERATED_AT = "2026-01-01T00:50:00+00:00"

PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile("/" + "home/"),
    re.compile("/" + "Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
]


def _baseline_report():
    return {
        "record_type": "behavior_baseline_report",
        "summary": {
            "baseline_entry_count": 4,
            "stable_behavior_count": 3,
            "novel_behavior_count": 1,
            "decaying_inactive_count": 0,
            "average_confidence": 0.82,
            "by_behavior_state": {"stable": 3, "newly_observed": 1},
        },
        "dashboard_status": {
            "metrics": {
                "baseline_entry_count": 4,
                "stable_behavior_count": 3,
                "novel_behavior_count": 1,
                "average_confidence": 0.82,
            }
        },
        "export_summary": {"digest": "sha256:baseline"},
    }


def _anomaly_report():
    return {
        "record_type": "temporal_anomaly_report",
        "summary": {
            "anomaly_count": 2,
            "burst_count": 1,
            "rare_service_timing_count": 1,
            "volume_drift_count": 0,
            "novel_behavior_count": 1,
            "average_confidence": 0.71,
            "by_label": {"burst_detected": 1, "rare_service_timing": 1},
        },
        "dashboard_status": {
            "metrics": {
                "anomaly_count": 2,
                "burst_count": 1,
                "rare_service_timing_count": 1,
                "average_confidence": 0.71,
            }
        },
    }


def _service_report():
    return {
        "record_type": "service_behavior_fingerprint_report",
        "summary": {"fingerprint_count": 3},
        "profile_summary": {
            "profile_count": 3,
            "stable_profile_count": 2,
            "unusual_combination_count": 1,
            "dormant_reappeared_count": 0,
            "average_confidence": 0.76,
            "by_behavior_state": {"baseline_consistent": 2, "unusual_process_port_pair": 1},
        },
        "dashboard_status": {
            "metrics": {
                "profile_count": 3,
                "stable_profile_count": 2,
                "unusual_combination_count": 1,
                "average_confidence": 0.76,
            }
        },
    }


def _destination_report():
    return {
        "record_type": "dns_destination_behavior_report",
        "summary": {
            "destination_count": 3,
            "stable_destination_count": 2,
            "new_destination_count": 1,
            "unusual_resolver_count": 1,
            "dormant_return_count": 0,
            "drift_count": 1,
            "average_confidence": 0.73,
            "by_behavior_state": {"stable_destination_behavior": 2, "destination_drift_detected": 1},
        },
        "dashboard_status": {
            "metrics": {
                "destination_count": 3,
                "stable_destination_count": 2,
                "new_destination_count": 1,
                "unusual_resolver_count": 1,
                "drift_count": 1,
                "average_confidence": 0.73,
            }
        },
    }


def _adaptive_risk_report():
    return {
        "record_type": "adaptive_risk_report",
        "summary": {
            "record_count": 2,
            "score_increase_count": 1,
            "score_reduction_count": 1,
            "average_base_score": 0.5,
            "average_adjusted_score": 0.56,
            "average_confidence": 0.79,
            "by_adjustment_reason": {"new_behavior_observed": 1, "known_stable_behavior": 1},
        },
        "dashboard_status": {
            "metrics": {
                "record_count": 2,
                "score_increase_count": 1,
                "score_reduction_count": 1,
                "average_adjusted_score": 0.56,
                "average_confidence": 0.79,
            }
        },
    }


def _complete_summary():
    return build_behavioral_intelligence_summary(
        behavior_baseline_report=_baseline_report(),
        temporal_anomaly_report=_anomaly_report(),
        service_fingerprint_report=_service_report(),
        dns_destination_behavior_report=_destination_report(),
        adaptive_risk_report=_adaptive_risk_report(),
        gateway_validation_summary={"overall_state": "supported"},
        generated_at=GENERATED_AT,
    )


def test_complete_behavior_summary_composition():
    summary = _complete_summary()

    assert summary["record_type"] == "behavioral_intelligence_summary"
    assert summary["status"] == "degraded"
    assert summary["component_rollups"]["baselines"]["metrics"]["stable_behavior_count"] == 3
    assert summary["component_rollups"]["temporal_anomalies"]["metrics"]["burst_count"] == 1
    assert summary["component_rollups"]["service_fingerprints"]["metrics"]["unusual_combination_count"] == 1
    assert summary["component_rollups"]["dns_destination_behavior"]["metrics"]["drift_count"] == 1
    assert summary["component_rollups"]["adaptive_risk"]["metrics"]["score_increase_count"] == 1
    assert summary["state_summary"]["gateway_validation_state"] == "supported"
    assert summary["dashboard_status"]["panel"] == "behavioral_intelligence"
    assert summary["api_status"]["status"] == "degraded"
    assert summary["export_summary"]["digest"].startswith("sha256:")


def test_empty_inputs_are_unavailable_with_recommendations():
    summary = build_behavioral_intelligence_summary(generated_at=GENERATED_AT)

    assert summary["status"] == "unavailable"
    assert summary["state_summary"]["unavailable_component_count"] == 5
    assert len(summary["recommendations"]) == 5
    assert all(item["action"] == "provide_component_summary" for item in summary["recommendations"])


def test_degraded_inputs_report_missing_component():
    summary = build_behavioral_intelligence_summary(
        behavior_baseline_report=_baseline_report(),
        adaptive_risk_report=_adaptive_risk_report(),
        generated_at=GENERATED_AT,
    )

    assert summary["status"] == "degraded"
    assert summary["state_summary"]["component_states"]["temporal_anomalies"] == "unavailable"
    assert summary["state_summary"]["supported_component_count"] >= 0
    assert summary["dashboard_status"]["metrics"]["unavailable_component_count"] == 3


def test_operator_view_and_live_telemetry_panel_include_behavioral_summary():
    summary = _complete_summary()
    operator = build_behavioral_intelligence_operator_view(summary, generated_at=GENERATED_AT)
    live = build_live_telemetry_operator_summary(behavioral_intelligence_summary=summary, generated_at=GENERATED_AT)

    assert operator["status"] == "degraded"
    assert operator["metrics"]["recommended_review_count"] > 0
    assert operator["recommended_review"] is True
    assert live["panels"]["behavioral_intelligence"]["status"] == "degraded"
    assert live["summary"]["behavioral_component_count"] > 0


def test_privacy_and_safety_fields_are_correct():
    summary = _complete_summary()
    privacy = summary["privacy_safety_summary"]

    assert privacy["payloads_stored"] is False
    assert privacy["credentials_stored"] is False
    assert privacy["external_reputation_calls"] is False
    assert privacy["automatic_enforcement"] is False
    assert summary["firewall_changes"] is False
    assert summary["advisory_only"] is True


def test_recommendations_and_explanations_are_advisory_only():
    summary = _complete_summary()

    assert any(item["action"] == "operator_review_recommended" for item in summary["recommendations"])
    assert all(item["enforcement_allowed"] is False for item in summary["recommendations"])
    assert all("why_no_enforcement" in item for item in summary["explanations"])
    assert all(item["automatic_blocking"] is False for item in summary["explanations"])


def test_serialization_is_deterministic_and_sanitized():
    summary = _complete_summary()
    operator = build_behavioral_intelligence_operator_view(summary, generated_at=GENERATED_AT)
    summary_json = deterministic_behavioral_intelligence_json(summary)
    operator_json = deterministic_behavior_operator_view_json(operator)

    assert summary_json == deterministic_behavioral_intelligence_json(summary)
    assert operator_json == deterministic_behavior_operator_view_json(operator)
    assert '"automatic_enforcement":false' in summary_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(summary_json)
        assert not pattern.search(operator_json)
