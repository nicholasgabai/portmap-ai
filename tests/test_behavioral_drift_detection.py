import json

import pytest

from core_engine.behavior import (
    BehavioralDriftError,
    EnvironmentDriftError,
    build_behavior_drift_record,
    build_behavior_drift_report,
    build_environment_drift_report,
    build_environment_drift_summary,
    deterministic_behavior_drift_json,
    deterministic_environment_drift_json,
    score_behavior_drift,
)


FIXED_TIME = "2026-01-01T00:00:00+00:00"


def _baseline(**overrides):
    base = {
        "baseline_id": "baseline-redacted-001",
        "category": "service",
        "behavior_state": "stable",
        "rolling_average_score": 0.72,
        "observation_count": 12,
        "recurring_behavior": True,
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def _current(**overrides):
    base = {
        "current_id": "current-redacted-001",
        "category": "service",
        "behavior_state": "stable",
        "rolling_average_score": 0.74,
        "observation_count": 13,
        "recurring_behavior": True,
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def test_stable_vs_drift_detection_records_are_bounded_and_advisory():
    stable = build_behavior_drift_record(
        baseline_record=_baseline(),
        current_record=_current(),
        drift_class="service_behavior",
        generated_at=FIXED_TIME,
    )
    drifted = build_behavior_drift_record(
        baseline_record=_baseline(rolling_average_score=0.2, observation_count=3),
        current_record=_current(rolling_average_score=0.95, observation_count=18, behavior_state="new", novelty=True),
        drift_class="service_behavior",
        generated_at=FIXED_TIME,
    )

    assert stable["drift_severity"] == "stable"
    assert stable["drift_score"] < 0.18
    assert drifted["drift_severity"] in {"moderate_drift", "major_drift"}
    assert 0.0 <= drifted["drift_score"] <= 1.0
    assert 0.0 <= drifted["confidence_score"] <= 1.0
    assert drifted["threat_verdict_generated"] is False
    assert drifted["enforcement_enabled"] is False
    assert drifted["automatic_changes"] is False


def test_drift_classes_and_source_mode_are_preserved():
    rows = [
        {
            "drift_class": "application_behavior",
            "baseline": _baseline(baseline_id="baseline-redacted-app", category="application", candidate_app_class="browser_or_web_client"),
            "current": _current(current_id="current-redacted-app", category="application", candidate_app_class="remote_access_client", rolling_average_score=0.9, source_mode="replay"),
        },
        {
            "drift_class": "protocol_behavior",
            "baseline": _baseline(baseline_id="baseline-redacted-protocol", category="protocol", protocol="tcp"),
            "current": _current(current_id="current-redacted-protocol", category="protocol", protocol="udp", rolling_average_score=0.9),
        },
    ]

    report = build_behavior_drift_report(rows, generated_at=FIXED_TIME)

    assert report["summary"]["drift_count"] == 2
    assert report["summary"]["by_drift_class"]["application_behavior"] == 1
    assert report["summary"]["by_drift_class"]["protocol_behavior"] == 1
    assert "replay" in report["summary"]["source_modes"]
    assert report["dashboard_status"]["panel"] == "behavioral_drift_detection"


def test_recurring_change_handling_and_environment_aggregation():
    report = build_environment_drift_report(
        [
            {
                "drift_class": "flow_behavior",
                "baseline": _baseline(category="flow", rolling_average_score=0.3, observation_count=2),
                "current": _current(category="flow", rolling_average_score=0.95, observation_count=18, recurrence_score=0.8, drift_detected=True),
            },
            {
                "drift_class": "topology_behavior",
                "baseline": _baseline(category="topology", rolling_average_score=0.8, observation_count=9),
                "current": _current(category="topology", rolling_average_score=0.78, observation_count=9),
            },
        ],
        generated_at=FIXED_TIME,
    )
    environment = report["environment_summary"]

    assert environment["recurring_change_detected"] is True
    assert environment["unusual_change_detected"] is True
    assert "flow_behavior" in environment["affected_categories"]
    assert 0.0 <= environment["stability_score"] <= 1.0
    assert 0.0 <= environment["confidence_score"] <= 1.0
    assert environment["threat_verdict"] == "not_assessed"
    assert environment["enforcement_action"] == "none"


def test_environment_summary_accepts_prebuilt_drift_records():
    record = build_behavior_drift_record(
        baseline_record=_baseline(category="destination", rolling_average_score=0.4),
        current_record=_current(category="destination", rolling_average_score=0.88, drift_detected=True),
        drift_class="destination_behavior",
        generated_at=FIXED_TIME,
    )
    summary = build_environment_drift_summary([record], generated_at=FIXED_TIME)

    assert summary["affected_categories"] == ["destination_behavior"]
    assert summary["drift_trend"] in {"minor_variation", "gradual_change", "rapid_change"}
    assert summary["operator_summary"]


def test_export_safe_serialization_has_no_payload_or_threat_verdict_behavior():
    record = build_behavior_drift_record(
        baseline_record=_baseline(payload_content="must-not-export"),
        current_record=_current(raw_packet="ignored", rolling_average_score=0.9),
        drift_class="application_behavior",
        generated_at=FIXED_TIME,
    )
    environment = build_environment_drift_summary([record], generated_at=FIXED_TIME)
    serialized = deterministic_behavior_drift_json(record)
    environment_json = deterministic_environment_drift_json(environment)

    assert "must-not-export" not in serialized
    assert "ignored" not in serialized
    assert '"raw_payload_stored":false' in serialized
    assert '"packet_payload_inspected":false' in serialized
    assert '"threat_verdict_generated":false' in serialized
    assert '"threat_verdict":"not_assessed"' in environment_json
    assert '"enforcement_action":"none"' in environment_json


def test_malformed_baseline_handling_and_cross_platform_safe_records():
    with pytest.raises(BehavioralDriftError):
        build_behavior_drift_record(baseline_record="not-an-object", current_record=_current(), generated_at=FIXED_TIME)
    with pytest.raises(BehavioralDriftError):
        build_behavior_drift_report(object(), generated_at=FIXED_TIME)
    with pytest.raises(EnvironmentDriftError):
        build_environment_drift_summary(object(), generated_at=FIXED_TIME)
    with pytest.raises(EnvironmentDriftError):
        build_environment_drift_report(object(), generated_at=FIXED_TIME)

    unknown = build_behavior_drift_record(generated_at=FIXED_TIME)
    serialized = deterministic_behavior_drift_json(unknown)

    assert unknown["drift_severity"] == "unknown"
    assert unknown["source_mode"] == "unknown"
    assert "real_hostname" not in serialized


def test_score_behavior_drift_is_deterministic_and_json_serializable():
    score_a = score_behavior_drift(_baseline(), _current())
    score_b = score_behavior_drift(_baseline(), _current())
    record = build_behavior_drift_record(baseline_record=_baseline(), current_record=_current(), generated_at=FIXED_TIME)

    assert score_a == score_b
    assert deterministic_behavior_drift_json(record) == json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
