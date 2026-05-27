import re

from core_engine.telemetry import (
    build_adaptive_risk_report,
    build_live_telemetry_operator_summary,
    clamp_risk_score,
    deterministic_adaptive_risk_json,
)


GENERATED_AT = "2026-01-01T00:40:00+00:00"

PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile("/" + "home/"),
    re.compile("/" + "Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
]


def _baseline(*, stable: int = 0, novel: int = 0, confidence: float = 0.85):
    return {
        "record_type": "behavior_baseline_report",
        "summary": {
            "stable_behavior_count": stable,
            "novel_behavior_count": novel,
            "recurring_behavior_count": stable,
            "average_confidence": confidence,
        },
        "entries": [{"baseline_id": f"baseline-{index}"} for index in range(stable + novel)],
    }


def _anomalies(*, burst: int = 0, confidence: float = 0.72):
    return {
        "record_type": "temporal_anomaly_report",
        "summary": {
            "anomaly_count": burst,
            "burst_count": burst,
            "average_confidence": confidence,
        },
        "anomalies": [{"anomaly_id": f"anomaly-{index}"} for index in range(burst)],
    }


def _service_fingerprints(*, unusual: int = 0, stable: int = 0, confidence: float = 0.7):
    return {
        "record_type": "service_behavior_fingerprint_report",
        "profile_summary": {
            "profile_count": unusual + stable,
            "stable_profile_count": stable,
            "unusual_combination_count": unusual,
            "average_confidence": confidence,
        },
        "profiles": [{"profile_id": f"service-profile-{index}"} for index in range(unusual + stable)],
    }


def _destinations(*, unusual: int = 0, drift: int = 0, stable: int = 0, confidence: float = 0.7):
    return {
        "record_type": "dns_destination_behavior_report",
        "summary": {
            "destination_count": unusual + drift + stable,
            "stable_destination_count": stable,
            "unusual_resolver_count": unusual,
            "drift_count": drift,
            "average_confidence": confidence,
        },
        "profiles": [{"profile_id": f"destination-profile-{index}"} for index in range(unusual + drift + stable)],
    }


def _record(report):
    return report["records"][0]


def test_stable_behavior_reduces_advisory_score():
    report = build_adaptive_risk_report(
        risk_inputs=[{"source_ref": "finding:stable", "base_score": 0.7, "confidence": 0.9}],
        baseline_report=_baseline(stable=4, confidence=0.9),
        generated_at=GENERATED_AT,
    )
    record = _record(report)

    assert record["adjusted_score"] < record["base_score"]
    assert "known_stable_behavior" in record["adjustment_reason"]
    assert "mature_baseline_confidence" in record["adjustment_reason"]
    assert record["enforcement_allowed"] is False
    assert record["automatic_blocking"] is False


def test_new_behavior_increases_advisory_score():
    report = build_adaptive_risk_report(
        risk_inputs=[{"source_ref": "finding:new", "base_score": 0.4, "confidence": 0.8}],
        baseline_report=_baseline(novel=2, confidence=0.6),
        generated_at=GENERATED_AT,
    )
    record = _record(report)

    assert record["adjusted_score"] > record["base_score"]
    assert "new_behavior_observed" in record["adjustment_reason"]


def test_temporal_anomaly_increases_advisory_score():
    report = build_adaptive_risk_report(
        risk_inputs=[{"source_ref": "finding:burst", "base_score": 0.35, "confidence": 0.8}],
        temporal_anomaly_report=_anomalies(burst=1),
        generated_at=GENERATED_AT,
    )
    record = _record(report)

    assert record["adjusted_score"] > record["base_score"]
    assert "temporal_burst_anomaly" in record["adjustment_reason"]


def test_unusual_service_and_destination_increase_score():
    report = build_adaptive_risk_report(
        risk_inputs=[{"source_ref": "finding:unusual", "base_score": 0.35, "confidence": 0.85}],
        service_fingerprint_report=_service_fingerprints(unusual=1),
        dns_destination_behavior_report=_destinations(unusual=1, drift=1),
        generated_at=GENERATED_AT,
    )
    record = _record(report)

    assert record["adjusted_score"] > record["base_score"]
    assert "unusual_process_port_pair" in record["adjustment_reason"]
    assert "unusual_resolver_or_destination" in record["adjustment_reason"]


def test_low_confidence_dampens_adjustment():
    high = _record(
        build_adaptive_risk_report(
            risk_inputs=[{"source_ref": "finding:high-confidence", "base_score": 0.4, "confidence": 0.9}],
            temporal_anomaly_report=_anomalies(burst=1),
            generated_at=GENERATED_AT,
        )
    )
    low = _record(
        build_adaptive_risk_report(
            risk_inputs=[{"source_ref": "finding:low-confidence", "base_score": 0.4, "confidence": 0.3}],
            temporal_anomaly_report=_anomalies(burst=1),
            generated_at=GENERATED_AT,
        )
    )

    assert high["adjusted_score"] > low["adjusted_score"]
    assert "low_confidence_dampening" in low["adjustment_reason"]
    assert "low_confidence_input" in low["explanation"]["limitations"]


def test_adjusted_score_clamps_to_valid_range():
    high = _record(
        build_adaptive_risk_report(
            risk_inputs=[{"source_ref": "finding:max", "base_score": 0.98, "confidence": 1.0}],
            temporal_anomaly_report=_anomalies(burst=2),
            service_fingerprint_report=_service_fingerprints(unusual=2),
            dns_destination_behavior_report=_destinations(unusual=2, drift=2),
            generated_at=GENERATED_AT,
        )
    )
    low = clamp_risk_score(-0.5)

    assert high["adjusted_score"] == 1.0
    assert low == 0.0


def test_explanation_serializes_safely_and_enforcement_stays_disabled():
    report = build_adaptive_risk_report(
        risk_inputs=[{"source_ref": "finding:explain", "base_score": 0.55, "confidence": 0.8}],
        baseline_report=_baseline(stable=3),
        temporal_anomaly_report=_anomalies(burst=1),
        service_fingerprint_report=_service_fingerprints(unusual=1),
        dns_destination_behavior_report=_destinations(unusual=1),
        generated_at=GENERATED_AT,
    )
    operator = build_live_telemetry_operator_summary(adaptive_risk_report=report, generated_at=GENERATED_AT)
    report_json = deterministic_adaptive_risk_json(report)

    assert "why_no_enforcement" in report["records"][0]["explanation"]
    assert report["records"][0]["enforcement_allowed"] is False
    assert report["export_summary"]["digest"].startswith("sha256:")
    assert operator["panels"]["adaptive_risk"]["metrics"]["record_count"] == 1
    assert operator["summary"]["adaptive_risk_count"] == 1
    assert report_json == deterministic_adaptive_risk_json(report)
    assert '"enforcement_allowed":false' in report_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(report_json)
