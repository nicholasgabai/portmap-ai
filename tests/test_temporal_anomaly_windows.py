import re

import pytest

from core_engine.telemetry import (
    TemporalAnomalyError,
    build_behavior_baseline_report,
    build_enriched_flow_observation,
    build_live_telemetry_operator_summary,
    build_temporal_anomaly_report,
    deterministic_temporal_anomaly_json,
)


GENERATED_AT = "2026-01-01T00:10:00+00:00"
WINDOW_CONFIG = {
    "short": {"duration_seconds": 120, "max_records": 200},
    "medium": {"duration_seconds": 600, "max_records": 500},
    "long": {"duration_seconds": 3600, "max_records": 1000},
}

PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile("/" + "home/"),
    re.compile("/" + "Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
]


def _flow_observation(timestamp: str, *, flow_ref: str, destination_port: int = 443, service_name: str = "https"):
    return build_enriched_flow_observation(
        {
            "flow_id": flow_ref,
            "flow_key": f"{flow_ref}-fixture-key",
            "transport_protocol": "tcp",
            "classification": "complete",
            "ephemeral_or_persistent": "persistent",
            "first_seen": timestamp,
            "last_seen": timestamp,
            "duration_seconds": 20,
            "initiator": {"ip": "203.0.113.10", "port": 53000},
            "responder": {"ip": "198.51.100.20", "port": destination_port},
            "packet_count": 10,
            "byte_count": 4096,
            "service_association": {
                "service_port": destination_port,
                "service_name": service_name,
                "service_endpoint": "responder",
                "confidence": 0.9,
            },
            "source_refs": [f"fixture:{flow_ref}:{timestamp}"],
        },
        local_cidrs=["203.0.113.0/24"],
        generated_at=timestamp,
    )


def _burst_baseline():
    flows = [
        _flow_observation(f"2026-01-01T00:09:{str(second).zfill(2)}+00:00", flow_ref=f"flow-{second}")
        for second in range(0, 8)
    ]
    return build_behavior_baseline_report(
        flow_observations=flows,
        dns_records=[{"query_name": "updates.example.test", "timestamp": "2026-01-01T00:09:30+00:00", "confidence": 0.7}],
        generated_at=GENERATED_AT,
        window_config=WINDOW_CONFIG,
    )


def _rare_service_baseline():
    flows = [
        _flow_observation("2026-01-01T00:00:00+00:00", flow_ref="stable-1"),
        _flow_observation("2026-01-01T00:03:00+00:00", flow_ref="stable-2"),
        _flow_observation("2026-01-01T00:06:00+00:00", flow_ref="stable-3"),
        _flow_observation("2026-01-01T00:09:30+00:00", flow_ref="rare-ssh", destination_port=22, service_name="ssh"),
    ]
    return build_behavior_baseline_report(
        flow_observations=flows,
        generated_at=GENERATED_AT,
        window_config=WINDOW_CONFIG,
    )


def test_detects_short_window_bursts_and_volume_drift():
    report = build_temporal_anomaly_report(_burst_baseline(), generated_at=GENERATED_AT)
    labels = {row["label"] for row in report["anomalies"]}

    assert report["record_type"] == "temporal_anomaly_report"
    assert "burst_detected" in labels
    assert "volume_drift_hint" in labels
    assert report["summary"]["burst_count"] >= 1
    assert report["summary"]["volume_drift_count"] == 1
    assert report["dashboard_status"]["status"] == "review_required"
    assert report["raw_payload_stored"] is False
    assert report["credentials_stored"] is False
    assert report["external_reputation_calls"] is False
    assert report["firewall_changes"] is False


def test_detects_rare_service_timing_and_new_behavior_inside_window():
    report = build_temporal_anomaly_report(_rare_service_baseline(), generated_at=GENERATED_AT)
    rows = {(row["label"], row["display_label"]) for row in report["anomalies"]}

    assert ("rare_service_timing", "ssh") in rows
    assert any(label == "new_behavior_in_window" and display == "ssh" for label, display in rows)
    rare = next(row for row in report["anomalies"] if row["label"] == "rare_service_timing")
    assert rare["confidence"] > 0.4
    assert "Rare service behavior" in rare["explanation"]


def test_handles_empty_baseline_without_anomalies():
    baseline = build_behavior_baseline_report(
        flow_observations=[],
        dns_records=[],
        service_attributions=[],
        generated_at=GENERATED_AT,
        window_config=WINDOW_CONFIG,
    )
    report = build_temporal_anomaly_report(baseline, generated_at=GENERATED_AT)

    assert report["summary"]["anomaly_count"] == 0
    assert report["dashboard_status"]["status"] == "ok"
    assert report["api_status"]["status"] == "ok"


def test_handles_malformed_baseline_input_safely():
    report = build_temporal_anomaly_report(None, generated_at=GENERATED_AT)

    assert report["summary"]["anomaly_count"] == 1
    assert report["anomalies"][0]["label"] == "malformed_baseline_input"
    assert report["anomalies"][0]["severity"] == "low"
    assert report["anomaly_windows"]["malformed_input"] is True


def test_bounds_anomaly_retention():
    report = build_temporal_anomaly_report(_burst_baseline(), generated_at=GENERATED_AT, max_anomalies=2)

    assert len(report["anomalies"]) == 2
    assert report["dropped_anomaly_count"] > 0
    assert all(row["bounded_retention_applied"] is True for row in report["anomalies"])


def test_operator_summary_and_export_serialization_are_safe_and_deterministic():
    report = build_temporal_anomaly_report(_rare_service_baseline(), generated_at=GENERATED_AT)
    operator = build_live_telemetry_operator_summary(temporal_anomaly_report=report, generated_at=GENERATED_AT)
    report_json = deterministic_temporal_anomaly_json(report)

    assert operator["panels"]["temporal_anomalies"]["metrics"]["anomaly_count"] == report["summary"]["anomaly_count"]
    assert operator["summary"]["temporal_anomaly_count"] == report["summary"]["anomaly_count"]
    assert report["export_summary"]["digest"].startswith("sha256:")
    assert report_json == deterministic_temporal_anomaly_json(report)
    assert '"raw_payload_stored":false' in report_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(report_json)


def test_rejects_invalid_temporal_anomaly_configuration():
    with pytest.raises(TemporalAnomalyError):
        build_temporal_anomaly_report(_burst_baseline(), generated_at=GENERATED_AT, max_anomalies=0)
    with pytest.raises(TemporalAnomalyError):
        build_temporal_anomaly_report(_burst_baseline(), generated_at=GENERATED_AT, burst_multiplier=1)
