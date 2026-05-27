import re

import pytest

from core_engine.telemetry import (
    BaselineWindowError,
    BehaviorBaselineError,
    build_behavior_baseline_report,
    build_enriched_flow_observation,
    build_live_telemetry_operator_summary,
    deterministic_behavior_baseline_json,
)


GENERATED_AT = "2026-01-01T00:10:00+00:00"
WINDOW_CONFIG = {
    "short": {"duration_seconds": 120, "max_records": 20},
    "medium": {"duration_seconds": 600, "max_records": 60},
    "long": {"duration_seconds": 3600, "max_records": 200},
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


def _flow_observation(timestamp: str, *, flow_ref: str = "flow-alpha", destination_port: int = 443):
    return build_enriched_flow_observation(
        {
            "flow_id": flow_ref,
            "flow_key": f"{flow_ref}-raw-key-not-exported",
            "transport_protocol": "tcp",
            "classification": "complete",
            "ephemeral_or_persistent": "persistent",
            "first_seen": timestamp,
            "last_seen": timestamp,
            "duration_seconds": 30,
            "initiator": {"ip": "203.0.113.10", "port": 53000},
            "responder": {"ip": "198.51.100.20", "port": destination_port},
            "packet_count": 8,
            "byte_count": 2048,
            "service_association": {
                "service_port": destination_port,
                "service_name": "https" if destination_port == 443 else "ssh",
                "service_endpoint": "responder",
                "confidence": 0.9,
            },
            "source_refs": [f"fixture:{flow_ref}:{timestamp}"],
        },
        local_cidrs=["203.0.113.0/24"],
        generated_at=timestamp,
    )


def _stable_inputs():
    return [
        _flow_observation("2026-01-01T00:00:00+00:00"),
        _flow_observation("2026-01-01T00:03:00+00:00"),
        _flow_observation("2026-01-01T00:06:00+00:00"),
        _flow_observation("2026-01-01T00:09:00+00:00"),
    ]


def _dns_records():
    return [
        {
            "query_name": "updates.example.test",
            "timestamp": "2026-01-01T00:09:30+00:00",
            "confidence": 0.7,
            "source_refs": ["fixture:dns:1"],
        }
    ]


def _service_attributions():
    return [
        {
            "service_name": "https",
            "service_port": 443,
            "transport_protocol": "tcp",
            "process": {"process_name": "web-service"},
            "last_seen": "2026-01-01T00:09:00+00:00",
            "confidence": 0.82,
            "source_refs": ["fixture:service:1"],
        }
    ]


def _report(**kwargs):
    return build_behavior_baseline_report(
        flow_observations=_stable_inputs(),
        dns_records=_dns_records(),
        service_attributions=_service_attributions(),
        generated_at=GENERATED_AT,
        window_config=WINDOW_CONFIG,
        **kwargs,
    )


def test_creates_metadata_only_baseline_records_for_required_categories():
    report = _report()
    categories = {row["category"] for row in report["entries"]}

    assert report["record_type"] == "behavior_baseline_report"
    assert {"port", "protocol", "service", "process_service_fingerprint", "flow_tuple", "dns_domain"} <= categories
    assert report["summary"]["baseline_entry_count"] == len(report["entries"])
    assert report["summary"]["stable_behavior_count"] >= 3
    assert report["window_set"]["windows"]["short"]["retained_observation_count"] > 0
    assert report["window_set"]["windows"]["long"]["retained_observation_count"] >= report["window_set"]["windows"]["short"]["retained_observation_count"]
    assert report["raw_payload_stored"] is False
    assert report["payload_bytes_stored"] == 0
    assert report["credentials_stored"] is False
    assert report["external_services_called"] is False


def test_detects_stable_recurring_behavior_and_novel_dns_behavior():
    report = _report()
    https = next(row for row in report["entries"] if row["category"] == "service" and row["display_label"] == "https")
    dns = next(row for row in report["entries"] if row["category"] == "dns_domain")

    assert https["behavior_state"] == "stable"
    assert https["stable_behavior"] is True
    assert https["novelty"] is False
    assert https["observation_count"] >= 3
    assert https["confidence"] >= 0.8
    assert dns["behavior_state"] == "new"
    assert dns["novelty"] is True
    assert dns["stable_behavior"] is False


def test_marks_previous_baseline_as_decaying_inactive_when_not_observed():
    first_report = _report()
    previous_https = [row for row in first_report["entries"] if row["category"] == "service" and row["display_label"] == "https"]
    second_report = build_behavior_baseline_report(
        flow_observations=[],
        dns_records=[],
        service_attributions=[],
        previous_baselines=previous_https,
        generated_at="2026-01-01T01:00:00+00:00",
        window_config=WINDOW_CONFIG,
    )

    assert second_report["summary"]["decaying_inactive_count"] == 1
    assert second_report["entries"][0]["behavior_state"] == "decaying_inactive"
    assert second_report["entries"][0]["novelty"] is False
    assert second_report["entries"][0]["confidence"] < previous_https[0]["confidence"]


def test_bounds_retained_baseline_entries():
    report = _report(max_entries=3)

    assert len(report["entries"]) == 3
    assert report["summary"]["baseline_entry_count"] == 3
    assert all(row["bounded_retention_applied"] is True for row in report["entries"])
    assert all(row["dropped_entry_count"] > 0 for row in report["entries"])


def test_window_rollover_excludes_old_short_window_observations():
    report = _report()

    short = report["window_set"]["windows"]["short"]
    medium = report["window_set"]["windows"]["medium"]
    assert short["retained_observation_count"] < medium["retained_observation_count"]
    assert short["earliest_seen"] >= "2026-01-01T00:09:00+00:00"
    assert medium["earliest_seen"] == "2026-01-01T00:00:00+00:00"


def test_operator_and_export_serialization_are_api_safe_and_deterministic():
    report = _report()
    operator_summary = build_live_telemetry_operator_summary(
        behavior_baseline_report=report,
        generated_at=GENERATED_AT,
    )
    report_json = deterministic_behavior_baseline_json(report)

    assert operator_summary["panels"]["behavior_baselines"]["metrics"]["baseline_entry_count"] == len(report["entries"])
    assert operator_summary["summary"]["behavior_baseline_count"] == len(report["entries"])
    assert report["export_summary"]["digest"].startswith("sha256:")
    assert report_json == deterministic_behavior_baseline_json(report)
    assert '"raw_payload_stored":false' in report_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(report_json)


def test_rejects_invalid_baseline_bounds():
    with pytest.raises(BehaviorBaselineError):
        _report(max_entries=0)
    with pytest.raises(BaselineWindowError):
        build_behavior_baseline_report(
            flow_observations=_stable_inputs(),
            generated_at=GENERATED_AT,
            window_config={"short": {"duration_seconds": 0, "max_records": 1}},
        )
