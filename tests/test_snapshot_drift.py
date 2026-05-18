import json
import re

from core_engine.topology.diff import (
    compare_asset_drift,
    compare_finding_drift,
    compare_service_drift,
    compare_topology_edge_drift,
    compare_topology_snapshots,
)
from core_engine.topology.drift import (
    build_drift_correlation_records,
    build_drift_event,
    build_drift_policy_records,
    build_drift_storage_record,
    build_drift_timeline_entries,
    summarize_drift,
)
from core_engine.topology.snapshots import build_topology_snapshot


PRIVATE_IDENTIFIER_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


def _snapshot(label, *, assets, services, edges, findings=None, observed_at="2026-01-01T00:00:00+00:00"):
    return build_topology_snapshot(
        assets=assets,
        services=services,
        topology_edges=edges,
        findings=findings or [],
        label=label,
        observed_at=observed_at,
    )


def _baseline_snapshot():
    return _snapshot(
        "baseline",
        assets=[
            {"asset_id": "asset-alpha", "label": "Asset Alpha", "category": "workload", "confidence": 0.9},
            {"asset_id": "asset-retired", "label": "Retired Asset", "category": "workload", "confidence": 0.8},
        ],
        services=[{"asset_id": "asset-alpha", "service": "http", "port": 8080}],
        edges=[
            {
                "source_asset": "asset-alpha",
                "target_asset": "asset-retired",
                "relationship_type": "service_dependency",
                "service_label": "http",
                "observation_count": 1,
                "confidence": 0.8,
            }
        ],
        findings=[
            {
                "finding_id": "finding-sample",
                "finding_type": "sample_review",
                "severity": "low",
                "summary": "Sample low finding.",
                "source_refs": ["snapshot:baseline"],
            }
        ],
    )


def _current_snapshot():
    return _snapshot(
        "current",
        assets=[
            {"asset_id": "asset-alpha", "label": "Asset Alpha Renamed", "category": "service", "confidence": 0.9},
            {"asset_id": "asset-beta", "label": "Asset Beta", "category": "database", "confidence": 0.85},
        ],
        services=[
            {"asset_id": "asset-alpha", "service": "https", "port": 8080},
            {"asset_id": "asset-beta", "service": "postgresql", "port": 5432},
        ],
        edges=[
            {
                "source_asset": "asset-alpha",
                "target_asset": "asset-beta",
                "relationship_type": "service_dependency",
                "service_label": "postgresql",
                "observation_count": 3,
                "confidence": 0.9,
            }
        ],
        findings=[
            {
                "finding_id": "finding-sample",
                "finding_type": "sample_review",
                "severity": "high",
                "summary": "Sample high finding.",
                "source_refs": ["snapshot:current"],
            },
            {
                "finding_id": "finding-sample-two",
                "finding_type": "sample_review",
                "severity": "medium",
                "summary": "Repeated sample finding.",
                "source_refs": ["snapshot:current"],
            },
        ],
        observed_at="2026-01-02T00:00:00+00:00",
    )


def test_asset_drift_detection():
    baseline = ( _baseline_snapshot()["topology"] )["nodes"]
    current = ( _current_snapshot()["topology"] )["nodes"]

    drifts = compare_asset_drift(baseline, current)
    drift_types = {row["drift_type"] for row in drifts}

    assert "asset_added" in drift_types
    assert "asset_removed" in drift_types
    assert "asset_label_changed" in drift_types
    assert "asset_category_changed" in drift_types
    assert all(row["raw_payload_stored"] is False for row in drifts)


def test_service_drift_detection():
    baseline = [
        {"asset_id": "asset-alpha", "service": "http", "port": 8080, "source_refs": ["service:baseline"]},
        {"asset_id": "asset-old", "service": "smtp", "port": 25, "source_refs": ["service:old"]},
    ]
    current = [
        {"asset_id": "asset-alpha", "service": "https", "port": 8080, "source_refs": ["service:current"]},
        {"asset_id": "asset-beta", "service": "postgresql", "port": 5432, "source_refs": ["service:new"]},
    ]

    drifts = compare_service_drift(baseline, current)
    drift_types = {row["drift_type"] for row in drifts}

    assert "service_added" in drift_types
    assert "service_removed" in drift_types
    assert "service_label_changed" in drift_types


def test_topology_edge_drift_detection():
    baseline = _baseline_snapshot()["topology"]["edges"]
    current = _current_snapshot()["topology"]["edges"]

    drifts = compare_topology_edge_drift(baseline, current)
    drift_types = {row["drift_type"] for row in drifts}

    assert "topology_edge_added" in drift_types
    assert "topology_edge_removed" in drift_types


def test_finding_drift_detection():
    drifts = compare_finding_drift(_baseline_snapshot()["findings"], _current_snapshot()["findings"])
    drift_types = {row["drift_type"] for row in drifts}

    assert "finding_added" in drift_types
    assert "finding_category_repeated" in drift_types
    assert "finding_severity_increased" in drift_types


def test_compare_topology_snapshots_returns_structured_report():
    report = compare_topology_snapshots(
        _baseline_snapshot(),
        _current_snapshot(),
        generated_at="2026-01-03T00:00:00+00:00",
    )

    assert report["ok"] is True
    assert report["status"] == "ok"
    assert report["drift_count"] >= 8
    assert report["summary"]["by_category"]["asset"] >= 4
    assert report["summary"]["by_category"]["service"] >= 1
    assert report["summary"]["by_category"]["topology"] >= 2
    assert report["summary"]["by_category"]["finding"] >= 3
    assert report["event_ready"] is True
    assert report["storage_ready"] is True
    assert report["policy_review_ready"] is True
    assert report["timeline_ready"] is True
    assert report["correlation_ready"] is True
    assert report["raw_payload_stored"] is False
    assert report["automatic_changes"] is False


def test_invalid_snapshot_report_is_structured():
    report = compare_topology_snapshots({"snapshot_type": "bad"}, _current_snapshot())

    assert report["ok"] is False
    assert report["status"] == "invalid"
    assert report["errors"]
    assert report["summary"]["error_count"] > 0


def test_drift_ready_records():
    report = compare_topology_snapshots(
        _baseline_snapshot(),
        _current_snapshot(),
        generated_at="2026-01-03T00:00:00+00:00",
    )

    event = build_drift_event(report, timestamp="2026-01-03T00:00:00+00:00")
    storage = build_drift_storage_record(report)
    policy_records = build_drift_policy_records(report)
    timeline = build_drift_timeline_entries(report)
    correlation = build_drift_correlation_records(report)
    summary = summarize_drift(report["drifts"])

    assert event["event_type"] == "policy_review_required"
    assert event["metadata"]["diagnostic_type"] == "topology_snapshot_drift"
    assert storage["record_type"] == "topology_snapshot_drift"
    assert storage["payload"]["drift_count"] == report["drift_count"]
    assert policy_records
    assert timeline
    assert correlation
    assert summary["drift_count"] == report["drift_count"]
    assert all(row["raw_payload_stored"] is False for row in [event, storage, *policy_records, *timeline, *correlation])


def test_snapshot_drift_outputs_do_not_contain_private_identifiers():
    report = compare_topology_snapshots(
        _baseline_snapshot(),
        _current_snapshot(),
        generated_at="2026-01-03T00:00:00+00:00",
    )
    records = [
        report,
        build_drift_event(report, timestamp="2026-01-03T00:00:00+00:00"),
        build_drift_storage_record(report),
        build_drift_timeline_entries(report),
        build_drift_correlation_records(report),
    ]
    payload = json.dumps(records, sort_keys=True)

    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(payload)
