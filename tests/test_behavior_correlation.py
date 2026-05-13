import re

from core_engine.correlation import (
    assign_advisory_severity,
    build_baseline_from_aggregated_reports,
    build_baseline_from_events,
    build_baseline_from_snapshots,
    build_baseline_from_visibility_reports,
    compare_asset_sets,
    compare_baselines,
    compare_finding_sets,
    compare_service_sets,
    compare_topology_sets,
    score_delta_finding,
    summarize_delta_scores,
)


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
]


def _asset(asset_id="asset-sample-a", label="Sample Asset", confidence=0.8):
    return {
        "asset_id": asset_id,
        "label": label,
        "category": "application",
        "confidence": confidence,
        "source_refs": [f"source:{asset_id}"],
    }


def _service(asset_id="asset-sample-a", port=8443, service="HTTPS", confidence=0.8):
    return {
        "asset_id": asset_id,
        "port": port,
        "service": service,
        "confidence": confidence,
        "source_refs": [f"source:{asset_id}:service:{port}"],
    }


def _edge(source="asset-sample-a", target="asset-sample-b", relation="service_dependency"):
    return {
        "source_asset": source,
        "target_asset": target,
        "relationship_type": relation,
        "confidence": 0.75,
        "source_refs": [f"source:{source}:{target}"],
    }


def _finding(category="service_drift", severity="medium", finding_id="finding-sample-a"):
    return {
        "finding_id": finding_id,
        "category": category,
        "severity": severity,
        "title": "Sample Finding",
        "source_refs": [f"source:{finding_id}"],
    }


def test_baseline_creation_from_events():
    baseline = build_baseline_from_events(
        [
            {
                "event_id": "event-sample-a",
                "event_type": "asset_observed",
                "severity": "info",
                "timestamp": "sample-time-a",
                "asset_ref": "asset-sample-a",
            },
            {
                "event_id": "event-sample-b",
                "event_type": "policy_review_required",
                "severity": "high",
                "timestamp": "sample-time-b",
                "finding_ref": "finding-sample-a",
                "metadata": {"category": "policy_review"},
            },
        ],
        label="events",
    )

    assert baseline["label"] == "events"
    assert baseline["event_count"] == 2
    assert baseline["asset_count"] == 1
    assert baseline["finding_count"] == 1
    assert baseline["start_time"] == "sample-time-a"
    assert baseline["end_time"] == "sample-time-b"
    assert baseline["raw_payload_stored"] is False


def test_baseline_creation_from_snapshots():
    baseline = build_baseline_from_snapshots(
        [
            {
                "snapshot_id": "snapshot-sample-a",
                "observed_at": "sample-time-a",
                "assets": [_asset()],
                "services": [_service()],
                "topology": {"edges": [_edge()]},
                "findings": [_finding()],
            }
        ]
    )

    assert baseline["asset_count"] == 1
    assert baseline["service_count"] == 1
    assert baseline["topology_edge_count"] == 1
    assert baseline["finding_count"] == 1


def test_baseline_creation_from_visibility_reports():
    baseline = build_baseline_from_visibility_reports(
        [
            {
                "report_id": "visibility-report-sample-a",
                "assets": [_asset()],
                "services": [_service()],
                "topology_edges": [_edge()],
                "findings": [_finding()],
            }
        ]
    )

    assert baseline["asset_count"] == 1
    assert baseline["service_count"] == 1
    assert baseline["topology_edge_count"] == 1


def test_baseline_creation_from_aggregated_reports():
    baseline = build_baseline_from_aggregated_reports(
        {
            "aggregation_id": "aggregation-sample-a",
            "assets": [_asset()],
            "services": [_service()],
            "topology_edges": [_edge()],
            "findings": [_finding()],
        }
    )

    assert baseline["asset_count"] == 1
    assert baseline["service_count"] == 1
    assert baseline["topology_edge_count"] == 1
    assert baseline["administrator_controlled"] is True


def test_asset_delta_detection():
    findings = compare_asset_sets(
        [_asset("asset-sample-a"), _asset("asset-missing")],
        [_asset("asset-sample-a", confidence=0.3), _asset("asset-sample-b")],
    )
    finding_types = {row["finding_type"] for row in findings}

    assert "new_asset_observed" in finding_types
    assert "asset_missing_from_current_window" in finding_types
    assert "low_confidence_identity_match" in finding_types


def test_service_delta_detection():
    findings = compare_service_sets(
        [_service("asset-sample-a", 8443, "HTTPS"), _service("asset-sample-b", 9443, "HTTPS")],
        [_service("asset-sample-a", 8443, "HTTP"), _service("asset-sample-c", 10443, "HTTPS")],
    )
    finding_types = {row["finding_type"] for row in findings}

    assert "new_service_observed" in finding_types
    assert "service_missing_from_current_window" in finding_types
    assert "service_label_changed" in finding_types


def test_topology_delta_detection():
    findings = compare_topology_sets(
        [_edge("asset-sample-a", "asset-sample-b")],
        [_edge("asset-sample-a", "asset-sample-c")],
    )
    finding_types = {row["finding_type"] for row in findings}

    assert "topology_relationship_added" in finding_types
    assert "topology_relationship_removed" in finding_types


def test_finding_category_repetition_and_severity_increase():
    findings = compare_finding_sets(
        [_finding("service_drift", "medium", "finding-before")],
        [
            _finding("service_drift", "high", "finding-after-a"),
            _finding("service_drift", "high", "finding-after-b"),
        ],
    )
    finding_types = {row["finding_type"] for row in findings}

    assert "repeated_finding_category" in finding_types
    assert "severity_increase_observed" in finding_types


def test_baseline_comparison_summary_counts_and_safety_flags():
    baseline = build_baseline_from_visibility_reports(
        [{"report_id": "before", "assets": [_asset("asset-sample-a")], "services": [_service("asset-sample-a", 8443, "HTTPS")]}]
    )
    current = build_baseline_from_visibility_reports(
        [{"report_id": "after", "assets": [_asset("asset-sample-b")], "services": [_service("asset-sample-b", 9443, "HTTPS")]}]
    )
    result = compare_baselines(baseline, current)

    assert result["finding_count"] == 4
    assert result["summary"]["finding_count"] == 4
    assert result["summary"]["recommended_review_count"] == 4
    assert result["automatic_changes"] is False
    assert result["administrator_controlled"] is True
    assert result["raw_payload_stored"] is False


def test_advisory_severity_scoring_helpers():
    finding = {
        "finding_type": "severity_increase_observed",
        "severity": "high",
        "evidence_refs": ["sample-evidence-a", "sample-evidence-b"],
        "recommended_review": True,
    }
    score = score_delta_finding(finding)
    summary = summarize_delta_scores([{**finding, "score": score, "severity": assign_advisory_severity(score)}])

    assert score >= 0.7
    assert assign_advisory_severity(score) in {"high", "critical"}
    assert summary["finding_count"] == 1
    assert summary["max_score"] == score


def test_no_private_identifiers_in_examples_or_output():
    result = compare_baselines(
        build_baseline_from_visibility_reports([{"report_id": "before", "assets": [_asset("asset-sample-a")]}]),
        build_baseline_from_visibility_reports([{"report_id": "after", "assets": [_asset("asset-sample-b")]}]),
    )
    output = repr(result)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(output)
