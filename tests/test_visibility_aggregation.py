import re

import pytest

from core_engine.aggregation import (
    collect_node_reports,
    merge_assets,
    merge_findings,
    merge_node_reports,
    merge_services,
    merge_topology_edges,
    normalize_node_report,
    summarize_collection,
    validate_node_report,
)
from core_engine.aggregation.collector import AggregationError


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
]


def _report(node_id="node-sample-a", label="Sample Node A", service_name="HTTPS", asset_label="Sample App"):
    return {
        "node_id": node_id,
        "node_label": label,
        "collected_at": "sample-time-a",
        "assets": [{"asset_id": "asset-sample", "label": asset_label, "category": "application", "confidence": 0.7}],
        "services": [{"service_id": "service-sample", "asset_id": "asset-sample", "port": 8443, "service": service_name, "confidence": 0.8}],
        "topology_edges": [
            {
                "edge_id": "edge-sample",
                "src": "asset-sample",
                "dst": "asset-peer",
                "relationship_type": "service_dependency",
                "protocol": "TLS",
                "observation_count": 1,
                "confidence": 0.75,
            }
        ],
        "findings": [{"finding_id": "finding-sample", "title": "Sample Finding", "severity": "medium", "confidence": 0.65}],
        "metadata": {"profile": "sample"},
    }


def test_single_node_report_normalization_and_validation():
    report = normalize_node_report(_report())

    validate_node_report(report)
    assert report["node_id"] == "node-sample-a"
    assert report["assets"][0]["source_node_ids"] == ["node-sample-a"]
    assert report["assets"][0]["source_refs"] == ["node-sample-a:asset:asset-sample"]
    assert report["raw_payload_stored"] is False
    assert report["automatic_changes"] is False
    assert report["administrator_controlled"] is True


def test_invalid_node_report_is_rejected():
    with pytest.raises(AggregationError):
        normalize_node_report({"node_id": "", "assets": []})
    with pytest.raises(AggregationError):
        normalize_node_report({"node_id": "node-sample", "assets": [], "automatic_changes": True})


def test_multi_node_report_collection_summary():
    reports = collect_node_reports([_report(), _report(node_id="node-sample-b", label="Sample Node B")])
    summary = summarize_collection(reports)

    assert len(reports) == 2
    assert summary["node_count"] == 2
    assert summary["asset_count"] == 2
    assert summary["source_node_ids"] == ["node-sample-a", "node-sample-b"]
    assert summary["automatic_changes"] is False


def test_asset_merging_and_duplicate_conflict_reporting():
    reports = collect_node_reports([
        _report(asset_label="Sample App"),
        _report(node_id="node-sample-b", label="Sample Node B", asset_label="Sample App Renamed"),
    ])
    assets, conflicts = merge_assets(report["assets"][0] for report in reports)

    assert len(assets) == 1
    assert assets[0]["source_node_ids"] == ["node-sample-a", "node-sample-b"]
    assert assets[0]["confidence"] == 0.7
    assert conflicts
    conflict_types = {conflict["conflict_type"] for conflict in conflicts}
    assert "duplicate_asset" in conflict_types
    assert "conflicting_asset_labels" in conflict_types
    assert all(conflict["recommended_review"] is True for conflict in conflicts)


def test_service_merging_conflicting_names():
    reports = collect_node_reports([
        _report(service_name="HTTPS"),
        _report(node_id="node-sample-b", label="Sample Node B", service_name="HTTP"),
    ])
    services, conflicts = merge_services(report["services"][0] for report in reports)

    assert len(services) == 1
    assert services[0]["source_node_ids"] == ["node-sample-a", "node-sample-b"]
    assert "conflicting_service_names" in {conflict["conflict_type"] for conflict in conflicts}


def test_topology_edge_merging_duplicate_edges():
    reports = collect_node_reports([_report(), _report(node_id="node-sample-b", label="Sample Node B")])
    edges, conflicts = merge_topology_edges(report["topology_edges"][0] for report in reports)

    assert len(edges) == 1
    assert edges[0]["observation_count"] == 2
    assert edges[0]["source_node_ids"] == ["node-sample-a", "node-sample-b"]
    assert {conflict["conflict_type"] for conflict in conflicts} == {"duplicate_topology_edge"}


def test_finding_merging_preserves_sources():
    reports = collect_node_reports([_report(), _report(node_id="node-sample-b", label="Sample Node B")])
    findings, conflicts = merge_findings(report["findings"][0] for report in reports)

    assert len(findings) == 1
    assert findings[0]["source_node_ids"] == ["node-sample-a", "node-sample-b"]
    assert {conflict["conflict_type"] for conflict in conflicts} == {"duplicate_finding"}


def test_merge_node_reports_preserves_source_attribution_and_safety_flags():
    report_b = _report(node_id="node-sample-b", label="Sample Node B", service_name="HTTP", asset_label="Sample App Renamed")
    report_b["assets"][0]["confidence"] = 0.9
    merged = merge_node_reports([_report(asset_label="Sample App"), report_b])

    assert merged["node_count"] == 2
    assert merged["summary"]["asset_count"] == 1
    assert merged["summary"]["service_count"] == 1
    assert merged["summary"]["conflict_count"] >= 2
    assert merged["assets"][0]["source_node_ids"] == ["node-sample-a", "node-sample-b"]
    assert any(conflict["conflict_type"] == "different_confidence_values" for conflict in merged["conflicts"])
    assert merged["automatic_changes"] is False
    assert merged["administrator_controlled"] is True
    assert merged["raw_payload_stored"] is False


def test_missing_optional_fields_are_handled():
    merged = merge_node_reports([
        {
            "node_id": "node-sample-a",
            "collected_at": "sample-time-a",
            "assets": [{"asset_id": "asset-sample"}],
            "services": [],
            "topology_edges": [],
            "findings": [],
        }
    ])

    assert merged["assets"][0]["asset_id"] == "asset-sample"
    assert merged["assets"][0]["source_node_ids"] == ["node-sample-a"]
    assert any(conflict["conflict_type"] == "missing_optional_fields" for conflict in merged["conflicts"])


def test_no_private_identifiers_in_examples_or_output():
    merged = merge_node_reports([_report(), _report(node_id="node-sample-b", label="Sample Node B")])
    output = repr(merged)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(output)
