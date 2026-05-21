import json
import re

from core_engine.policy import (
    build_distributed_review_summary,
    build_review_record,
    create_policy,
    detect_duplicate_reviews,
    import_review_drafts_from_node_summary,
    normalize_node_review_summary,
)
from core_engine.policy.history import build_finding_status_record, export_review_records


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
]


def _policy():
    return create_policy(
        policy_id="policy-sample",
        name="Sample Review Policy",
        description="Review advisory records.",
        severity_threshold="medium",
        now="2026-01-01T00:00:00+00:00",
    )


def _review(index: str, *, source_ref: str | None = None, category: str = "exposure_review", severity: str = "high"):
    return build_review_record(
        policy=_policy(),
        source_ref=source_ref or f"finding:finding-{index}",
        category=category,
        severity=severity,
        title=f"Sample Review {index}",
        summary=f"Sample review summary {index}.",
        evidence_refs=[f"asset:asset-{index}"],
        now="2026-01-01T00:00:00+00:00",
    )


def _node_summary(node_id: str, role: str = "worker", reviews=None, finding_statuses=None, **overrides):
    payload = {
        "node_id": node_id,
        "node_label": f"{role}-node",
        "role": role,
        "source_refs": [f"node-review:{node_id}"],
        "reviews": [review.to_dict() for review in (reviews or [])],
        "finding_statuses": finding_statuses or [],
    }
    payload.update(overrides)
    return payload


def test_node_review_summary_imports_sanitized_review_drafts():
    review = _review("a", severity="medium")
    node = normalize_node_review_summary(
        _node_summary("node-worker-a", reviews=[review]),
        generated_at="2026-01-02T00:00:00+00:00",
    )

    assert node["record_type"] == "distributed_node_review_summary"
    assert node["node_id"] == "node-worker-a"
    assert node["summary"]["review_count"] == 1
    assert node["summary"]["by_status"]["open"] == 1
    assert node["summary"]["by_severity"]["medium"] == 1
    assert node["reviews"][0]["source_node_id"] == "node-worker-a"
    assert node["reviews"][0]["node_owned"] is True
    assert node["reviews"][0]["remote_state_changes_enabled"] is False
    assert node["raw_payload_stored"] is False


def test_import_review_drafts_accepts_existing_export_payload():
    first = _review("a")
    exported = export_review_records([first], generated_at="2026-01-02T00:00:00+00:00")

    imported = import_review_drafts_from_node_summary({"node_id": "node-worker-a", "review_export": exported})

    assert len(imported) == 1
    assert imported[0].review_id == first.review_id
    assert imported[0].automatic_changes is False


def test_distributed_review_summary_counts_duplicates_and_repeated_categories():
    shared = "finding:finding-shared"
    first = _review("a", source_ref=shared, category="exposure_review", severity="high")
    second = _review("b", source_ref=shared, category="exposure_review", severity="medium")
    third = _review("c", source_ref="finding:finding-c", category="service_review", severity="medium")

    distributed = build_distributed_review_summary(
        [
            _node_summary("node-master-a", "master", reviews=[first, third]),
            _node_summary("node-worker-b", "worker", reviews=[second]),
        ],
        generated_at="2026-01-02T00:00:00+00:00",
    )

    assert distributed["record_type"] == "distributed_review_summary"
    assert distributed["summary"]["node_count"] == 2
    assert distributed["summary"]["review_count"] == 3
    assert distributed["summary"]["duplicate_review_count"] >= 1
    assert distributed["summary"]["repeated_category_count"] == 1
    assert distributed["summary"]["recommended_review_count"] >= 2
    assert distributed["summary"]["administrator_review_required"] is True
    assert distributed["dashboard_panel"]["panel"] == "distributed_review_queue"
    assert distributed["dashboard_panel"]["status"] == "review_required"
    assert distributed["export_ready"]["export_ready"] is True
    assert distributed["export_ready"]["source_node_ids"] == ["node-master-a", "node-worker-b"]


def test_duplicate_detection_reports_review_id_and_source_conflicts():
    first = _review("a", source_ref="finding:finding-shared")
    second = _review("b", source_ref="finding:finding-shared")
    rows = [
        {**first.to_dict(), "source_node_id": "node-a"},
        {**first.to_dict(), "source_node_id": "node-b"},
        {**second.to_dict(), "source_node_id": "node-c"},
    ]

    duplicates = detect_duplicate_reviews(rows)
    conflict_types = {duplicate["conflict_type"] for duplicate in duplicates}

    assert {"duplicate_review_id", "duplicate_review_source"} <= conflict_types
    assert all(duplicate["recommended_review"] is True for duplicate in duplicates)
    assert all(len(duplicate["source_node_ids"]) >= 2 for duplicate in duplicates)


def test_cross_node_finding_statuses_and_malformed_nodes_are_reported():
    first_status = build_finding_status_record(
        "finding:finding-shared",
        status="deferred",
        source_ref="review:review-a",
        updated_at="2026-01-02T00:00:00+00:00",
    )
    second_status = build_finding_status_record(
        "finding:finding-shared",
        status="resolved",
        source_ref="review:review-b",
        updated_at="2026-01-02T00:01:00+00:00",
    )

    distributed = build_distributed_review_summary(
        [
            _node_summary("node-a", reviews=[_review("a")], finding_statuses=[first_status]),
            _node_summary("node-b", reviews=[_review("b")], finding_statuses=[second_status]),
            {"role": "worker", "reviews": []},
        ],
        generated_at="2026-01-02T00:00:00+00:00",
    )
    finding = distributed["finding_statuses"]["findings"][0]

    assert distributed["summary"]["malformed_node_count"] == 1
    assert distributed["summary"]["finding_status_count"] == 2
    assert finding["finding_ref"] == "finding:finding-shared"
    assert finding["by_status"] == {"deferred": 1, "resolved": 1}
    assert finding["source_node_ids"] == ["node-a", "node-b"]


def test_distributed_review_output_has_no_private_identifiers():
    distributed = build_distributed_review_summary(
        [
            _node_summary("node-master-a", "master", reviews=[_review("a")]),
            _node_summary("node-worker-b", "worker", reviews=[_review("b", severity="medium")]),
        ],
        generated_at="2026-01-02T00:00:00+00:00",
    )
    payload = json.dumps(distributed, sort_keys=True)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
