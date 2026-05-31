import json

from core_engine.history import (
    build_historical_snapshot,
    build_historical_timeline_replay,
    build_replay_window_record,
    deterministic_historical_replay_json,
    select_snapshots_for_replay_window,
)
from core_engine.telemetry.behavior_summary import build_behavioral_intelligence_summary


NOW = "2026-04-01T00:00:00+00:00"


def _behavior_summary(generated_at: str, *, anomaly_count: int = 0, risk_count: int = 0):
    baseline_report = {
        "record_type": "behavior_baseline_report",
        "summary": {
            "baseline_entry_count": 2,
            "stable_behavior_count": 1,
            "novel_behavior_count": 1,
            "decaying_inactive_count": 0,
            "average_confidence": 0.8,
        },
        "dashboard_status": {"metrics": {"baseline_entry_count": 2, "novel_behavior_count": 1, "average_confidence": 0.8}},
    }
    anomaly_report = {
        "record_type": "temporal_anomaly_report",
        "summary": {
            "anomaly_count": anomaly_count,
            "burst_count": anomaly_count,
            "rare_service_timing_count": 0,
            "volume_drift_count": 0,
            "novel_behavior_count": anomaly_count,
            "average_confidence": 0.72,
        },
        "dashboard_status": {"metrics": {"anomaly_count": anomaly_count, "burst_count": anomaly_count, "average_confidence": 0.72}},
    }
    adaptive_risk_report = {
        "record_type": "adaptive_risk_report",
        "summary": {
            "record_count": risk_count,
            "score_increase_count": risk_count,
            "score_reduction_count": 0,
            "average_base_score": 40,
            "average_adjusted_score": 50,
            "average_confidence": 0.7,
        },
        "dashboard_status": {"metrics": {"record_count": risk_count, "score_increase_count": risk_count, "average_confidence": 0.7}},
    }
    return build_behavioral_intelligence_summary(
        behavior_baseline_report=baseline_report,
        temporal_anomaly_report=anomaly_report,
        adaptive_risk_report=adaptive_risk_report,
        generated_at=generated_at,
    )


def _snapshot(ts: str, *, anomaly_count: int = 0, risk_count: int = 0):
    return build_historical_snapshot(
        _behavior_summary(ts, anomaly_count=anomaly_count, risk_count=risk_count),
        source_label="behavior-fixture",
        generated_at=ts,
    )


def _topology_report():
    return {
        "record_type": "long_term_topology_evolution_report",
        "report_id": "topology-evolution-placeholder",
        "generated_at": NOW,
        "relationship_summary": {
            "stable_relationship_count": 1,
            "transient_relationship_count": 1,
            "dormant_return_count": 1,
        },
        "drift_summary": {
            "status": "review_required",
            "added_relationship_count": 1,
            "removed_relationship_count": 1,
            "dormant_return_count": 1,
        },
        "export_summary": {
            "record_counts": {"relationships": 2, "stable": 1, "transient": 1},
            "digest": "sha256:topology-placeholder",
        },
    }


def test_replay_from_ordered_snapshots_reconstructs_timeline():
    snapshots = [
        _snapshot("2026-03-01T00:00:00+00:00", anomaly_count=1),
        _snapshot(NOW, anomaly_count=2, risk_count=1),
    ]

    report = build_historical_timeline_replay(historical_snapshots=snapshots, generated_at=NOW)

    assert report["snapshot_sequence"]["snapshot_count"] == 2
    assert report["timeline_events"][0]["event_type"] == "snapshot"
    assert report["anomaly_replay_summary"]["snapshot_anomaly_count"] == 3
    assert report["adaptive_risk_replay_summary"]["snapshot_record_count"] == 1
    assert report["dashboard_status"]["recommended_review"] is True
    assert report["packet_payloads_stored"] is False
    assert report["automatic_enforcement"] is False


def test_replay_from_missing_snapshots_builds_empty_review_helper():
    report = build_historical_timeline_replay(historical_snapshots=[], generated_at=NOW)

    assert report["snapshot_sequence"]["snapshot_count"] == 0
    assert report["timeline_events"] == []
    assert report["dashboard_status"]["status"] == "empty"
    assert report["offline_review_helpers"][0]["action"] == "provide_historical_snapshots"


def test_replay_from_malformed_snapshots_is_isolated():
    report = build_historical_timeline_replay(
        historical_snapshots=[{"record_type": "wrong", "snapshot_id": "bad"}],
        generated_at=NOW,
    )

    assert report["snapshot_sequence"]["malformed_snapshot_count"] == 1
    assert report["malformed_snapshots"][0]["record_type"] == "malformed_historical_snapshot"
    assert report["malformed_snapshots"][0]["raw_record_stored"] is False


def test_bounded_replay_windows_limit_timeline_events():
    snapshots = [
        _snapshot("2026-03-01T00:00:00+00:00", anomaly_count=1),
        _snapshot("2026-03-02T00:00:00+00:00", anomaly_count=1),
        _snapshot("2026-03-03T00:00:00+00:00", anomaly_count=1),
    ]
    window = build_replay_window_record(max_events=4, generated_at=NOW)
    report = build_historical_timeline_replay(historical_snapshots=snapshots, replay_window=window, generated_at=NOW)

    assert len(report["timeline_events"]) == 4
    assert report["truncated_event_count"] > 0
    assert all(row["bounded_retention_applied"] is True for row in report["timeline_events"])


def test_replay_window_filters_snapshot_sequence():
    snapshots = [
        _snapshot("2026-03-01T00:00:00+00:00"),
        _snapshot("2026-04-01T00:00:00+00:00"),
    ]
    window = build_replay_window_record(
        start_at="2026-04-01T00:00:00+00:00",
        end_at="2026-04-02T00:00:00+00:00",
        max_events=10,
        generated_at=NOW,
    )
    selected, malformed = select_snapshots_for_replay_window(snapshots, replay_window=window)

    assert len(selected) == 1
    assert selected[0]["snapshot_timestamp"] == "2026-04-01T00:00:00+00:00"
    assert malformed == []


def test_topology_timeline_reconstruction_and_offline_review():
    report = build_historical_timeline_replay(
        historical_snapshots=[_snapshot(NOW)],
        topology_evolution_reports=[_topology_report()],
        generated_at=NOW,
    )

    assert report["topology_replay_summary"]["added_relationship_count"] == 1
    assert report["topology_replay_summary"]["removed_relationship_count"] == 1
    assert any(helper["action"] == "review_topology_drift" for helper in report["offline_review_helpers"])


def test_component_replay_summaries_from_provided_reports():
    report = build_historical_timeline_replay(
        historical_snapshots=[_snapshot(NOW)],
        baseline_decay_reports=[{"record_type": "baseline_aging_decay_report", "report_id": "baseline-decay-placeholder", "generated_at": NOW, "export_summary": {"record_counts": {"decay_records": 2}}}],
        service_fingerprint_reports=[{"record_type": "service_behavior_fingerprint_report", "report_id": "service-fingerprint-placeholder", "generated_at": NOW}],
        dns_destination_behavior_reports=[{"record_type": "dns_destination_behavior_report", "report_id": "dns-destination-placeholder", "generated_at": NOW}],
        adaptive_risk_reports=[{"record_type": "adaptive_risk_report", "report_id": "adaptive-risk-placeholder", "generated_at": NOW}],
        generated_at=NOW,
    )

    assert report["baseline_change_replay_summary"]["provided_report_count"] == 1
    assert report["service_fingerprint_replay_summary"]["provided_report_count"] == 1
    assert report["dns_destination_replay_summary"]["provided_report_count"] == 1
    assert report["adaptive_risk_replay_summary"]["provided_report_count"] == 1


def test_serialization_export_summary_is_safe_and_deterministic():
    report = build_historical_timeline_replay(
        historical_snapshots=[_snapshot(NOW, anomaly_count=1, risk_count=1)],
        topology_evolution_reports=[_topology_report()],
        generated_at=NOW,
    )
    left = deterministic_historical_replay_json(report)
    right = deterministic_historical_replay_json(json.loads(left))

    assert left == right
    assert report["export_summary"]["digest"].startswith("sha256:")
    assert "payload" not in report["export_summary"]
    assert report["credentials_stored"] is False
    assert report["raw_browsing_history_stored"] is False
