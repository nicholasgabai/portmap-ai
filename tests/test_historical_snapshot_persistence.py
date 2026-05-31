import json

import pytest

from core_engine.history import (
    HistoricalSnapshotError,
    build_bounded_snapshot_store,
    build_export_safe_snapshot_summary,
    build_historical_snapshot,
    build_snapshot_store_write_plan,
    deserialize_historical_snapshot,
    read_historical_snapshot,
    rotate_historical_snapshots,
    serialize_historical_snapshot,
    write_historical_snapshot,
)
from core_engine.telemetry.behavior_summary import build_behavioral_intelligence_summary


GENERATED_AT = "2026-01-01T00:00:00+00:00"


def _behavior_summary(*, generated_at=GENERATED_AT):
    baseline_report = {
        "record_type": "behavior_baseline_report",
        "summary": {
            "baseline_entry_count": 3,
            "stable_behavior_count": 2,
            "novel_behavior_count": 1,
            "decaying_inactive_count": 0,
            "average_confidence": 0.82,
            "by_behavior_state": {"newly_observed_behavior": 1, "stable_behavior": 2},
        },
        "dashboard_status": {
            "metrics": {
                "baseline_entry_count": 3,
                "stable_behavior_count": 2,
                "novel_behavior_count": 1,
                "decaying_inactive_count": 0,
                "average_confidence": 0.82,
            }
        },
    }
    anomaly_report = {
        "record_type": "temporal_anomaly_report",
        "summary": {
            "anomaly_count": 1,
            "burst_count": 1,
            "rare_service_timing_count": 0,
            "volume_drift_count": 0,
            "novel_behavior_count": 1,
            "average_confidence": 0.74,
            "by_label": {"burst_detected": 1},
        },
        "dashboard_status": {
            "metrics": {
                "anomaly_count": 1,
                "burst_count": 1,
                "rare_service_timing_count": 0,
                "volume_drift_count": 0,
                "novel_behavior_count": 1,
                "average_confidence": 0.74,
            }
        },
    }
    return build_behavioral_intelligence_summary(
        behavior_baseline_report=baseline_report,
        temporal_anomaly_report=anomaly_report,
        generated_at=generated_at,
    )


def _snapshot(ts=GENERATED_AT, source_label="behavior-summary"):
    return build_historical_snapshot(
        _behavior_summary(generated_at=ts),
        source_label=source_label,
        source_refs=["fixture:behavior-summary"],
        generated_at=ts,
        snapshot_label="sanitized behavior snapshot",
    )


def test_historical_snapshot_creation_is_metadata_only_and_export_safe():
    snapshot = _snapshot()

    assert snapshot["record_type"] == "historical_behavior_snapshot"
    assert snapshot["snapshot_id"].startswith("historical-snapshot-")
    assert snapshot["snapshot_timestamp"] == GENERATED_AT
    assert snapshot["source_label"] == "behavior-summary"
    assert snapshot["metadata_summary"]["record_count"] == 4
    assert snapshot["metadata_summary"]["component_count"] == 5
    assert snapshot["payload"]["component_rollups"]["baselines"]["record_count"] == 3
    assert snapshot["raw_payload_stored"] is False
    assert snapshot["packet_payloads_stored"] is False
    assert snapshot["credentials_stored"] is False
    assert snapshot["raw_logs_stored"] is False
    assert snapshot["raw_browsing_history_stored"] is False
    assert snapshot["external_services_used"] is False
    assert snapshot["automatic_enforcement"] is False
    assert snapshot["dashboard_status"]["metrics"]["record_count"] == 4
    assert snapshot["export_summary"]["digest"].startswith("sha256:")


def test_snapshot_serialization_and_deserialization_are_deterministic():
    snapshot = _snapshot()

    left = serialize_historical_snapshot(snapshot)
    right = serialize_historical_snapshot(json.loads(left))
    loaded = deserialize_historical_snapshot(left)

    assert left == right
    assert loaded["snapshot_id"] == snapshot["snapshot_id"]
    assert loaded["metadata_summary"]["metadata_digest"] == snapshot["metadata_summary"]["metadata_digest"]


def test_malformed_snapshot_handling_is_structured():
    malformed = deserialize_historical_snapshot("{bad json")
    wrong_type = deserialize_historical_snapshot({"record_type": "wrong"})

    assert malformed["record_type"] == "malformed_historical_snapshot"
    assert malformed["valid"] is False
    assert malformed["raw_record_stored"] is False
    assert wrong_type["status"] == "malformed"
    assert any("record_type" in error for error in wrong_type["errors"])


def test_bounded_retention_and_rotation_keep_newest_snapshots():
    snapshots = [
        _snapshot("2026-01-01T00:00:00+00:00", "behavior-a"),
        _snapshot("2026-01-02T00:00:00+00:00", "behavior-b"),
        _snapshot("2026-01-03T00:00:00+00:00", "behavior-c"),
    ]

    rotation = rotate_historical_snapshots(snapshots, max_snapshots=2)
    store = build_bounded_snapshot_store(snapshots, max_snapshots=2, generated_at="2026-01-04T00:00:00+00:00")

    assert rotation["retained_count"] == 2
    assert rotation["dropped_count"] == 1
    assert snapshots[0]["snapshot_id"] in rotation["dropped_snapshot_ids"]
    assert store["summary"]["snapshot_count"] == 2
    assert store["rotation"]["delete_performed"] is False
    assert all(row["raw_payload_stored"] is False for row in store["snapshots"])


def test_write_plan_is_dry_run_and_write_read_use_temp_directory(tmp_path):
    snapshot = _snapshot()
    plan = build_snapshot_store_write_plan(tmp_path, snapshot)

    assert plan["dry_run"] is True
    assert plan["write_performed"] is False
    assert plan["status"] == "ready"

    result = write_historical_snapshot(tmp_path, snapshot)
    loaded = read_historical_snapshot(tmp_path / result["target_name"])

    assert result["status"] == "written"
    assert result["target_name"].endswith(".json")
    assert loaded["snapshot_id"] == snapshot["snapshot_id"]
    assert loaded["payload"]["privacy_safety_summary"]["credentials_stored"] is False


def test_invalid_snapshot_write_is_blocked(tmp_path):
    with pytest.raises(HistoricalSnapshotError):
        write_historical_snapshot(tmp_path, {"record_type": "wrong"})


def test_export_safe_summary_omits_snapshot_payload():
    snapshot = _snapshot()
    export_summary = build_export_safe_snapshot_summary(snapshot)

    assert "payload" not in export_summary
    assert export_summary["record_counts"]["behavior_records"] == 4
    assert export_summary["raw_payload_stored"] is False
