import json

import pytest

from core_engine.history import (
    AgingPolicyError,
    apply_confidence_decay,
    build_aging_policy_record,
    build_baseline_aging_decay_report,
    deterministic_baseline_decay_json,
    get_safe_default_aging_profile,
    score_baseline_maturity,
)
from core_engine.history.snapshots import build_historical_snapshot
from core_engine.telemetry.behavior_summary import build_behavioral_intelligence_summary


NOW = "2026-02-01T00:00:00+00:00"


def _baseline_entry(**overrides):
    row = {
        "record_type": "behavior_baseline_entry",
        "baseline_id": "behavior-baseline-placeholder",
        "category": "service",
        "baseline_key": "service-placeholder",
        "display_label": "service-placeholder",
        "first_seen": "2025-12-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:00:00+00:00",
        "observation_count": 8,
        "rolling_frequency": 0.25,
        "rolling_average_score": 0.8,
        "stable_behavior": True,
        "novelty": False,
        "confidence": 0.9,
        "behavior_state": "stable",
        "source_refs": ["fixture:baseline"],
    }
    row.update(overrides)
    return row


def _fingerprint_profile(**overrides):
    row = {
        "record_type": "service_fingerprint_profile",
        "profile_id": "service-fingerprint-profile-placeholder",
        "fingerprint_key": "fingerprint-key-placeholder",
        "display_label": "process-placeholder/tcp/443",
        "first_seen": "2025-12-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:00:00+00:00",
        "observation_count": 5,
        "recurrence_count": 5,
        "behavior_state": "stable_service_behavior",
        "stable_service_profile": True,
        "confidence": 0.82,
        "source_refs": ["fixture:fingerprint"],
    }
    row.update(overrides)
    return row


def _destination_profile(**overrides):
    row = {
        "record_type": "dns_destination_behavior_profile",
        "profile_id": "dns-destination-profile-placeholder",
        "destination_key": "destination-key-placeholder",
        "domain_summary": {
            "display_domain": "<redacted-domain>",
            "raw_domain_stored": False,
        },
        "first_seen": "2025-11-01T00:00:00+00:00",
        "last_seen": "2025-11-20T00:00:00+00:00",
        "observation_count": 6,
        "behavior_state": "dormant_destination_returned",
        "confidence": 0.7,
        "source_refs": ["fixture:destination"],
    }
    row.update(overrides)
    return row


def _snapshot():
    summary = build_behavioral_intelligence_summary(
        behavior_baseline_report={
            "record_type": "behavior_baseline_report",
            "summary": {
                "baseline_entry_count": 1,
                "stable_behavior_count": 1,
                "novel_behavior_count": 0,
                "decaying_inactive_count": 0,
                "average_confidence": 0.9,
            },
            "dashboard_status": {"metrics": {"baseline_entry_count": 1, "average_confidence": 0.9}},
        },
        generated_at=NOW,
    )
    return build_historical_snapshot(summary, generated_at=NOW)


def test_safe_default_aging_profile_is_deterministic_and_safe():
    left = get_safe_default_aging_profile(generated_at=NOW)
    right = get_safe_default_aging_profile(generated_at=NOW)

    assert left == right
    assert left["record_type"] == "baseline_aging_policy"
    assert left["metadata_only"] is True
    assert left["automatic_enforcement"] is False


def test_invalid_aging_policy_is_rejected():
    with pytest.raises(AgingPolicyError):
        build_aging_policy_record(inactive_after_days=10, stale_after_days=5, generated_at=NOW)


def test_confidence_decay_over_time_and_inactive_behavior_fading():
    policy = build_aging_policy_record(inactive_after_days=7, stale_after_days=21, dormant_after_days=45, decay_rate=0.5, generated_at=NOW)
    report = build_baseline_aging_decay_report(
        baseline_entries=[
            _baseline_entry(last_seen="2026-01-20T00:00:00+00:00", confidence=0.8),
            _baseline_entry(baseline_id="behavior-baseline-stale", last_seen="2025-12-20T00:00:00+00:00", confidence=0.8),
        ],
        aging_policy=policy,
        generated_at=NOW,
    )

    current = next(row for row in report["records"] if row["source_id"] == "behavior-baseline-placeholder")
    stale = next(row for row in report["records"] if row["source_id"] == "behavior-baseline-stale")

    assert current["decay_state"] == "inactive"
    assert current["decayed_confidence"] < current["original_confidence"]
    assert stale["decay_state"] == "stale"
    assert stale["decayed_confidence"] == 0.4
    assert report["summary"]["inactive_count"] == 2
    assert report["summary"]["stale_count"] == 1


def test_stale_fingerprint_and_dormant_destination_handling():
    policy = build_aging_policy_record(inactive_after_days=7, stale_after_days=21, dormant_after_days=45, decay_rate=0.5, generated_at=NOW)
    report = build_baseline_aging_decay_report(
        service_fingerprint_profiles=[_fingerprint_profile()],
        destination_profiles=[_destination_profile()],
        aging_policy=policy,
        generated_at=NOW,
    )

    fingerprint = next(row for row in report["records"] if row["record_kind"] == "service_fingerprint")
    destination = next(row for row in report["records"] if row["record_kind"] == "destination_behavior")

    assert fingerprint["decay_state"] == "stale"
    assert fingerprint["stale_behavior"] is True
    assert destination["decay_state"] == "dormant"
    assert destination["dormant_behavior"] is True
    assert report["dashboard_status"]["recommended_review"] is True


def test_baseline_maturity_scoring_uses_observations_and_age():
    policy = build_aging_policy_record(mature_after_observations=5, mature_after_days=20, generated_at=NOW)
    mature = score_baseline_maturity(_baseline_entry(), policy=policy, generated_at=NOW)
    immature = score_baseline_maturity(
        _baseline_entry(first_seen="2026-01-31T00:00:00+00:00", observation_count=1, stable_behavior=False),
        policy=policy,
        generated_at=NOW,
    )

    assert mature >= 0.75
    assert immature < mature


def test_empty_and_malformed_inputs_are_handled_safely():
    empty = build_baseline_aging_decay_report(generated_at=NOW)
    malformed = build_baseline_aging_decay_report(baseline_entries=[{"baseline_id": "missing-type"}, "bad"], generated_at=NOW)

    assert empty["summary"]["record_count"] == 0
    assert empty["summary"]["average_decayed_confidence"] == 0.0
    assert malformed["summary"]["malformed_record_count"] == 2
    assert all(row["raw_record_stored"] is False for row in malformed["malformed_records"])


def test_serialization_export_and_snapshot_context_are_safe_and_deterministic():
    report = build_baseline_aging_decay_report(
        baseline_entries=[_baseline_entry()],
        historical_snapshots=[_snapshot()],
        generated_at=NOW,
    )
    left = deterministic_baseline_decay_json(report)
    right = deterministic_baseline_decay_json(json.loads(left))

    assert left == right
    assert report["export_summary"]["digest"].startswith("sha256:")
    assert report["summary"]["snapshot_context_count"] == 1
    assert report["raw_payload_stored"] is False
    assert report["credentials_stored"] is False
    assert report["automatic_enforcement"] is False
    assert "api_status" in report


def test_apply_confidence_decay_clamps_to_policy_minimum():
    policy = build_aging_policy_record(minimum_confidence=0.2, generated_at=NOW)

    assert apply_confidence_decay(0.1, age_days=999, policy=policy, dormant=True) == 0.2
