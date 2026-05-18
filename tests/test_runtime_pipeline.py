import json
import re

from core_engine.policy.models import create_policy
from core_engine.runtime.pipeline import run_runtime_pipeline
from core_engine.runtime.workflows import run_visibility_runtime_workflow
from core_engine.storage.repositories import LocalStorageRepository
from core_engine.storage.sqlite_store import SQLiteStore
from core_engine.topology.snapshots import build_topology_snapshot


PRIVATE_IDENTIFIER_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


def _assets():
    return [
        {"asset_id": "asset-alpha", "label": "Asset Alpha", "category": "workload", "confidence": 0.94},
        {"asset_id": "asset-beta", "label": "Asset Beta", "category": "data-service", "confidence": 0.88},
    ]


def _services():
    return [
        {"service_id": "svc-alpha-ssh", "asset_id": "asset-alpha", "service": "ssh", "port": 22, "state": "open", "confidence": 0.9},
        {"service_id": "svc-beta-db", "asset_id": "asset-beta", "service": "postgresql", "port": 5432, "state": "open", "confidence": 0.9},
    ]


def _baseline_snapshot():
    return build_topology_snapshot(
        assets=_assets()[:1],
        services=_services()[:1],
        label="baseline",
        observed_at="2026-01-01T00:00:00+00:00",
    )


def _current_snapshot():
    return build_topology_snapshot(
        assets=_assets(),
        services=_services(),
        label="current",
        observed_at="2026-01-02T00:00:00+00:00",
    )


def test_runtime_pipeline_dry_run_builds_visibility_snapshot_and_events():
    result = run_runtime_pipeline(
        assets=_assets(),
        services=_services(),
        dry_run=True,
        generated_at="2026-01-03T00:00:00+00:00",
    )

    assert result["status"] == "ok"
    assert result["dry_run"] is True
    assert result["summary"]["event_count"] == 2
    assert result["summary"]["snapshot_count"] == 1
    assert result["summary"]["finding_count"] >= 2
    assert result["summary"]["storage_write_count"] == 0
    assert result["topology_snapshot"]["snapshot_type"] == "topology_state"
    assert result["automatic_changes"] is False
    assert result["administrator_controlled"] is True
    assert result["raw_payload_stored"] is False


def test_runtime_pipeline_compares_snapshots_and_builds_ready_records():
    result = run_runtime_pipeline(
        baseline_snapshot=_baseline_snapshot(),
        current_snapshot=_current_snapshot(),
        generated_at="2026-01-03T00:00:00+00:00",
    )

    assert result["status"] == "ok"
    assert result["drift_report"]["drift_count"] > 0
    assert result["summary"]["timeline_entry_count"] > 0
    assert result["summary"]["correlation_record_count"] > 0
    assert result["storage_records"][0]["record_type"] == "topology_snapshot_drift"
    assert any(event["event_type"] in {"policy_review_required", "system_notice"} for event in result["events"])


def test_runtime_pipeline_generates_policy_review_drafts():
    policy = create_policy(
        name="Sample Review Policy",
        description="Require review for medium or higher advisory findings.",
        severity_threshold="medium",
        categories=[],
        now="2026-01-03T00:00:00+00:00",
    )

    result = run_runtime_pipeline(
        assets=_assets(),
        services=_services(),
        policies=[policy],
        generated_at="2026-01-03T00:00:00+00:00",
    )

    assert result["summary"]["review_draft_count"] >= 1
    assert all(review["status"] == "open" for review in result["review_drafts"])
    assert all(review["automatic_changes"] is False for review in result["review_drafts"])


def test_runtime_pipeline_dry_run_does_not_write_to_repository(tmp_path):
    repository = LocalStorageRepository(SQLiteStore(tmp_path / "runtime.db"))

    result = run_runtime_pipeline(
        assets=_assets(),
        services=_services(),
        repository=repository,
        dry_run=True,
        write_local=True,
        generated_at="2026-01-03T00:00:00+00:00",
    )

    assert result["summary"]["storage_write_count"] == 0
    assert repository.list_events() == []
    assert repository.list_snapshots() == []
    assert repository.list_findings() == []


def test_runtime_pipeline_explicit_write_mode_uses_existing_repository(tmp_path):
    repository = LocalStorageRepository(SQLiteStore(tmp_path / "runtime.db"))

    result = run_runtime_pipeline(
        assets=_assets(),
        services=_services(),
        repository=repository,
        dry_run=False,
        write_local=True,
        generated_at="2026-01-03T00:00:00+00:00",
    )

    assert result["status"] == "ok"
    assert result["summary"]["storage_write_count"] > 0
    assert len(repository.list_events()) == result["summary"]["event_count"]
    assert len(repository.list_snapshots()) == 1
    assert len(repository.list_findings()) == result["summary"]["finding_count"]


def test_runtime_pipeline_isolates_step_failure():
    result = run_runtime_pipeline(
        assets=_assets(),
        services=_services(),
        dry_run=False,
        write_local=True,
        generated_at="2026-01-03T00:00:00+00:00",
    )

    assert result["status"] == "partial"
    assert result["summary"]["failed_step_count"] == 1
    assert result["step_results"][-1]["step"] == "storage"
    assert "LocalStorageRepository" in result["step_results"][-1]["error"]
    assert result["summary"]["event_count"] == 2


def test_visibility_runtime_workflow_wrapper_delegates_to_pipeline():
    result = run_visibility_runtime_workflow(
        assets=_assets(),
        services=_services(),
        generated_at="2026-01-03T00:00:00+00:00",
    )

    assert result["status"] == "ok"
    assert result["summary"]["snapshot_count"] == 1
    assert result["summary"]["event_count"] == 2


def test_runtime_pipeline_output_does_not_contain_private_identifiers():
    result = run_runtime_pipeline(
        assets=_assets(),
        services=_services(),
        baseline_snapshot=_baseline_snapshot(),
        current_snapshot=_current_snapshot(),
        generated_at="2026-01-03T00:00:00+00:00",
    )
    payload = json.dumps(result, sort_keys=True)

    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(payload)
