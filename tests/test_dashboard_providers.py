import json
import re

from core_engine.policy import PersistentReviewStore, build_review_record, create_policy
from core_engine.runtime.runtime_state import RuntimeState
from core_engine.storage.repositories import LocalStorageRepository
from core_engine.storage.sqlite_store import SQLiteStore
from core_engine.topology.snapshots import build_topology_snapshot
from gui.web import (
    StaticDashboardProvider,
    StorageDashboardProvider,
    build_dashboard_view,
    diagnostic_summary_response,
    render_dashboard_sections,
    render_dashboard_view,
    review_summary_response,
    runtime_state_response,
    sample_dashboard_api_data,
    snapshot_summary_response,
    topology_summary_response,
)


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
]


def _repository(tmp_path):
    return LocalStorageRepository(SQLiteStore(tmp_path / "dashboard.db"))


def _snapshot():
    return build_topology_snapshot(
        assets=[
            {"asset_id": "asset-alpha", "label": "Asset Alpha", "category": "workload", "confidence": 0.9},
            {"asset_id": "asset-beta", "label": "Asset Beta", "category": "service", "confidence": 0.9},
        ],
        services=[{"asset_id": "asset-alpha", "service": "https", "port": 443}],
        topology_edges=[
            {
                "edge_id": "edge-alpha-beta",
                "source_asset": "asset-alpha",
                "target_asset": "asset-beta",
                "relationship_type": "service_dependency",
                "service_label": "https",
            }
        ],
        label="dashboard-snapshot",
        observed_at="2026-01-01T00:00:00+00:00",
    )


def _review_store(repository):
    store = PersistentReviewStore(repository)
    policy = create_policy(
        policy_id="policy-sample",
        name="Sample Review Policy",
        description="Review advisory findings.",
        now="2026-01-01T00:00:00+00:00",
    )
    review = build_review_record(
        policy=policy,
        source_ref="finding:finding-sample",
        category="policy_review_required",
        severity="high",
        title="Sample Review",
        summary="Sample review summary.",
        now="2026-01-01T00:00:00+00:00",
    )
    store.add_review(review)
    return store


def test_static_provider_supports_api_compatible_dictionaries():
    provider = StaticDashboardProvider(sample_dashboard_api_data(), generated_at=lambda: "2026-01-01T00:00:00+00:00")

    status, response = provider.get("/assets")
    model = build_dashboard_view(provider)

    assert status == 200
    assert response["count"] == 2
    assert model["metrics"]["asset_count"] == 2
    assert model["metrics"]["operator_review_count"] == 2
    assert model["metrics"]["diagnostic_count"] == 1
    assert model["empty_state"] is False


def test_storage_provider_reads_existing_repositories(tmp_path):
    repository = _repository(tmp_path)
    repository.insert_asset({"asset_id": "asset-alpha", "status": "reachable"})
    repository.insert_service({"service_id": "svc-alpha-https", "asset_id": "asset-alpha", "service": "https", "port": 443})
    repository.insert_snapshot(_snapshot())
    review_store = _review_store(repository)
    state = RuntimeState()
    state.mark_started(10.0)

    provider = StorageDashboardProvider(
        repository,
        runtime_state=state,
        review_store=review_store,
        diagnostics=[{"diagnostic_id": "diag-sample", "diagnostic_type": "schema_validation", "status": "ok"}],
        nodes=[{"node_id": "node-sample", "state": "online"}],
        generated_at=lambda: "2026-01-02T00:00:00+00:00",
        now_seconds=lambda: 12.0,
    )
    model = build_dashboard_view(provider)

    assert model["metrics"]["asset_count"] == 1
    assert model["metrics"]["snapshot_count"] == 1
    assert model["metrics"]["node_count"] == 1
    assert model["metrics"]["topology_node_count"] == 2
    assert model["metrics"]["topology_edge_count"] == 1
    assert model["metrics"]["operator_review_count"] == 1
    assert model["metrics"]["diagnostic_count"] == 1


def test_runtime_snapshot_topology_review_and_diagnostic_summary_helpers(tmp_path):
    repository = _repository(tmp_path)
    review_store = _review_store(repository)
    state = RuntimeState()
    state.mark_started(4.0)

    runtime = runtime_state_response(state, generated_at="2026-01-01T00:00:00+00:00", now_seconds=lambda: 9.0)
    snapshots = snapshot_summary_response([_snapshot()], generated_at="2026-01-01T00:00:00+00:00")
    topology = topology_summary_response(snapshots=[_snapshot()], generated_at="2026-01-01T00:00:00+00:00")
    reviews = review_summary_response(review_store, generated_at="2026-01-01T00:00:00+00:00")
    diagnostics = diagnostic_summary_response(
        [{"diagnostic_id": "diag-sample", "diagnostic_type": "stream_metadata", "status": "ok", "severity": "info"}],
        generated_at="2026-01-01T00:00:00+00:00",
    )

    assert runtime["runtime"]["uptime_seconds"] == 5.0
    assert snapshots["summary"]["snapshot_count"] == 1
    assert topology["summary"]["node_count"] == 2
    assert reviews["summary"]["review_count"] == 1
    assert diagnostics["summary"]["by_type"] == {"stream_metadata": 1}
    assert diagnostics["raw_payload_stored"] is False


def test_empty_state_dashboard_view_and_rendering():
    model = build_dashboard_view()
    html = render_dashboard_view()
    sections = render_dashboard_sections(model)

    assert model["empty_state"] is True
    assert model["metrics"]["asset_count"] == 0
    assert "PortMap-AI Local Dashboard" in html
    assert "Operator Reviews" in sections
    assert model["automatic_changes"] is False


def test_dashboard_provider_output_has_no_private_identifiers(tmp_path):
    repository = _repository(tmp_path)
    repository.insert_snapshot(_snapshot())
    provider = StorageDashboardProvider(
        repository,
        diagnostics=[{"diagnostic_id": "diag-sample", "diagnostic_type": "schema_validation", "status": "ok"}],
        generated_at=lambda: "2026-01-02T00:00:00+00:00",
    )
    payload = json.dumps(build_dashboard_view(provider), sort_keys=True) + render_dashboard_view(provider)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
