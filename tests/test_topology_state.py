import json
import re

from core_engine.storage.repositories import LocalStorageRepository
from core_engine.storage.sqlite_store import SQLiteStore
from core_engine.topology.import_export import (
    build_topology_export_bundle,
    export_topology_bundle,
    export_topology_snapshot,
    import_topology_snapshot,
    load_topology_snapshot,
    write_topology_snapshot,
)
from core_engine.topology.snapshots import (
    build_topology_snapshot,
    summarize_topology_snapshot,
    topology_snapshot_to_storage_record,
    validate_topology_snapshot,
)
from core_engine.topology.state import (
    build_topology_state,
    list_persisted_topology_snapshots,
    persist_topology_snapshot,
    summarize_topology_history,
)


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
        {"asset_id": "asset-alpha", "label": "Asset Alpha", "category": "workload", "confidence": 0.9},
        {"asset_id": "asset-beta", "label": "Asset Beta", "category": "service", "confidence": 0.8},
    ]


def _services():
    return [
        {"service_id": "service-alpha-web", "asset_id": "asset-alpha", "service": "http", "port": 8080},
        {"service_id": "service-beta-db", "asset_id": "asset-beta", "service": "postgresql", "port": 5432},
    ]


def _edges():
    return [
        {
            "edge_id": "edge-alpha-beta",
            "source_asset": "asset-alpha",
            "target_asset": "asset-beta",
            "relationship_type": "service_dependency",
            "service_label": "postgresql",
            "observation_count": 2,
            "confidence": 0.85,
        }
    ]


def _findings():
    return [
        {
            "finding_id": "finding-review-sample",
            "finding_type": "sample_review",
            "severity": "medium",
            "summary": "Sample review finding.",
            "source_refs": ["snapshot:sample"],
        }
    ]


def test_build_topology_snapshot_from_existing_records():
    snapshot = build_topology_snapshot(
        assets=_assets(),
        services=_services(),
        topology_edges=_edges(),
        findings=_findings(),
        label="sample-topology",
        observed_at="2026-01-01T00:00:00+00:00",
    )

    assert snapshot["ok"] is True
    assert snapshot["snapshot_type"] == "topology_state"
    assert snapshot["summary"]["node_count"] == 2
    assert snapshot["summary"]["edge_count"] == 1
    assert snapshot["summary"]["service_count"] == 2
    assert snapshot["summary"]["finding_count"] == 1
    assert snapshot["summary"]["recommended_review"] is True
    assert snapshot["raw_payload_stored"] is False
    assert snapshot["automatic_changes"] is False
    assert snapshot["administrator_controlled"] is True


def test_topology_snapshot_summary_and_storage_record():
    snapshot = build_topology_snapshot(
        assets=_assets(),
        services=_services(),
        topology_edges=_edges(),
        label="sample-topology",
        observed_at="2026-01-01T00:00:00+00:00",
    )
    summary = summarize_topology_snapshot(snapshot)
    storage_record = topology_snapshot_to_storage_record(snapshot)

    assert summary["snapshot_id"] == snapshot["snapshot_id"]
    assert summary["node_count"] == 2
    assert storage_record["snapshot_type"] == "topology_state"
    assert storage_record["payload"]["snapshot_id"] == snapshot["snapshot_id"]
    assert storage_record["raw_payload_stored"] is False


def test_validate_topology_snapshot_rejects_malformed_record():
    valid = build_topology_snapshot(assets=_assets(), observed_at="2026-01-01T00:00:00+00:00")
    invalid = {"snapshot_type": "topology_state", "snapshot_id": "sample"}

    assert validate_topology_snapshot(valid)["ok"] is True
    result = validate_topology_snapshot(invalid)
    assert result["ok"] is False
    assert "topology must be an object" in result["errors"]


def test_topology_state_and_history_are_deterministic():
    first = build_topology_snapshot(
        assets=_assets()[:1],
        services=_services()[:1],
        topology_edges=[],
        label="baseline",
        observed_at="2026-01-01T00:00:00+00:00",
    )
    second = build_topology_snapshot(
        assets=_assets(),
        services=_services(),
        topology_edges=_edges(),
        label="current",
        observed_at="2026-01-02T00:00:00+00:00",
    )

    history = summarize_topology_history([second, first])
    state = build_topology_state([second, first])

    assert history["snapshot_count"] == 2
    assert history["first_observed_at"] == "2026-01-01T00:00:00+00:00"
    assert history["last_observed_at"] == "2026-01-02T00:00:00+00:00"
    assert history["max_node_count"] == 2
    assert state["current_snapshot_id"] == second["snapshot_id"]
    assert state["history_summary"] == history


def test_persist_topology_snapshot_reuses_existing_snapshot_repository(tmp_path):
    store = SQLiteStore(tmp_path / "topology.db")
    repository = LocalStorageRepository(store)
    snapshot = build_topology_snapshot(
        assets=_assets(),
        services=_services(),
        topology_edges=_edges(),
        label="persisted",
        observed_at="2026-01-01T00:00:00+00:00",
    )

    row_id = persist_topology_snapshot(repository, snapshot)
    rows = list_persisted_topology_snapshots(repository)

    assert row_id == 1
    assert len(rows) == 1
    assert rows[0]["snapshot_id"] == snapshot["snapshot_id"]
    assert rows[0]["snapshot_type"] == "topology_state"


def test_import_export_topology_snapshot_round_trip(tmp_path):
    snapshot = build_topology_snapshot(
        assets=_assets(),
        services=_services(),
        topology_edges=_edges(),
        label="exportable",
        observed_at="2026-01-01T00:00:00+00:00",
    )

    exported = export_topology_snapshot(snapshot)
    imported = import_topology_snapshot(exported)
    write_result = write_topology_snapshot(tmp_path / "snapshot.json", snapshot)
    loaded = load_topology_snapshot(tmp_path / "snapshot.json")

    assert imported == snapshot
    assert loaded == snapshot
    assert write_result["status"] == "written"
    assert write_result["path_stored"] is False


def test_topology_export_bundle_has_manifest_and_digest():
    snapshot = build_topology_snapshot(
        assets=_assets(),
        services=_services(),
        topology_edges=_edges(),
        label="bundle",
        observed_at="2026-01-01T00:00:00+00:00",
    )
    bundle = build_topology_export_bundle([snapshot], label="sample-bundle", generated_at="2026-01-03T00:00:00+00:00")
    text = export_topology_bundle(bundle)

    assert bundle["manifest"]["bundle_type"] == "topology_state_export"
    assert bundle["manifest"]["snapshot_count"] == 1
    assert bundle["manifest"]["digest"].startswith("sha256:")
    assert json.loads(text)["manifest"]["snapshot_ids"] == [snapshot["snapshot_id"]]
    assert bundle["raw_payload_stored"] is False


def test_topology_state_outputs_do_not_contain_private_identifiers():
    snapshot = build_topology_snapshot(
        assets=_assets(),
        services=_services(),
        topology_edges=_edges(),
        findings=_findings(),
        label="sample-topology",
        observed_at="2026-01-01T00:00:00+00:00",
    )
    bundle = build_topology_export_bundle([snapshot], generated_at="2026-01-03T00:00:00+00:00")
    payload = json.dumps([snapshot, build_topology_state([snapshot]), bundle], sort_keys=True)

    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(payload)
