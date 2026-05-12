import sqlite3

import pytest

from core_engine.events import create_event
from core_engine.storage import LocalStorageRepository, SCHEMA_VERSION, SQLiteStore, StorageError


def _repository(tmp_path):
    return LocalStorageRepository(SQLiteStore(tmp_path / "nested" / "visibility.db"))


def test_database_initialization_creates_schema_and_parent_directory(tmp_path):
    db_path = tmp_path / "missing" / "parents" / "portmap.db"
    store = SQLiteStore(db_path)

    store.initialize_schema()

    assert db_path.exists()
    assert store.schema_versions() == [SCHEMA_VERSION]
    table_rows = store.query("SELECT name FROM sqlite_master WHERE type = 'table'")
    table_names = {row["name"] for row in table_rows}
    assert table_names >= {"events", "snapshots", "assets", "services", "topology_edges", "findings", "schema_version"}


def test_event_insert_and_list_round_trip(tmp_path):
    repository = _repository(tmp_path)
    event = create_event(
        "asset_observed",
        severity="low",
        source="visibility",
        message="Sample asset observed",
        asset_ref="asset-sample",
        metadata={"sample": True},
    )

    row_id = repository.insert_event(event)
    rows = repository.list_events()

    assert row_id == 1
    assert rows == [event.to_dict()]


def test_snapshot_insert_and_list_round_trip(tmp_path):
    repository = _repository(tmp_path)
    snapshot = {
        "snapshot_id": "snapshot-sample",
        "label": "sample-baseline",
        "assets": [{"asset_id": "asset-sample"}],
        "automatic_changes": False,
    }

    repository.insert_snapshot(snapshot)

    assert repository.list_snapshots() == [snapshot]


def test_asset_insert_and_list_round_trip(tmp_path):
    repository = _repository(tmp_path)
    asset = {
        "asset_id": "asset-sample",
        "host": "192.0.2.10",
        "status": "reachable",
        "metadata": {"source": "sample"},
    }

    repository.insert_asset(asset)

    assert repository.list_assets() == [asset]


def test_service_insert_and_list_round_trip(tmp_path):
    repository = _repository(tmp_path)
    service = {
        "service_id": "service-sample",
        "target": "192.0.2.10",
        "port": 8443,
        "service": "HTTPS",
        "metadata": {"encrypted": True},
    }

    repository.insert_service(service)

    assert repository.list_services() == [service]


def test_topology_edge_insert_and_list_round_trip(tmp_path):
    repository = _repository(tmp_path)
    edge = {
        "edge_id": "edge-sample",
        "src": "asset-sample-a",
        "dst": "asset-sample-b",
        "protocol": "HTTPS",
        "metadata": {"direction": "outbound"},
    }

    repository.insert_topology_edge(edge)

    assert repository.list_topology_edges() == [edge]


def test_finding_insert_and_list_round_trip(tmp_path):
    repository = _repository(tmp_path)
    finding = {
        "finding_id": "finding-sample",
        "finding_type": "baseline_delta_detected",
        "severity": "medium",
        "message": "Sample advisory finding",
        "automatic_changes": False,
    }

    repository.insert_finding(finding)

    assert repository.list_findings() == [finding]


def test_generated_ids_and_json_payload_round_trip(tmp_path):
    repository = _repository(tmp_path)
    asset = {"host": "198.51.100.20", "status": "unknown", "metadata": {"nested": {"ok": True}}}

    repository.insert_asset(asset)
    stored = repository.list_assets()[0]

    assert stored["asset_id"].startswith("asset-")
    assert stored["metadata"]["nested"]["ok"] is True


def test_non_json_payload_is_rejected(tmp_path):
    repository = _repository(tmp_path)

    with pytest.raises(StorageError):
        repository.insert_finding({"finding_id": "finding-bad", "metadata": {"bad": object()}})


def test_local_only_behavior_and_no_network_transport(tmp_path):
    store = SQLiteStore(tmp_path / "visibility.db")
    repository = LocalStorageRepository(store)

    assert store.local_only is True
    assert repository.local_only is True
    assert not hasattr(store, "send")
    assert not hasattr(repository, "sync")


def test_duplicate_ids_raise_storage_error(tmp_path):
    repository = _repository(tmp_path)
    asset = {"asset_id": "asset-sample", "host": "203.0.113.10"}

    repository.insert_asset(asset)
    with pytest.raises(StorageError):
        repository.insert_asset(asset)


def test_schema_is_sqlite_compatible(tmp_path):
    repository = _repository(tmp_path)

    repository.insert_snapshot({"snapshot_id": "snapshot-sample"})
    with sqlite3.connect(tmp_path / "nested" / "visibility.db") as connection:
        count = connection.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]

    assert count == 1
