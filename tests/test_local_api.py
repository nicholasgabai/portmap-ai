from http import HTTPStatus

from core_engine.api import DEFAULT_LOCAL_API_HOST, DEFAULT_LOCAL_API_PORT, create_local_api_app
from core_engine.events import create_event
from core_engine.nodes import NodeRegistry, create_node_capabilities, create_node_identity
from core_engine.storage import LocalStorageRepository, SQLiteStore


def _timestamp():
    return "sample-generated-at"


def test_app_creation_defaults_to_localhost():
    app = create_local_api_app(generated_at=_timestamp)

    assert app.bind_host == DEFAULT_LOCAL_API_HOST
    assert app.port == DEFAULT_LOCAL_API_PORT
    assert app.local_only is True


def test_health_endpoint():
    app = create_local_api_app(generated_at=_timestamp)
    status, payload = app.get("/health")

    assert status == HTTPStatus.OK
    assert payload["status"] == "ok"
    assert payload["bind_host"] == "127.0.0.1"
    assert payload["generated_at"] == "sample-generated-at"
    assert payload["raw_payload_stored"] is False
    assert payload["automatic_changes"] is False
    assert payload["administrator_controlled"] is True


def test_empty_state_responses():
    app = create_local_api_app(generated_at=_timestamp)

    for path in ("/events", "/assets", "/snapshots", "/nodes", "/topology"):
        status, payload = app.get(path)
        assert status == HTTPStatus.OK
        assert payload["status"] == "ok"
        assert payload["count"] == 0
        assert payload["items"] == []
        assert payload["generated_at"] == "sample-generated-at"
        assert payload["raw_payload_stored"] is False
        assert payload["automatic_changes"] is False
        assert payload["administrator_controlled"] is True


def test_events_assets_snapshots_and_topology_from_storage(tmp_path):
    repository = LocalStorageRepository(SQLiteStore(tmp_path / "local-api.db"))
    event = create_event("system_notice", source="api", message="Sample event")
    asset = {"asset_id": "asset-sample", "host": "192.0.2.10", "status": "reachable"}
    snapshot = {"snapshot_id": "snapshot-sample", "label": "sample"}
    edge = {"edge_id": "edge-sample", "src": "asset-sample", "dst": "asset-peer", "protocol": "HTTPS"}
    repository.insert_event(event)
    repository.insert_asset(asset)
    repository.insert_snapshot(snapshot)
    repository.insert_topology_edge(edge)
    app = create_local_api_app(repository=repository, generated_at=_timestamp)

    assert app.get("/events")[1]["items"] == [event.to_dict()]
    assert app.get("/assets")[1]["items"] == [asset]
    assert app.get("/snapshots")[1]["items"] == [snapshot]
    assert app.get("/topology")[1]["items"] == [edge]


def test_sample_provider_endpoints_without_repository():
    app = create_local_api_app(
        events=[{"event_id": "event-sample"}],
        assets=[{"asset_id": "asset-sample"}],
        snapshots=[{"snapshot_id": "snapshot-sample"}],
        topology_edges=[{"edge_id": "edge-sample"}],
        generated_at=_timestamp,
    )

    assert app.get("/events")[1]["items"] == [{"event_id": "event-sample"}]
    assert app.get("/assets")[1]["items"] == [{"asset_id": "asset-sample"}]
    assert app.get("/snapshots")[1]["items"] == [{"snapshot_id": "snapshot-sample"}]
    assert app.get("/topology")[1]["items"] == [{"edge_id": "edge-sample"}]


def test_nodes_endpoint_from_registry():
    registry = NodeRegistry()
    identity = create_node_identity(role="worker", node_id="worker-sample", now="sample-created-at")
    capabilities = create_node_capabilities(
        node_id="worker-sample",
        role="worker",
        platform="Linux",
        architecture="aarch64",
        supported_features=["visibility"],
    )
    registry.register_node(identity, capabilities, now="sample-registered-at")
    registry.update_heartbeat("worker-sample", now="sample-heartbeat-at", health_status="ok")
    app = create_local_api_app(node_registry=registry, generated_at=_timestamp)

    status, payload = app.get("/nodes")

    assert status == HTTPStatus.OK
    assert payload["count"] == 1
    assert payload["items"][0]["node_id"] == "worker-sample"
    assert payload["items"][0]["state"] == "online"


def test_localhost_default_configuration_behavior():
    app = create_local_api_app()
    non_local = create_local_api_app(bind_host="0.0.0.0")

    assert app.local_only is True
    assert non_local.local_only is False


def test_read_only_methods_and_not_found():
    app = create_local_api_app(generated_at=_timestamp)

    status, payload = app.handle_request("POST", "/events")
    assert status == HTTPStatus.METHOD_NOT_ALLOWED
    assert payload["status"] == "error"
    assert payload["automatic_changes"] is False

    status, payload = app.get("/missing")
    assert status == HTTPStatus.NOT_FOUND
    assert payload["error"] == "not_found"
