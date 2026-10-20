import json
from pathlib import Path

import pytest

from core_engine import orchestrator_service
from core_engine.orchestrator_service import OrchestratorState


def test_register_and_heartbeat(tmp_path):
    state_file = tmp_path / "state.json"
    state = OrchestratorState(state_file=state_file)

    node = state.register_node("worker-1", "worker", "203.0.113.2", {"cap": "scan"})
    assert node["node_id"] == "worker-1"
    assert state.get_node("worker-1") is not None

    state.enqueue_command("worker-1", {"type": "scan_now"})
    heartbeat = state.record_heartbeat("worker-1", status="ready")
    assert heartbeat["node"]["status"] == "ready"
    assert heartbeat["commands"][0]["type"] == "scan_now"
    assert heartbeat["node"]["meta"]["cap"] == "scan"


def test_state_scrubs_secrets_from_metadata(tmp_path):
    state_file = tmp_path / "state.json"
    state = OrchestratorState(state_file=state_file)

    node = state.register_node(
        "worker-1",
        "worker",
        "203.0.113.2",
        {"orchestrator_token": "secret-token", "safe": "value"},
    )

    assert node["meta"]["orchestrator_token"].startswith("<redacted:")
    assert node["meta"]["safe"] == "value"

    state.record_heartbeat("worker-1", "online", {"api_key": "secret-key"})

    reloaded = OrchestratorState(state_file=state_file)
    stored = reloaded.get_node("worker-1")
    assert stored["meta"]["api_key"].startswith("<redacted:")
    assert "secret-key" not in state_file.read_text()


def test_state_persistence(tmp_path):
    state_file = tmp_path / "state.json"
    state = OrchestratorState(state_file=state_file)
    state.register_node("master-1", "master", "203.0.113.5")

    state_reloaded = OrchestratorState(state_file=state_file)
    nodes = state_reloaded.list_nodes()
    assert nodes and nodes[0]["node_id"] == "master-1"


def test_stale_nodes_are_marked_offline(tmp_path):
    state_file = tmp_path / "state.json"
    state = OrchestratorState(state_file=state_file, stale_after_seconds=10)
    node = state.register_node("worker-1", "worker", "203.0.113.2")

    marked = state.mark_stale_nodes(now=int(node["last_seen"]) + 11)

    assert marked == 1
    assert state.get_node("worker-1")["status"] == "offline"
    assert state.get_metrics()["nodes_marked_offline"] == 1


@pytest.mark.parametrize("read", ["get_metrics", "get_node"])
def test_health_reads_expire_disconnected_workers_and_heartbeat_recovers(tmp_path, monkeypatch, read):
    now = 1783217962
    monkeypatch.setattr(orchestrator_service.time, "time", lambda: now)
    state_file = tmp_path / "state.json"
    state = OrchestratorState(state_file=state_file, stale_after_seconds=10)
    for node in ("worker-one", "worker-two"):
        state.register_node(node, "worker", "192.0.2.10")
        state.record_heartbeat(node, "online")
    now += 11
    state.record_heartbeat("worker-two", "online")
    getattr(state, read)(*(["worker-one"] if read == "get_node" else []))
    nodes = json.loads(state_file.read_text())["nodes"]
    assert nodes["worker-one"]["status"] == "offline"
    assert nodes["worker-two"]["status"] == "online"
    from gui.app import _compute_metrics
    metrics = _compute_metrics(list(nodes.values()), [])
    assert metrics["total_nodes"] == 2 and metrics["online_nodes"] == 1
    assert state.get_metrics()["nodes_marked_offline"] == 1
    restarted = OrchestratorState(state_file=state_file, stale_after_seconds=10)
    restarted.record_heartbeat("worker-one", "online")
    assert len(restarted.list_nodes()) == 2
    assert all(node["status"] == "online" for node in restarted.list_nodes())
    assert _compute_metrics(restarted.list_nodes(), [])["online_nodes"] == 2


def test_interrupted_registry_write_preserves_last_complete_state(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    state = OrchestratorState(state_file=path)
    state.register_node("worker-one", "worker", "192.0.2.10")
    state.enqueue_command("worker-one", {"type": "set_interval", "value": 5})
    before = path.read_bytes()
    original_dump = json.dump
    def interrupted_dump(payload, handle, **kwargs):
        handle.write('{"nodes":')
        raise OSError("interrupted disk write")
    monkeypatch.setattr(orchestrator_service.json, "dump", interrupted_dump)
    state.register_node("worker-two", "worker", "192.0.2.11")
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]
    monkeypatch.setattr(orchestrator_service.json, "dump", original_dump)
    reloaded = OrchestratorState(state_file=path)
    assert [node["node_id"] for node in reloaded.list_nodes()] == ["worker-one"]
    assert reloaded.record_heartbeat("worker-one", "online")["commands"] == [{"type": "set_interval", "value": 5}]


def test_registry_replacement_failure_preserves_previous_state_and_cleans_tempfile(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    state = OrchestratorState(state_file=path)
    state.register_node("worker-one", "worker", "192.0.2.10")
    before = path.read_bytes()
    def failed_replace(source, destination):
        assert json.loads(source.read_text())["nodes"]["worker-two"]["node_id"] == "worker-two"
        assert destination.read_bytes() == before
        raise OSError("replacement unavailable")
    monkeypatch.setattr(orchestrator_service.os, "replace", failed_replace)
    state.register_node("worker-two", "worker", "192.0.2.11")
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]
