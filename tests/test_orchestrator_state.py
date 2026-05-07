import json
from pathlib import Path

from core_engine.orchestrator_service import OrchestratorState


def test_register_and_heartbeat(tmp_path):
    state_file = tmp_path / "state.json"
    state = OrchestratorState(state_file=state_file)

    node = state.register_node("worker-1", "worker", "192.168.1.2", {"cap": "scan"})
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
        "192.168.1.2",
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
    state.register_node("master-1", "master", "10.0.0.5")

    state_reloaded = OrchestratorState(state_file=state_file)
    nodes = state_reloaded.list_nodes()
    assert nodes and nodes[0]["node_id"] == "master-1"


def test_stale_nodes_are_marked_offline(tmp_path):
    state_file = tmp_path / "state.json"
    state = OrchestratorState(state_file=state_file, stale_after_seconds=10)
    node = state.register_node("worker-1", "worker", "192.168.1.2")

    marked = state.mark_stale_nodes(now=int(node["last_seen"]) + 11)

    assert marked == 1
    assert state.get_node("worker-1")["status"] == "offline"
    assert state.get_metrics()["nodes_marked_offline"] == 1
