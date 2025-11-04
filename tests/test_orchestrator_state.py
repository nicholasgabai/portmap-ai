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


def test_state_persistence(tmp_path):
    state_file = tmp_path / "state.json"
    state = OrchestratorState(state_file=state_file)
    state.register_node("master-1", "master", "10.0.0.5")

    state_reloaded = OrchestratorState(state_file=state_file)
    nodes = state_reloaded.list_nodes()
    assert nodes and nodes[0]["node_id"] == "master-1"
