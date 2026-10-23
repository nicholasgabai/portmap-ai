import logging
import json
from contextlib import contextmanager
from io import BytesIO
from types import SimpleNamespace
from urllib import error

import pytest

from core_engine import worker_node
from core_engine.orchestrator_service import OrchestratorState


def test_worker_heartbeat_reregisters_after_orchestrator_state_loss(monkeypatch):
    calls = []

    def fake_heartbeat(logger, runtime, orchestrator_url, orchestrator_token):
        calls.append("heartbeat")
        if calls.count("heartbeat") == 1:
            return {"_register_required": True}
        return {"commands": [{"type": "scan_now"}]}

    def fake_register(logger, runtime, orchestrator_url, orchestrator_token):
        calls.append(("register", runtime["node_id"], orchestrator_url, orchestrator_token))

    monkeypatch.setattr(worker_node, "_send_heartbeat", fake_heartbeat)
    monkeypatch.setattr(worker_node, "_register_with_orchestrator", fake_register)

    response = worker_node._heartbeat_with_reregister(
        logging.getLogger("test.worker"),
        {"node_id": "worker-1"},
        "http://127.0.0.1:9100",
        "token",
    )

    assert calls == [
        "heartbeat",
        ("register", "worker-1", "http://127.0.0.1:9100", "token"),
        "heartbeat",
    ]
    assert response["commands"][0]["type"] == "scan_now"


def test_worker_logs_safe_socket_collection_diagnostics(monkeypatch, caplog):
    diagnostics = {
        "platform_family": "macos",
        "primary_backend": "psutil",
        "primary_raw_count": 0,
        "primary_error_type": "PermissionError",
        "primary_error_summary": "operation_not_permitted",
        "permission_blocked": True,
        "fallback_backend": "macos_lsof",
        "fallback_attempted": True,
        "fallback_available": True,
        "fallback_used": False,
        "fallback_raw_count": 0,
        "candidate_count": 0,
        "normalized_count": 0,
        "result_state": "empty",
        "raw_endpoint_logged": False,
        "privilege_escalation_attempted": False,
    }
    monkeypatch.setattr(worker_node, "basic_scan_with_diagnostics", lambda: ([], diagnostics))

    with caplog.at_level(logging.INFO):
        rows = worker_node.collect_connections(logging.getLogger("test.worker.diagnostics"))

    assert rows == []
    assert "Socket collection returned no observations" in caplog.text
    assert "operation_not_permitted" in caplog.text
    assert "macos_lsof" in caplog.text
    assert "raw_endpoint_logged': False" in caplog.text


@pytest.mark.parametrize("identity", [
    {"node_id": "worker-stable"},
    {"worker_id": "worker-stable"},
    {"node_id": "worker-stable", "worker_id": "legacy-other"},
])
def test_worker_loop_recovers_registration_and_preserves_node_identity_on_restart(tmp_path, monkeypatch, identity, caplog):
    state = OrchestratorState(state_file=tmp_path / "state.json")
    available = False
    calls, samples = [], []
    @contextmanager
    def local_request(req, timeout):
        assert req.get_header("Authorization") == "Bearer test-local-token"
        assert timeout == 5
        payload = json.loads(req.data)
        calls.append((req.full_url.rsplit("/", 1)[-1], payload["node_id"]))
        if not available:
            raise error.URLError(ConnectionRefusedError())
        if req.full_url.endswith("/register"):
            result = {"node": state.register_node(payload["node_id"], payload["role"], payload["address"], payload["meta"])}
        else:
            try:
                result = state.record_heartbeat(payload["node_id"], payload["status"], payload["meta"])
            except KeyError as exc:
                body = BytesIO(json.dumps({"error": str(exc)}).encode("utf-8"))
                raise error.HTTPError(req.full_url, 404, "unknown worker", {"Content-Type": "application/json"}, body) from exc
        yield SimpleNamespace(read=lambda: json.dumps(result).encode())
    sleeps = 0
    def next_cycle(interval):
        nonlocal available, sleeps
        assert interval == 1
        sleeps += 1
        if sleeps == 2:
            raise KeyboardInterrupt
        available = True
    config = {**identity, "master_ip": "127.0.0.1", "port": 9000,
              "scan_interval": 1, "orchestrator_url": "http://127.0.0.1:9100",
              "orchestrator_token": "test-local-token"}
    monkeypatch.setattr(worker_node.request, "urlopen", local_request)
    monkeypatch.setattr(worker_node, "local_node_address", lambda: "192.0.2.10")
    monkeypatch.setattr(worker_node.socket, "gethostname", lambda: "fallback-host")
    monkeypatch.setattr(worker_node, "configure_firewall", lambda *args: None)
    monkeypatch.setattr(worker_node, "send_to_master", lambda **kwargs: samples.append(kwargs["node_id"]))
    monkeypatch.setattr(worker_node.time, "sleep", next_cycle)
    logger = logging.getLogger("test.worker.recovery")
    worker_node.run_worker(config, {}, logger, continuous=True)
    assert calls == [("register", "worker-stable"), ("heartbeat", "worker-stable"),
                     ("heartbeat", "worker-stable"), ("register", "worker-stable"),
                     ("heartbeat", "worker-stable")]
    assert samples == ["worker-stable", "worker-stable"]
    assert state.get_node("worker-stable")["status"] == "online"
    assert len(state.list_nodes()) == 1
    assert state.get_metrics()["registers"] == state.get_metrics()["heartbeats"] == 1
    assert 'Heartbeat failed HTTP 404 unknown worker: {"error":' in caplog.text
    state = OrchestratorState(state_file=tmp_path / "state.json")
    state.register_node("worker-other", "worker", "192.0.2.11")
    worker_node.run_worker(config, {}, logger)
    assert samples[-1] == "worker-stable"
    assert {node["node_id"] for node in state.list_nodes()} == {"worker-stable", "worker-other"}
    assert state.get_node("worker-stable")["status"] == "online"
