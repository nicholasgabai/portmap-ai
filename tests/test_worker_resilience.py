import logging

from core_engine import worker_node


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
