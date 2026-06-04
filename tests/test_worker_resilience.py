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
