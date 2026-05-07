import json
from pathlib import Path

import pytest


def _load_run_stack_module():
    from core_engine import stack_launcher

    return stack_launcher


def test_resolve_stack_runtime_returns_shared_url_and_token(tmp_path):
    run_stack = _load_run_stack_module()

    orchestrator_cfg = tmp_path / "orchestrator.json"
    master_cfg = tmp_path / "master.json"
    worker_cfg = tmp_path / "worker.json"

    orchestrator_cfg.write_text(json.dumps({
        "bind_ip": "127.0.0.1",
        "port": 9200,
        "auth_token": "shared-token",
    }))
    master_cfg.write_text(json.dumps({"orchestrator_token": "shared-token"}))
    worker_cfg.write_text(json.dumps({"orchestrator_token": "shared-token"}))

    runtime = run_stack.resolve_stack_runtime(
        str(orchestrator_cfg),
        str(master_cfg),
        str(worker_cfg),
    )

    assert runtime["orchestrator_url"] == "http://127.0.0.1:9200"
    assert runtime["orchestrator_token"] == "shared-token"


def test_resolve_stack_runtime_rejects_token_mismatch(tmp_path):
    run_stack = _load_run_stack_module()

    orchestrator_cfg = tmp_path / "orchestrator.json"
    master_cfg = tmp_path / "master.json"
    worker_cfg = tmp_path / "worker.json"

    orchestrator_cfg.write_text(json.dumps({
        "bind_ip": "127.0.0.1",
        "port": 9100,
        "auth_token": "shared-token",
    }))
    master_cfg.write_text(json.dumps({"orchestrator_token": "wrong-token"}))
    worker_cfg.write_text(json.dumps({"orchestrator_token": "shared-token"}))

    with pytest.raises(ValueError, match="auth_token") as exc_info:
        run_stack.resolve_stack_runtime(
            str(orchestrator_cfg),
            str(master_cfg),
            str(worker_cfg),
        )
    message = str(exc_info.value)
    assert "wrong-token" not in message
    assert "shared-token" not in message
    assert "<fingerprint:" in message


def test_build_env_sets_stack_defaults(monkeypatch):
    run_stack = _load_run_stack_module()
    monkeypatch.delenv("PORTMAP_ORCHESTRATOR_URL", raising=False)
    monkeypatch.delenv("PORTMAP_ORCHESTRATOR_TOKEN", raising=False)

    env = run_stack.build_env({
        "orchestrator_url": "http://127.0.0.1:9300",
        "orchestrator_token": "stack-token",
    })

    assert env["PORTMAP_ORCHESTRATOR_URL"] == "http://127.0.0.1:9300"
    assert env["PORTMAP_ORCHESTRATOR_TOKEN"] == "stack-token"


def test_build_worker_launch_args_adds_stable_defaults():
    run_stack = _load_run_stack_module()

    args = run_stack.build_worker_launch_args("worker.json", ["--watch-config"])

    assert args == ["--config", "worker.json", "--watch-config", "--continuous", "--log-level", "INFO"]


def test_build_worker_launch_args_preserves_explicit_loop_and_log_level():
    run_stack = _load_run_stack_module()

    args = run_stack.build_worker_launch_args("worker.json", ["--continuous", "--log-level", "DEBUG"])

    assert args == ["--config", "worker.json", "--continuous", "--log-level", "DEBUG"]


def test_restart_policy_is_bounded():
    run_stack = _load_run_stack_module()
    counts = {}

    assert run_stack.maybe_restart_service("master", counts, restart_limit=2) is True
    assert run_stack.maybe_restart_service("master", counts, restart_limit=2) is True
    assert run_stack.maybe_restart_service("master", counts, restart_limit=2) is False
    assert counts["master"] == 2


def test_find_stack_port_conflicts_reports_listeners(monkeypatch):
    run_stack = _load_run_stack_module()

    monkeypatch.setattr(run_stack, "port_is_listening", lambda host, port, timeout=0.2: port in {9100, 9000})
    monkeypatch.setattr(run_stack, "_listener_pid", lambda host, port: 111 if port == 9100 else 222)

    conflicts = run_stack.find_stack_port_conflicts({
        "orchestrator_bind_ip": "127.0.0.1",
        "orchestrator_port": 9100,
        "master_bind_ip": "0.0.0.0",
        "master_port": 9000,
    })

    assert conflicts == [
        {"role": "orchestrator", "host": "127.0.0.1", "port": 9100, "pid": 111},
        {"role": "master", "host": "127.0.0.1", "port": 9000, "pid": 222},
    ]


def test_format_port_conflicts_is_readable():
    run_stack = _load_run_stack_module()

    message = run_stack.format_port_conflicts([
        {"role": "orchestrator", "host": "127.0.0.1", "port": 9100, "pid": 111},
        {"role": "master", "host": "127.0.0.1", "port": 9000, "pid": 222},
    ])

    assert "required ports are already in use" in message
    assert "orchestrator 127.0.0.1:9100 pid=111" in message
    assert "master 127.0.0.1:9000 pid=222" in message


def test_validate_stack_configs_rejects_bad_worker(tmp_path):
    run_stack = _load_run_stack_module()

    orchestrator_cfg = tmp_path / "orchestrator.json"
    master_cfg = tmp_path / "master.json"
    worker_cfg = tmp_path / "worker.json"

    orchestrator_cfg.write_text(json.dumps({
        "node_role": "orchestrator",
        "bind_ip": "127.0.0.1",
        "port": 9100,
        "auth_token": "shared-token",
    }))
    master_cfg.write_text(json.dumps({
        "node_role": "master",
        "master_ip": "127.0.0.1",
        "port": 9000,
    }))
    worker_cfg.write_text(json.dumps({
        "node_role": "worker",
        "node_id": "worker-1",
        "master_ip": "127.0.0.1",
        "port": 99999,
    }))

    with pytest.raises(ValueError, match="port must be between 1 and 65535"):
        run_stack.validate_stack_configs(
            str(orchestrator_cfg),
            str(master_cfg),
            str(worker_cfg),
        )
