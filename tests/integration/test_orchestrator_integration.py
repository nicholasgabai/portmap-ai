import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Optional

import pytest


def find_free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
    except OSError as exc:
        pytest.skip(f"Cannot bind to test port: {exc}")


def wait_for_healthz(url: str, timeout: float = 5.0, headers: Optional[Dict[str, str]] = None) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=1):
                return
        except Exception:
            time.sleep(0.1)
    raise TimeoutError(f"Orchestrator health check timed out at {url}")


@pytest.mark.integration
def test_orchestrator_metrics(tmp_path):
    port = find_free_port()
    config_data = json.loads((Path("tests/node_configs/orchestrator.json")).read_text())
    config_data["port"] = port
    config_data["master_ip"] = "127.0.0.1"
    config_path = tmp_path / "orch.json"
    config_data["auth_token"] = "integration-token"
    config_path.write_text(json.dumps(config_data))

    proc = subprocess.Popen(
        [sys.executable, "-m", "core_engine.orchestrator", "--config", str(config_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        headers = {"Authorization": "Bearer integration-token"}
        wait_for_healthz(f"http://127.0.0.1:{port}/healthz", headers=headers)

        headers = {"Content-Type": "application/json", "Authorization": "Bearer integration-token"}

        register_payload = json.dumps({
            "node_id": "worker-int",
            "role": "worker",
            "address": "127.0.0.1",
        }).encode()

        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/register",
            data=register_payload,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as resp:
            assert resp.status == 201

        heartbeat_payload = json.dumps({
            "node_id": "worker-int",
            "status": "online",
            "meta": {"interval": 5},
        }).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/heartbeat",
            data=heartbeat_payload,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            assert data["node"]["status"] == "online"

        command_payload = json.dumps({
            "node_id": "worker-int",
            "command": {"type": "scan_now"},
        }).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/commands",
            data=command_payload,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as resp:
            assert resp.status == 202

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/metrics",
            headers={"Authorization": "Bearer integration-token"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            metrics = json.loads(resp.read().decode())
            assert metrics.get("registers") == 1
            assert metrics.get("heartbeats") == 1
            assert metrics.get("commands_queued") == 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
