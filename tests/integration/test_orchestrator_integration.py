import json
import os
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
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}

    proc = subprocess.Popen(
        [sys.executable, "-m", "core_engine.orchestrator", "--config", str(config_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )

    try:
        headers = {"Authorization": "Bearer integration-token"}
        wait_for_healthz(f"http://127.0.0.1:{port}/healthz", headers=headers)
        with pytest.raises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/nodes", timeout=1)
        assert denied.value.code == 401

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

        other = urllib.request.Request(
            f"http://127.0.0.1:{port}/register",
            data=json.dumps({"node_id": "worker-other", "role": "worker", "address": "127.0.0.1"}).encode(),
            headers=headers, method="POST",
        )
        with urllib.request.urlopen(other, timeout=5) as resp:
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
            assert metrics.get("registers") == 2
            assert metrics.get("heartbeats") == 1
            assert metrics.get("commands_queued") == 1
        proc.terminate()
        proc.wait(timeout=5)
        proc = subprocess.Popen(
            [sys.executable, "-m", "core_engine.orchestrator", "--config", str(config_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )
        wait_for_healthz(f"http://127.0.0.1:{port}/healthz", headers=headers)
        req = urllib.request.Request(f"http://127.0.0.1:{port}/nodes", headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            nodes = json.load(resp)["nodes"]
        assert {node["node_id"] for node in nodes} == {"worker-int", "worker-other"}
        req = urllib.request.Request(f"http://127.0.0.1:{port}/heartbeat", data=heartbeat_payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            heartbeat = json.load(resp)
        assert heartbeat["node"]["node_id"] == "worker-int"
        assert heartbeat["commands"] == [{"type": "scan_now"}]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


@pytest.mark.integration
def test_master_restart_preserves_two_workers_and_replay_identity(tmp_path, monkeypatch):
    from core_engine import worker_node
    from core_engine.modules.flow_tracker import build_flow_report
    from core_engine.telemetry_framing import encode_json_frame
    from core_engine.time_utils import parse_utc_instant
    import logging

    port = find_free_port()
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
    config = tmp_path / "master.json"
    config.write_text(json.dumps({"node_role": "master", "master_ip": "127.0.0.1", "port": port}))
    monkeypatch.setattr(worker_node, "get_score", lambda *args, **kwargs: 0.0)
    monkeypatch.setattr(worker_node, "utc_now_iso", lambda: "2026-07-05T02:19:22Z")
    row = {"local": "192.0.2.10:51515", "remote": "198.51.100.20:22", "port": 51515,
           "protocol": "TCP", "status": "ESTABLISHED", "source_mode": "live"}
    payloads = [worker_node.build_payload(node, [row], logging.getLogger("test.integration"), False)
                for node in ("worker-one", "worker-two")]
    proc = None
    try:
        for generation in range(2):
            proc = subprocess.Popen(
                [sys.executable, "-m", "core_engine.master_node", "--config", str(config)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
            )
            deadline = time.monotonic() + 10
            while True:
                assert proc.poll() is None, "Master exited before accepting telemetry"
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Master startup timed out")
                    time.sleep(0.05)
            if generation:
                monkeypatch.setattr(worker_node, "utc_now_iso", lambda: "2026-07-05T02:19:52Z")
                payloads[1] = worker_node.build_payload("worker-two", [row], logging.getLogger("test.integration"), False)
            for payload in payloads:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
                    conn.sendall(encode_json_frame(payload))
                    # ACK is unframed legacy JSON; a TCP read need not contain the full object.
                    ack = b""
                    while True:
                        chunk = conn.recv(1024)
                        assert chunk, "Master closed without acknowledgement"
                        ack += chunk
                        try:
                            assert json.loads(ack)["status"] == "ok"
                            break
                        except json.JSONDecodeError:
                            pass
            proc.terminate()
            proc.wait(timeout=5)
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
    events = [json.loads(line) for line in (home / ".portmap-ai/logs/master_events.log").read_text().splitlines()]
    assert len(events) == 4
    observations = [event["observations"][0] for event in events]
    assert observations[0]["observation_id"] == observations[2]["observation_id"]
    assert observations[1]["observation_id"] != observations[3]["observation_id"]
    assert observations[0]["session_id"] != observations[1]["session_id"]
    for record in observations:
        assert parse_utc_instant(record["event_timestamp"]) is not None
        assert parse_utc_instant(record["ingested_at"]) is not None
    flows = build_flow_report([flow for event in events for flow in event["flows"]])["flows"]
    assert len(flows) == 2
    assert sum(flow["event_count"] for flow in flows) == 3
    assert all(flow["captured_packet_count"] == flow["captured_bytes"] == 0 for flow in flows)
