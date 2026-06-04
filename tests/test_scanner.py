import socket
from types import SimpleNamespace

from core_engine import platform_utils
from core_engine.modules import scanner


def test_basic_scan_normalizes_psutil_connections(monkeypatch):
    fake_connections = [
        SimpleNamespace(
            laddr=SimpleNamespace(ip="127.0.0.1", port=8080),
            raddr=(),
            pid=123,
            status="LISTEN",
            type=socket.SOCK_STREAM,
        ),
        SimpleNamespace(
            laddr=SimpleNamespace(ip="203.0.113.10", port=5353),
            raddr=SimpleNamespace(ip="224.0.0.251", port=5353),
            pid=None,
            status="NONE",
            type=socket.SOCK_DGRAM,
        ),
    ]

    fake_psutil = SimpleNamespace(
        net_connections=lambda kind="inet": fake_connections,
        Process=lambda pid: SimpleNamespace(name=lambda: "python"),
    )
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)

    results = scanner.basic_scan()

    assert len(results) == 2
    assert results[0]["protocol"] in {"TCP", "UDP"}
    listen_row = next(item for item in results if item["port"] == 8080)
    assert listen_row["program"] == "python"
    assert listen_row["service_name"] == "HTTP-alt"
    assert listen_row["direction"] == "incoming"
    assert listen_row["status"] == "LISTEN"
    assert listen_row["local"] == "127.0.0.1:8080"


def test_basic_scan_falls_back_when_collection_fails(monkeypatch):
    fake_psutil = SimpleNamespace(net_connections=lambda kind="inet": (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)

    results = scanner.basic_scan(source_mode="simulated")

    assert len(results) == 2
    assert {item["program"] for item in results} == {"dummy_app", "dummy_db"}
    assert {item["source_mode"] for item in results} == {"simulated"}


def test_macos_permission_error_uses_lsof_socket_inventory(monkeypatch):
    fake_psutil = SimpleNamespace(net_connections=lambda kind="inet": (_ for _ in ()).throw(PermissionError("Operation not permitted")))
    fake_platform = SimpleNamespace(system="Darwin", release="24", machine="arm64", python_version="3.11", is_macos=True, is_linux=False, is_windows=False, is_arm=True)
    lsof_output = "\n".join(
        [
            "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME",
            "ssh     1001 user    5u  IPv4 0xabc      0t0  TCP 192.0.2.10:55159->198.51.100.20:22 (ESTABLISHED)",
            "curl    1002 user    7u  IPv4 0xdef      0t0  TCP 192.0.2.10:55160->198.51.100.30:443 (ESTABLISHED)",
            "dig     1003 user    8u  IPv4 0x123      0t0  UDP 192.0.2.10:55161->198.51.100.53:53",
            "daemon  1004 user    9u  IPv4 0x456      0t0  TCP *:8443 (LISTEN)",
        ]
    )

    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)
    monkeypatch.setattr(platform_utils, "get_platform_info", lambda: fake_platform)
    monkeypatch.setattr(platform_utils, "find_executable", lambda name: "/usr/sbin/lsof" if name == "lsof" else None)
    monkeypatch.setattr(
        platform_utils,
        "run_command",
        lambda command, **kwargs: SimpleNamespace(returncode=0, stdout=lsof_output, stderr=""),
    )

    results, diagnostics = scanner.basic_scan_with_diagnostics()

    assert diagnostics["platform_family"] == "macos"
    assert diagnostics["permission_blocked"] is True
    assert diagnostics["primary_error_type"] == "PermissionError"
    assert diagnostics["primary_error_summary"] == "operation_not_permitted"
    assert diagnostics["fallback_backend"] == "macos_lsof"
    assert diagnostics["fallback_used"] is True
    assert diagnostics["fallback_raw_count"] == 4
    assert diagnostics["normalized_count"] == 4
    assert diagnostics["privilege_escalation_attempted"] is False
    assert {row["collection_backend"] for row in results} == {"macos_lsof"}
    assert {row["source_mode"] for row in results} == {"live"}
    assert {row["port"] for row in results} == {8443, 55159, 55160, 55161}
    assert any(row["remote"].endswith(":22") and row["protocol"] == "TCP" for row in results)
    assert any(row["remote"].endswith(":443") and row["protocol"] == "TCP" for row in results)
    assert any(row["remote"].endswith(":53") and row["protocol"] == "UDP" for row in results)


def test_non_macos_permission_error_reports_diagnostics_without_lsof(monkeypatch):
    fake_psutil = SimpleNamespace(net_connections=lambda kind="inet": (_ for _ in ()).throw(PermissionError("Operation not permitted")))
    fake_platform = SimpleNamespace(system="Linux", release="6", machine="x86_64", python_version="3.11", is_macos=False, is_linux=True, is_windows=False, is_arm=False)
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)
    monkeypatch.setattr(platform_utils, "get_platform_info", lambda: fake_platform)

    results, diagnostics = scanner.basic_scan_with_diagnostics()

    assert results == []
    assert diagnostics["platform_family"] == "linux"
    assert diagnostics["permission_blocked"] is True
    assert diagnostics["fallback_attempted"] is False
    assert diagnostics["normalized_count"] == 0
