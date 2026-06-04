import json
import socket
from types import SimpleNamespace

from core_engine import platform_utils
from core_engine.modules import scanner
from core_engine.runtime.milestone_v_bridge import build_milestone_v_runtime_bridge


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


def _macos_platform():
    return SimpleNamespace(
        system="Darwin",
        release="24",
        machine="arm64",
        python_version="3.11",
        is_macos=True,
        is_linux=False,
        is_windows=False,
        is_arm=True,
    )


def _sample_lsof_output():
    return "\n".join(
        [
            "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME",
            "ssh     1001 user    5u  IPv4 0xabc      0t0  TCP 192.0.2.10:55159->198.51.100.20:22 (ESTABLISHED)",
            "curl    1002 user    7u  IPv4 0xdef      0t0  TCP 192.0.2.10:55160->198.51.100.30:443 (ESTABLISHED)",
            "dig     1003 user    8u  IPv4 0x123      0t0  UDP 192.0.2.10:55161->198.51.100.53:53",
            "daemon  1004 user    9u  IPv4 0x456      0t0  TCP *:8443 (LISTEN)",
        ]
    )


def _install_macos_lsof_fixture(monkeypatch, *, exc):
    fake_psutil = SimpleNamespace(net_connections=lambda kind="inet": (_ for _ in ()).throw(exc))
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)
    monkeypatch.setattr(platform_utils, "get_platform_info", _macos_platform)
    monkeypatch.setattr(platform_utils, "find_executable", lambda name: "/usr/sbin/lsof" if name == "lsof" else None)
    monkeypatch.setattr(
        platform_utils,
        "run_command",
        lambda command, **kwargs: SimpleNamespace(returncode=0, stdout=_sample_lsof_output(), stderr=""),
    )


def test_macos_permission_error_uses_lsof_socket_inventory(monkeypatch):
    _install_macos_lsof_fixture(monkeypatch, exc=PermissionError("Operation not permitted"))

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


def test_macos_access_denied_triggers_lsof_fallback_and_milestone_v_bridge(monkeypatch):
    class AccessDenied(Exception):
        pass

    _install_macos_lsof_fixture(monkeypatch, exc=AccessDenied("access denied"))

    results, diagnostics = scanner.basic_scan_with_diagnostics()
    bridge = build_milestone_v_runtime_bridge(results, node_id="worker-fixture", generated_at="2026-06-04T12:00:00+00:00")

    assert diagnostics["primary_error_type"] == "AccessDenied"
    assert diagnostics["primary_error_summary"] == "access_denied"
    assert diagnostics["permission_blocked"] is True
    assert diagnostics["fallback_attempted"] is True
    assert diagnostics["fallback_used"] is True
    assert diagnostics["fallback_raw_count"] == 4
    assert bridge["runtime_counters"]["observations_seen"] > 0
    assert bridge["runtime_counters"]["flows_reconstructed"] > 0


def test_macos_wrapped_access_denied_class_name_triggers_lsof_fallback(monkeypatch):
    class WrappedAccessDeniedError(Exception):
        pass

    _install_macos_lsof_fixture(monkeypatch, exc=WrappedAccessDeniedError("wrapped scanner failure"))

    results, diagnostics = scanner.basic_scan_with_diagnostics()

    assert results
    assert diagnostics["primary_error_type"] == "WrappedAccessDeniedError"
    assert diagnostics["permission_blocked"] is True
    assert diagnostics["fallback_attempted"] is True
    assert diagnostics["fallback_used"] is True


def test_macos_arbitrary_runtime_error_does_not_trigger_lsof_fallback(monkeypatch):
    _install_macos_lsof_fixture(monkeypatch, exc=RuntimeError("boom"))

    results, diagnostics = scanner.basic_scan_with_diagnostics()

    assert results == []
    assert diagnostics["primary_error_type"] == "RuntimeError"
    assert diagnostics["permission_blocked"] is False
    assert diagnostics["fallback_attempted"] is False
    assert diagnostics["fallback_used"] is False


def test_fixture_and_simulated_modes_never_use_lsof_fallback(monkeypatch):
    _install_macos_lsof_fixture(monkeypatch, exc=PermissionError("Operation not permitted"))

    fixture_rows, fixture_diagnostics = scanner.basic_scan_with_diagnostics(source_mode="fixture")
    simulated_rows, simulated_diagnostics = scanner.basic_scan_with_diagnostics(source_mode="simulated")

    assert {row["program"] for row in fixture_rows} == {"dummy_app", "dummy_db"}
    assert {row["program"] for row in simulated_rows} == {"dummy_app", "dummy_db"}
    assert fixture_diagnostics["fallback_attempted"] is False
    assert simulated_diagnostics["fallback_attempted"] is False


def test_macos_lsof_fallback_diagnostics_do_not_expose_raw_endpoints(monkeypatch):
    class AccessDenied(Exception):
        pass

    _install_macos_lsof_fixture(monkeypatch, exc=AccessDenied("access denied"))

    _, diagnostics = scanner.basic_scan_with_diagnostics()
    serialized = json.dumps(diagnostics, sort_keys=True)

    assert diagnostics["raw_endpoint_logged"] is False
    assert "192.0.2.10" not in serialized
    assert "198.51.100.20" not in serialized
    assert "198.51.100.30" not in serialized
    assert "198.51.100.53" not in serialized


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
