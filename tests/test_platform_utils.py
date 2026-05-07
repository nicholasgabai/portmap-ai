import socket
import subprocess
from types import SimpleNamespace

from core_engine import platform_utils


def test_platform_info_flags(monkeypatch):
    monkeypatch.setattr(platform_utils.platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform_utils.platform, "release", lambda: "6.1")
    monkeypatch.setattr(platform_utils.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(platform_utils.platform, "python_version", lambda: "3.11.5")

    info = platform_utils.get_platform_info()

    assert info.is_linux is True
    assert info.is_arm is True
    assert info.is_macos is False
    assert info.is_windows is False


def test_normalize_bind_host():
    assert platform_utils.normalize_bind_host(None) == "127.0.0.1"
    assert platform_utils.normalize_bind_host("0.0.0.0") == "127.0.0.1"
    assert platform_utils.normalize_bind_host("192.168.1.10") == "192.168.1.10"


def test_listener_pid_uses_psutil(monkeypatch):
    fake_conn = SimpleNamespace(
        status="LISTEN",
        laddr=SimpleNamespace(ip="0.0.0.0", port=9100),
        pid=1234,
    )
    fake_psutil = SimpleNamespace(net_connections=lambda kind="inet": [fake_conn])
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)

    assert platform_utils.listener_pid("127.0.0.1", 9100) == 1234


def test_process_name_falls_back(monkeypatch):
    fake_psutil = SimpleNamespace(Process=lambda pid: (_ for _ in ()).throw(RuntimeError("denied")))
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)

    assert platform_utils.process_name(1234) == "Unknown"


def test_network_interfaces_returns_plain_dict(monkeypatch):
    fake_addr = SimpleNamespace(
        family=socket.AF_INET,
        address="127.0.0.1",
        netmask="255.0.0.0",
        broadcast=None,
    )
    fake_psutil = SimpleNamespace(net_if_addrs=lambda: {"lo": [fake_addr]})
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)

    assert platform_utils.network_interfaces()["lo"][0]["address"] == "127.0.0.1"


def test_stop_processes_terminates_then_kills_on_timeout():
    class FakeProcess:
        def __init__(self):
            self.returncode = None
            self.terminated = False
            self.killed = False
            self.wait_calls = 0

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True
            self.returncode = -9

        def wait(self, timeout=None):
            self.wait_calls += 1
            if not self.killed:
                raise subprocess.TimeoutExpired("fake", timeout)
            return self.returncode

    proc = FakeProcess()

    platform_utils.stop_processes([proc])

    assert proc.terminated is True
    assert proc.killed is True
    assert proc.wait_calls == 2


def test_clear_terminal_uses_platform_command(monkeypatch):
    calls = []
    monkeypatch.setattr(platform_utils, "get_platform_info", lambda: SimpleNamespace(is_windows=True))
    monkeypatch.setattr(platform_utils.os, "system", lambda cmd: calls.append(cmd) or 0)

    platform_utils.clear_terminal()

    assert calls == ["cls"]


def test_find_executable_and_run_command_delegate(monkeypatch):
    monkeypatch.setattr(platform_utils.shutil, "which", lambda name: f"/bin/{name}")
    calls = []
    monkeypatch.setattr(platform_utils.subprocess, "run", lambda command, check=True: calls.append((command, check)) or "done")

    assert platform_utils.find_executable("tool") == "/bin/tool"
    assert platform_utils.run_command(["tool", "--version"], check=False) == "done"
    assert calls == [(["tool", "--version"], False)]


def test_terminate_pid_uses_os_kill(monkeypatch):
    calls = []
    monkeypatch.setattr(platform_utils.os, "kill", lambda pid, sig: calls.append((pid, sig)))

    platform_utils.terminate_pid(1234, force=False)

    assert calls == [(1234, platform_utils.signal.SIGTERM)]
