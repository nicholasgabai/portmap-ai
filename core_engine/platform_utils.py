"""Cross-platform host and network inspection helpers."""

from __future__ import annotations

import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

try:
    import psutil
except Exception:  # pragma: no cover - optional dependency fallback
    psutil = None


@dataclass(frozen=True)
class PlatformInfo:
    system: str
    release: str
    machine: str
    python_version: str

    @property
    def is_macos(self) -> bool:
        return self.system == "Darwin"

    @property
    def is_linux(self) -> bool:
        return self.system == "Linux"

    @property
    def is_windows(self) -> bool:
        return self.system == "Windows"

    @property
    def is_arm(self) -> bool:
        machine = self.machine.lower()
        return machine.startswith(("arm", "aarch")) or machine in {"arm64", "aarch64"}


def get_platform_info() -> PlatformInfo:
    return PlatformInfo(
        system=platform.system(),
        release=platform.release(),
        machine=platform.machine(),
        python_version=platform.python_version(),
    )


def normalize_bind_host(host: str | None) -> str:
    if not host or host in {"0.0.0.0", "::", "localhost"}:
        return "127.0.0.1"
    return host


def net_connections(kind: str = "inet") -> list[Any]:
    if psutil is None:
        return []
    return list(psutil.net_connections(kind=kind))


def network_interfaces() -> dict[str, list[dict[str, Any]]]:
    if psutil is None:
        return {}
    interfaces: dict[str, list[dict[str, Any]]] = {}
    for name, addrs in psutil.net_if_addrs().items():
        interfaces[name] = [
            {
                "family": str(addr.family),
                "address": addr.address,
                "netmask": addr.netmask,
                "broadcast": addr.broadcast,
            }
            for addr in addrs
        ]
    return interfaces


def process_name(pid: int | None) -> str:
    if not pid or psutil is None:
        return "Unknown"
    try:
        return psutil.Process(pid).name()
    except Exception:
        return "Unknown"


def find_executable(name: str) -> str | None:
    return shutil.which(name)


def run_command(command: list[str], *, check: bool = True, **kwargs: Any) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=check, **kwargs)


def terminate_pid(pid: int, *, force: bool = False) -> None:
    sig = signal.SIGKILL if force and hasattr(signal, "SIGKILL") else signal.SIGTERM
    os.kill(pid, sig)


def local_node_address() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def listener_pid(host: str, port: int) -> int | None:
    if psutil is None:
        return None
    probe_host = normalize_bind_host(host)
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "LISTEN" or not conn.laddr:
                continue
            conn_host = getattr(conn.laddr, "ip", None) or conn.laddr[0]
            conn_port = getattr(conn.laddr, "port", None) or conn.laddr[1]
            host_matches = conn_host in {probe_host, "0.0.0.0", "::", "::1"} or probe_host == "127.0.0.1"
            if host_matches and conn_port == port:
                return conn.pid
    except Exception:
        return None
    return None


def port_is_listening(host: str, port: int, timeout: float = 0.2) -> bool:
    probe_host = normalize_bind_host(host)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((probe_host, port)) == 0


def launch_python_module(module: str, args: list[str], env: dict[str, str] | None = None, *, quiet: bool = False) -> subprocess.Popen:
    cmd = [sys.executable, "-m", module, *args]
    stdout = None
    stderr = None
    if quiet:
        stdout = subprocess.DEVNULL
        stderr = subprocess.STDOUT
    return subprocess.Popen(cmd, env=env, stdout=stdout, stderr=stderr)


def stop_process(process: subprocess.Popen, *, timeout: float = 5.0) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout)


def stop_processes(processes: list[subprocess.Popen], *, timeout: float = 5.0) -> None:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        if process.poll() is not None:
            continue
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=timeout)


def clear_terminal() -> None:
    os.system("cls" if get_platform_info().is_windows else "clear")


__all__ = [
    "clear_terminal",
    "find_executable",
    "PlatformInfo",
    "get_platform_info",
    "launch_python_module",
    "listener_pid",
    "local_node_address",
    "net_connections",
    "network_interfaces",
    "normalize_bind_host",
    "port_is_listening",
    "process_name",
    "run_command",
    "stop_process",
    "stop_processes",
    "terminate_pid",
]
