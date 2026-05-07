"""Convenience launcher for running a local PortMap-AI stack."""

from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List

from core_engine.config_loader import load_node_config
from core_engine.config_validation import format_validation_result, validate_config
from core_engine import platform_utils
from core_engine.security import token_fingerprint

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ORCHESTRATOR_URL = "http://127.0.0.1:9100"
DEFAULT_ORCHESTRATOR_TOKEN = "test-token"


def default_config_path(name: str) -> str:
    return str(resources.files("core_engine").joinpath("default_configs", name))


DEFAULT_ORCHESTRATOR_CFG = default_config_path("orchestrator.json")
DEFAULT_MASTER_CFG = default_config_path("master1.json")
DEFAULT_WORKER_CFG = default_config_path("worker_orchestrated.json")


@dataclass(frozen=True)
class ServiceSpec:
    role: str
    module: str
    args: list[str]
    critical: bool = True


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _normalize_bind_ip(bind_ip: str | None) -> str:
    return platform_utils.normalize_bind_host(bind_ip)


def resolve_stack_runtime(orchestrator_config: str, master_config: str, worker_config: str) -> Dict[str, Any]:
    orchestrator_cfg = _load_json(orchestrator_config)
    master_cfg = _load_json(master_config)
    worker_cfg = _load_json(worker_config)

    bind_ip = _normalize_bind_ip(orchestrator_cfg.get("bind_ip"))
    port = int(orchestrator_cfg.get("port", 9100))
    orchestrator_url = f"http://{bind_ip}:{port}"
    orchestrator_token = orchestrator_cfg.get("auth_token") or DEFAULT_ORCHESTRATOR_TOKEN
    master_bind_ip = _normalize_bind_ip(master_cfg.get("master_ip") or master_cfg.get("bind_ip") or "0.0.0.0")
    master_port = int(master_cfg.get("port", 9000))

    explicit_master_token = master_cfg.get("orchestrator_token")
    explicit_worker_token = worker_cfg.get("orchestrator_token")
    mismatched_tokens = {
        role: token
        for role, token in {"master": explicit_master_token, "worker": explicit_worker_token}.items()
        if token is not None and token != orchestrator_token
    }
    if mismatched_tokens:
        details = ", ".join(f"{role}=<fingerprint:{token_fingerprint(token)}>" for role, token in mismatched_tokens.items())
        raise ValueError(
            "Orchestrator auth_token does not match node configs "
            f"({details}, orchestrator=<fingerprint:{token_fingerprint(orchestrator_token)}>)"
        )

    explicit_master_url = master_cfg.get("orchestrator_url")
    explicit_worker_url = worker_cfg.get("orchestrator_url")
    mismatched_urls = {
        role: url
        for role, url in {"master": explicit_master_url, "worker": explicit_worker_url}.items()
        if url is not None and url.rstrip("/") != orchestrator_url.rstrip("/")
    }
    if mismatched_urls:
        details = ", ".join(f"{role}={url}" for role, url in mismatched_urls.items())
        raise ValueError(
            f"Orchestrator URL does not match node configs ({details}, orchestrator={orchestrator_url})"
        )

    return {
        "orchestrator_url": orchestrator_url,
        "orchestrator_token": orchestrator_token,
        "orchestrator_bind_ip": bind_ip,
        "orchestrator_port": port,
        "master_bind_ip": master_bind_ip,
        "master_port": master_port,
    }


def validate_stack_configs(orchestrator_config: str, master_config: str, worker_config: str) -> None:
    specs = [
        ("orchestrator", orchestrator_config, {"node_role": "orchestrator", "bind_ip": "0.0.0.0", "port": 9100}),
        ("master", master_config, {"node_role": "master"}),
        ("worker", worker_config, {"node_role": "worker"}),
    ]
    failures: list[str] = []
    for role, path, defaults in specs:
        try:
            config, settings = load_node_config(path, defaults=defaults)
            result = validate_config(config, settings, path=path, expected_role=role)
        except Exception as exc:
            failures.append(f"ERROR {path}\n  error: {exc}")
            continue
        if not result.ok:
            failures.append(format_validation_result(result))
    if failures:
        raise ValueError("\n\n".join(failures))


def build_env(runtime: Dict[str, Any]) -> dict:
    env = os.environ.copy()
    py_path = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{PACKAGE_ROOT}{os.pathsep}{py_path}" if py_path else str(PACKAGE_ROOT)
    env.setdefault("PORTMAP_ORCHESTRATOR_URL", runtime["orchestrator_url"])
    env.setdefault("PORTMAP_ORCHESTRATOR_TOKEN", runtime["orchestrator_token"])
    return env


def _listener_pid(host: str, port: int) -> int | None:
    return platform_utils.listener_pid(host, port)


def port_is_listening(host: str, port: int, timeout: float = 0.2) -> bool:
    return platform_utils.port_is_listening(host, port, timeout=timeout)


def find_stack_port_conflicts(runtime: Dict[str, Any]) -> List[Dict[str, Any]]:
    endpoints = [
        ("orchestrator", runtime["orchestrator_bind_ip"], int(runtime["orchestrator_port"])),
        ("master", runtime["master_bind_ip"], int(runtime["master_port"])),
    ]
    conflicts: List[Dict[str, Any]] = []
    for role, host, port in endpoints:
        probe_host = "127.0.0.1" if host in {"0.0.0.0", "localhost"} else host
        if port_is_listening(probe_host, port):
            conflicts.append({
                "role": role,
                "host": probe_host,
                "port": port,
                "pid": _listener_pid(probe_host, port),
            })
    return conflicts


def format_port_conflicts(conflicts: List[Dict[str, Any]]) -> str:
    details = []
    for item in conflicts:
        pid = f" pid={item['pid']}" if item.get("pid") else ""
        details.append(f"{item['role']} {item['host']}:{item['port']}{pid}")
    joined = "; ".join(details)
    return (
        "Stack startup blocked because required ports are already in use: "
        f"{joined}. Stop the existing listeners or choose different configs."
    )


def launch(module: str, args: List[str], env: dict, *, quiet: bool = False):
    return platform_utils.launch_python_module(module, args, env=env, quiet=quiet)


def build_worker_launch_args(worker_config: str, worker_args: list[str] | None = None) -> list[str]:
    worker_launch_args = ["--config", worker_config]
    if worker_args:
        worker_launch_args.extend(worker_args)
    if "--continuous" not in worker_launch_args:
        worker_launch_args.append("--continuous")
    if "--log-level" not in worker_launch_args:
        worker_launch_args.extend(["--log-level", "INFO"])
    return worker_launch_args


def build_service_specs(args: argparse.Namespace) -> list[ServiceSpec]:
    return [
        ServiceSpec("orchestrator", "core_engine.orchestrator", ["--config", args.orchestrator_config]),
        ServiceSpec("master", "core_engine.master_node", ["--config", args.master_config]),
        ServiceSpec("worker", "core_engine.worker_node", build_worker_launch_args(args.worker_config, args.worker_args)),
    ]


def maybe_restart_service(role: str, restart_counts: dict[str, int], restart_limit: int) -> bool:
    if restart_limit <= 0:
        return False
    current = restart_counts.get(role, 0)
    if current >= restart_limit:
        return False
    restart_counts[role] = current + 1
    return True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run orchestrator, master, and worker together")
    parser.add_argument("--orchestrator-config", default=DEFAULT_ORCHESTRATOR_CFG, help="Path to orchestrator config JSON")
    parser.add_argument("--master-config", default=DEFAULT_MASTER_CFG, help="Path to master config JSON")
    parser.add_argument("--worker-config", default=DEFAULT_WORKER_CFG, help="Path to worker config JSON")
    parser.add_argument("--worker-args", nargs=argparse.REMAINDER, help="Extra args for worker module (placed after --config)")
    parser.add_argument("--no-dashboard", action="store_true", help="Skip launching the Textual dashboard")
    parser.add_argument("--dashboard-delay", type=float, default=2.0, help="Seconds to wait before launching dashboard")
    parser.add_argument("--verbose", action="store_true", help="Stream orchestrator/master/worker output to console")
    parser.add_argument("--restart-limit", type=int, default=3, help="Restart each core service up to this many times after unexpected exits")
    parser.add_argument("--no-restart", action="store_true", help="Disable stack service restart supervision")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        validate_stack_configs(
            args.orchestrator_config,
            args.master_config,
            args.worker_config,
        )
        runtime = resolve_stack_runtime(
            args.orchestrator_config,
            args.master_config,
            args.worker_config,
        )
    except Exception as exc:
        raise SystemExit(f"Stack configuration invalid: {exc}") from exc

    env = build_env(runtime)
    conflicts = find_stack_port_conflicts(runtime)
    if conflicts:
        raise SystemExit(format_port_conflicts(conflicts))
    specs = {spec.role: spec for spec in build_service_specs(args)}
    processes = {}
    restart_counts: dict[str, int] = {}
    restart_limit = 0 if args.no_restart else max(args.restart_limit, 0)
    dashboard_proc = None

    try:
        for spec in specs.values():
            proc = launch(spec.module, spec.args, env, quiet=not args.verbose)
            processes[spec.role] = proc
            detail = f", {runtime['orchestrator_url']}" if spec.role == "orchestrator" else ""
            print("[+] %s started (PID %s%s)" % (spec.role.capitalize(), proc.pid, detail))

        if not args.no_dashboard:
            time.sleep(max(args.dashboard_delay, 0))
            dashboard_proc = launch("cli.dashboard", [], env, quiet=False)
            print("[+] Dashboard started (PID %s)" % dashboard_proc.pid)

        print("\nPress Ctrl+C to stop all processes.")
        while True:
            if dashboard_proc and dashboard_proc.poll() is not None:
                print(f"[!] Dashboard exited with code {dashboard_proc.returncode}")
                dashboard_proc = None
            exited = [(role, proc) for role, proc in processes.items() if proc.poll() is not None]
            if exited:
                stop_stack = False
                for role, proc in exited:
                    print(f"[!] {role} PID {proc.pid} exited with code {proc.returncode}")
                    spec = specs[role]
                    if maybe_restart_service(role, restart_counts, restart_limit):
                        replacement = launch(spec.module, spec.args, env, quiet=not args.verbose)
                        processes[role] = replacement
                        print(
                            "[+] %s restarted (PID %s, attempt %s/%s)"
                            % (role.capitalize(), replacement.pid, restart_counts[role], restart_limit)
                        )
                    else:
                        print(f"[!] {role} restart limit reached; stopping stack")
                        stop_stack = True
                if stop_stack:
                    break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[!] Stopping services...")
    finally:
        if dashboard_proc:
            platform_utils.stop_process(dashboard_proc)
        platform_utils.stop_processes(list(processes.values()))
        print("[+] All services stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
