"""Unified command interface for PortMap-AI local operations."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any
from urllib import error, request

from rich.console import Console
from rich.table import Table

from core_engine.config_loader import get_default_orchestrator_token, get_default_orchestrator_url
from core_engine.config_validation import format_validation_result, validate_config_files
from core_engine.log_exporter import export_logs, filter_audit_events
from core_engine.modules.scanner import basic_scan
from core_engine.network_control import assess_network_posture, summarize_posture
from core_engine.runtime_setup import initialize_runtime, packaging_diagnostics
from core_engine import stack_launcher

console = Console()


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _auth_headers(token: str | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get_json(url: str, token: str | None, endpoint: str) -> dict[str, Any]:
    req = request.Request(f"{url.rstrip('/')}{endpoint}", headers=_auth_headers(token), method="GET")
    with request.urlopen(req, timeout=5) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}


def _resolve_api_defaults(args: argparse.Namespace) -> tuple[str, str | None]:
    return (
        args.url or get_default_orchestrator_url(),
        args.token if args.token is not None else get_default_orchestrator_token(),
    )


def _render_scan_table(rows: list[dict[str, Any]]) -> None:
    table = Table(title="PortMap-AI Scan")
    table.add_column("Port", justify="right")
    table.add_column("PID", justify="right")
    table.add_column("Program")
    table.add_column("Protocol")
    table.add_column("Status")
    table.add_column("Direction")
    table.add_column("Local")
    table.add_column("Remote")

    for item in rows:
        table.add_row(
            str(item.get("port", "-")),
            str(item.get("pid", "-")),
            str(item.get("program", "-")),
            str(item.get("protocol", "-")),
            str(item.get("status", "-")),
            str(item.get("direction", "-")),
            str(item.get("local", "-")),
            str(item.get("remote", "-")),
        )
    console.print(table)


def cmd_scan(args: argparse.Namespace) -> int:
    rows = basic_scan(kind=args.kind)
    if args.output == "json":
        _print_json(rows)
    else:
        _render_scan_table(rows)
    return 0


def cmd_stack(args: argparse.Namespace) -> int:
    stack_args = [
        "--orchestrator-config",
        args.orchestrator_config,
        "--master-config",
        args.master_config,
        "--worker-config",
        args.worker_config,
    ]
    if args.no_dashboard:
        stack_args.append("--no-dashboard")
    if args.dashboard_delay is not None:
        stack_args.extend(["--dashboard-delay", str(args.dashboard_delay)])
    if args.verbose:
        stack_args.append("--verbose")
    if args.no_restart:
        stack_args.append("--no-restart")
    if args.restart_limit is not None:
        stack_args.extend(["--restart-limit", str(args.restart_limit)])
    if args.worker_args:
        stack_args.append("--worker-args")
        stack_args.extend(args.worker_args)
    return stack_launcher.main(stack_args)


def cmd_tui(args: argparse.Namespace) -> int:
    if args.url:
        os.environ["PORTMAP_ORCHESTRATOR_URL"] = args.url
    if args.token:
        os.environ["PORTMAP_ORCHESTRATOR_TOKEN"] = args.token
    from gui.app import run

    run()
    return 0


def cmd_api_get(args: argparse.Namespace, endpoint: str) -> int:
    url, token = _resolve_api_defaults(args)
    try:
        _print_json(_get_json(url, token, endpoint))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        print(f"HTTP {exc.code}: {detail}", file=sys.stderr)
        return 1
    except error.URLError as exc:
        print(f"Unable to reach orchestrator at {url}: {exc.reason}", file=sys.stderr)
        return 1
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    if args.filter_node or args.filter_event_type or args.tail is not None:
        _print_json(
            filter_audit_events(
                node_id=args.filter_node,
                event_type=args.filter_event_type,
                limit=args.tail,
            )
        )
        return 0
    archive = export_logs(output_dir=args.output_dir, include_state=not args.no_state)
    print(f"Log archive created at {archive}")
    return 0


def cmd_config_validate(args: argparse.Namespace) -> int:
    results = validate_config_files(args.paths, profile=args.profile, expected_role=args.role)
    if args.output == "json":
        _print_json([result.to_dict() for result in results])
    else:
        print("\n".join(format_validation_result(result) for result in results))
    return 0 if all(result.ok for result in results) else 1


def cmd_setup(args: argparse.Namespace) -> int:
    result = initialize_runtime(force=args.force)
    if args.output == "json":
        _print_json(result)
        return 0
    paths = result["paths"]
    print("PortMap-AI local runtime initialized")
    print(f"  app root: {paths['app_root']}")
    print(f"  data dir: {paths['data_dir']}")
    print(f"  log dir: {paths['log_dir']}")
    print(f"  settings: {paths['settings_file']}")
    print(f"  export dir: {paths['export_dir']}")
    print("Next steps:")
    for step in result["next_steps"]:
        print(f"  {step}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    result = packaging_diagnostics()
    if args.output == "json":
        _print_json(result)
        return 0 if result["ok"] else 1

    platform_info = result["platform"]
    print("PortMap-AI diagnostics")
    print(f"  platform: {platform_info['system']} {platform_info['machine']} ({platform_info['level']})")
    print(f"  notes: {platform_info['notes']}")
    print(f"  service manager: {result['service_manager']}")
    print("  paths:")
    for key, value in result["runtime_paths"].items():
        print(f"    {key}: {value}")
    print("  checks:")
    for check in result["checks"]:
        mark = "ok" if check["ok"] else "missing"
        print(f"    {mark}: {check['name']} ({check['detail']})")
    return 0 if result["ok"] else 1


def cmd_network(args: argparse.Namespace) -> int:
    posture = assess_network_posture()
    if args.output == "json":
        _print_json(posture)
    else:
        print(summarize_posture(posture))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="portmap", description="PortMap-AI unified local CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan local network sockets")
    scan.add_argument("--kind", choices=["inet", "tcp", "udp"], default="inet", help="psutil connection kind")
    scan.add_argument("--output", choices=["table", "json"], default="table", help="Output format")
    scan.set_defaults(func=cmd_scan)

    stack = subparsers.add_parser("stack", help="Run orchestrator, master, worker, and optional TUI")
    stack.add_argument("--orchestrator-config", default=stack_launcher.DEFAULT_ORCHESTRATOR_CFG)
    stack.add_argument("--master-config", default=stack_launcher.DEFAULT_MASTER_CFG)
    stack.add_argument("--worker-config", default=stack_launcher.DEFAULT_WORKER_CFG)
    stack.add_argument("--no-dashboard", action="store_true", help="Skip launching the Textual dashboard")
    stack.add_argument("--dashboard-delay", type=float, default=None)
    stack.add_argument("--verbose", action="store_true")
    stack.add_argument("--restart-limit", type=int, default=None, help="Restart each core service up to this many times after unexpected exits")
    stack.add_argument("--no-restart", action="store_true", help="Disable stack service restart supervision")
    stack.add_argument("--worker-args", nargs=argparse.REMAINDER, help="Arguments passed to the worker after --config")
    stack.set_defaults(func=cmd_stack)

    tui = subparsers.add_parser("tui", help="Launch the Textual operator dashboard")
    tui.add_argument("--url", help="Orchestrator URL")
    tui.add_argument("--token", help="Orchestrator bearer token")
    tui.set_defaults(func=cmd_tui)

    for name, endpoint, help_text in [
        ("health", "/healthz", "Check orchestrator health"),
        ("nodes", "/nodes", "List registered nodes"),
        ("metrics", "/metrics", "Show orchestrator metrics"),
    ]:
        api = subparsers.add_parser(name, help=help_text)
        api.add_argument("--url", help="Orchestrator URL")
        api.add_argument("--token", default=None, help="Orchestrator bearer token")
        api.set_defaults(func=lambda args, endpoint=endpoint: cmd_api_get(args, endpoint))

    logs = subparsers.add_parser("logs", help="Export logs and runtime state")
    logs.add_argument("--output-dir", default=None, help="Directory for the archive")
    logs.add_argument("--no-state", action="store_true", help="Exclude state files from the archive")
    logs.add_argument("--filter-node", help="Print JSONL audit events for a node instead of creating an archive")
    logs.add_argument("--filter-event-type", help="Print JSONL audit events by event_type instead of creating an archive")
    logs.add_argument("--tail", type=int, default=None, help="Limit filtered audit output to the last N events")
    logs.set_defaults(func=cmd_logs)

    config = subparsers.add_parser("config", help="Configuration utilities")
    config_subparsers = config.add_subparsers(dest="config_command", required=True)
    validate = config_subparsers.add_parser("validate", help="Validate one or more JSON config files")
    validate.add_argument("paths", nargs="+", help="Config file paths to validate")
    validate.add_argument("--profile", help="Profile name to merge before validation")
    validate.add_argument("--role", choices=["orchestrator", "master", "worker"], help="Require configs to match this node role")
    validate.add_argument("--output", choices=["text", "json"], default="text", help="Validation output format")
    validate.set_defaults(func=cmd_config_validate)

    setup = subparsers.add_parser("setup", help="Initialize local runtime directories and default settings")
    setup.add_argument("--force", action="store_true", help="Rewrite settings with default values")
    setup.add_argument("--output", choices=["text", "json"], default="text", help="Output format")
    setup.set_defaults(func=cmd_setup)

    doctor = subparsers.add_parser("doctor", help="Check local packaging/runtime readiness")
    doctor.add_argument("--output", choices=["text", "json"], default="text", help="Output format")
    doctor.set_defaults(func=cmd_doctor)

    network = subparsers.add_parser("network", help="Assess local gateway and exposed service posture")
    network.add_argument("--output", choices=["text", "json"], default="text", help="Output format")
    network.set_defaults(func=cmd_network)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
