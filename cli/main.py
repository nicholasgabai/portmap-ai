"""Unified command interface for PortMap-AI local operations."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib import error, request

from rich.console import Console
from rich.table import Table

from ai_agent.baseline_store import load_baseline, save_baseline
from ai_agent.behavior_model import analyze_events
from ai_agent.payload_classifier import classify_payload_events
from ai_agent.recommendation_engine import generate_recommendations
from ai_agent.threat_correlation import correlate_events
from core_engine.advisory.workflow import ReviewWorkflow, build_review_packet
from core_engine.cluster.scheduler import plan_distributed_scan
from core_engine.config_loader import get_default_orchestrator_token, get_default_orchestrator_url
from core_engine.config_validation import format_validation_result, validate_config_files
from core_engine.integrations.elastic import format_elastic_bulk, format_elastic_document, send_elastic_bulk
from core_engine.integrations.email import format_email_alert, send_email_alert
from core_engine.integrations.sentinel import format_sentinel_event
from core_engine.integrations.splunk import format_splunk_hec_event, send_splunk_hec
from core_engine.integrations.webhook import format_webhook_alert, send_webhook_alert
from core_engine.log_exporter import export_logs, filter_audit_events
from core_engine.modules.dpi import analyze_observation
from core_engine.modules.discovery import asset_telemetry_events, inventory_network_assets, local_topology_snapshot
from core_engine.modules.async_scanner import scan_targets as fast_scan_targets
from core_engine.modules.flow_tracker import build_flow_report
from core_engine.modules.ipv6_scanner import scan_dual_stack_targets
from core_engine.modules.os_fingerprint import fingerprint_observation, fingerprint_targets
from core_engine.modules.packet_capture import capture_live
from core_engine.modules.scanner import basic_scan
from core_engine.modules.service_detection import enumerate_services
from core_engine.modules.tls_inspector import analyze_tls_observation, inspect_tls_targets
from core_engine.modules.udp_scanner import scan_udp_target
from core_engine.network_control import assess_network_posture, summarize_posture
from core_engine.runtime_setup import initialize_runtime, packaging_diagnostics
from core_engine.rbac import authorize, role_report
from core_engine.visibility import build_visibility_report
from core_engine.visibility_history import build_visibility_snapshot, compare_visibility_snapshots
from core_engine.vuln.cve_client import analyze_service_cves, fetch_nvd_cves, load_cves_from_json
from core_engine.vuln.cve_store import load_cve_cache, merge_cve_records, save_cve_cache
from core_engine.vuln.vuln_correlator import correlate_vulnerabilities
from core_engine import stack_launcher
from saas.cloud_sync import export_sync_manifest, import_sync_manifest, resolve_sync_conflicts
from saas.licensing import check_quota, feature_enabled, usage_summary
from saas.orgs import build_org_directory, effective_user_access
from saas.tenancy import WorkspaceConfig, save_workspace_config

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


def _render_discovery_table(rows: list[dict[str, Any]]) -> None:
    table = Table(title="PortMap-AI Asset Inventory")
    table.add_column("Host")
    table.add_column("IP", justify="right")
    table.add_column("Status")
    table.add_column("Methods")
    table.add_column("MAC")
    table.add_column("Interface")
    table.add_column("Open Ports")
    table.add_column("Closed Ports")

    for item in rows:
        table.add_row(
            str(item.get("host", "-")),
            str(item.get("ip_version", "-")),
            str(item.get("status", "-")),
            ",".join(item.get("methods") or []) or "-",
            str(item.get("mac") or "-"),
            str(item.get("interface") or "-"),
            ",".join(str(port) for port in item.get("open_ports") or []) or "-",
            ",".join(str(port) for port in item.get("closed_ports") or []) or "-",
        )
    console.print(table)


def _render_service_table(rows: list[dict[str, Any]]) -> None:
    table = Table(title="PortMap-AI Service Enumeration")
    table.add_column("Target")
    table.add_column("Port", justify="right")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("Confidence", justify="right")
    table.add_column("Reason")

    for item in rows:
        table.add_row(
            str(item.get("target", "-")),
            str(item.get("port", "-")),
            str(item.get("state", "-")),
            str(item.get("service", "-")),
            str(item.get("version", "-")),
            f"{float(item.get('confidence') or 0):.2f}",
            str(item.get("reason", "-")),
        )
    console.print(table)


def _render_os_table(rows: list[dict[str, Any]]) -> None:
    table = Table(title="PortMap-AI OS Fingerprinting")
    table.add_column("Target")
    table.add_column("Probable OS")
    table.add_column("Confidence", justify="right")
    table.add_column("Certainty")
    table.add_column("Evidence")

    for item in rows:
        table.add_row(
            str(item.get("target", "-")),
            str(item.get("probable_os", "-")),
            f"{float(item.get('confidence') or 0):.2f}",
            str(item.get("certainty", "-")),
            "; ".join(item.get("evidence") or []) or "-",
        )
    console.print(table)


def _render_tls_table(rows: list[dict[str, Any]]) -> None:
    table = Table(title="PortMap-AI TLS Intelligence")
    table.add_column("Target")
    table.add_column("Port", justify="right")
    table.add_column("TLS")
    table.add_column("Cipher")
    table.add_column("Cert Expiry")
    table.add_column("Risk", justify="right")
    table.add_column("Warnings")

    for item in rows:
        tls_version = item.get("tls_version") or {}
        cipher = item.get("cipher") or {}
        certificate = item.get("certificate") or {}
        warnings = item.get("warnings") or []
        table.add_row(
            str(item.get("target", "-")),
            str(item.get("port", "-")),
            str(tls_version.get("version") or "-"),
            str(cipher.get("name") or "-"),
            str(certificate.get("not_after") or "-"),
            f"{float(item.get('risk_score') or 0):.2f}",
            ",".join(str(warning.get("type")) for warning in warnings) or "-",
        )
    console.print(table)


def _render_capture_table(payload: dict[str, Any]) -> None:
    if not payload.get("ok"):
        print(f"Capture unavailable: {payload.get('error')} ({payload.get('reason')})")
        return
    table = Table(title="PortMap-AI Packet Capture")
    table.add_column("#", justify="right")
    table.add_column("Interface")
    table.add_column("Protocol")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Bytes", justify="right")

    for item in payload.get("packets") or []:
        src = str(item.get("src_ip") or item.get("src_mac") or "-")
        if item.get("src_port"):
            src = f"{src}:{item['src_port']}"
        dst = str(item.get("dst_ip") or item.get("dst_mac") or "-")
        if item.get("dst_port"):
            dst = f"{dst}:{item['dst_port']}"
        table.add_row(
            str(item.get("packet_number", "-")),
            str(item.get("interface") or "-"),
            str(item.get("protocol") or "-"),
            src,
            dst,
            str(item.get("captured_len", "-")),
        )
    console.print(table)


def _render_flow_table(payload: dict[str, Any]) -> None:
    table = Table(title="PortMap-AI Traffic Flows")
    table.add_column("Flow")
    table.add_column("Initiator")
    table.add_column("Responder")
    table.add_column("Packets", justify="right")
    table.add_column("Payload", justify="right")
    table.add_column("Apps")
    table.add_column("Findings")

    for item in payload.get("flows") or []:
        initiator = item.get("initiator") or {}
        responder = item.get("responder") or {}
        table.add_row(
            str(item.get("flow_id") or "-"),
            _endpoint_text(initiator),
            _endpoint_text(responder),
            str(item.get("packet_count") or 0),
            str(item.get("payload_bytes") or 0),
            ",".join(item.get("application_protocols") or []) or "-",
            ",".join(item.get("findings") or []) or "-",
        )
    console.print(table)


def _render_behavior_table(payload: dict[str, Any]) -> None:
    table = Table(title="PortMap-AI Behavioral Analysis")
    table.add_column("Device")
    table.add_column("Status")
    table.add_column("Score", justify="right")
    table.add_column("Findings")

    for item in payload.get("analyses") or []:
        table.add_row(
            str(item.get("device_id") or "-"),
            str(item.get("status") or "-"),
            f"{float(item.get('score') or 0):.2f}",
            ",".join(str(finding.get("type")) for finding in item.get("findings") or []) or "-",
        )
    console.print(table)


def _render_payload_table(payload: dict[str, Any]) -> None:
    table = Table(title="PortMap-AI Payload Classification")
    table.add_column("#", justify="right")
    table.add_column("Protocol")
    table.add_column("Label")
    table.add_column("Confidence", justify="right")
    table.add_column("Risk", justify="right")
    table.add_column("Findings")

    for index, item in enumerate(payload.get("classifications") or [], start=1):
        table.add_row(
            str(index),
            str(item.get("protocol") or "-"),
            str(item.get("label") or "-"),
            f"{float(item.get('confidence') or 0):.2f}",
            f"{float(item.get('risk_score') or 0):.2f}",
            ",".join(str(finding.get("type")) for finding in item.get("findings") or []) or "-",
        )
    console.print(table)


def _render_correlation_table(payload: dict[str, Any]) -> None:
    table = Table(title="PortMap-AI Threat Correlation")
    table.add_column("Incident")
    table.add_column("Type")
    table.add_column("Entity")
    table.add_column("Severity")
    table.add_column("Score", justify="right")
    table.add_column("Events", justify="right")

    for item in payload.get("incidents") or []:
        table.add_row(
            str(item.get("incident_id") or "-"),
            str(item.get("type") or "-"),
            str(item.get("entity") or "-"),
            str(item.get("severity") or "-"),
            f"{float(item.get('score') or 0):.2f}",
            str(item.get("event_count") or 0),
        )
    console.print(table)


def _render_recommendation_table(payload: dict[str, Any]) -> None:
    table = Table(title="PortMap-AI Recommendations")
    table.add_column("Recommendation")
    table.add_column("Action")
    table.add_column("Target")
    table.add_column("Priority", justify="right")
    table.add_column("Approval")

    for item in payload.get("recommendations") or []:
        table.add_row(
            str(item.get("recommendation_id") or "-"),
            str(item.get("action") or "-"),
            str(item.get("target") or "-"),
            f"{float(item.get('priority') or 0):.2f}",
            "required" if item.get("approval_required") else "review",
        )
    console.print(table)


def _render_cve_table(payload: dict[str, Any]) -> None:
    table = Table(title="PortMap-AI CVE Intelligence")
    table.add_column("CVE")
    table.add_column("Target")
    table.add_column("Service")
    table.add_column("Severity")
    table.add_column("CVSS", justify="right")
    table.add_column("Risk", justify="right")
    table.add_column("Confidence", justify="right")

    rows = payload.get("matches") or payload.get("records") or []
    for item in rows:
        table.add_row(
            str(item.get("cve_id") or item.get("id") or "-"),
            str(item.get("target") or "-"),
            str(item.get("service") or "-"),
            str(item.get("severity") or "-"),
            f"{float(item.get('cvss_score') or 0):.1f}",
            f"{float(item.get('risk_score') or 0):.2f}" if "risk_score" in item else "-",
            f"{float(item.get('confidence') or 0):.2f}" if "confidence" in item else "-",
        )
    console.print(table)


def _render_vulnerability_table(payload: dict[str, Any]) -> None:
    table = Table(title="PortMap-AI Vulnerability Prioritization")
    table.add_column("Priority")
    table.add_column("CVE")
    table.add_column("Target")
    table.add_column("Service")
    table.add_column("Score", justify="right")
    table.add_column("Exposure")
    table.add_column("Indicators")

    for item in payload.get("vulnerabilities") or []:
        table.add_row(
            str(item.get("priority") or "-"),
            str(item.get("cve_id") or "-"),
            str(item.get("target") or "-"),
            str(item.get("service") or "-"),
            f"{float(item.get('priority_score') or 0):.2f}",
            str((item.get("exposure") or {}).get("scope") or "-"),
            ",".join(item.get("exploitability_indicators") or []) or "-",
        )
    console.print(table)


def _render_rbac_table(payload: dict[str, Any]) -> None:
    table = Table(title="PortMap-AI RBAC")
    if "roles" in payload and isinstance(payload.get("roles"), dict):
        table.add_column("Role")
        table.add_column("Inherits")
        table.add_column("Permissions")
        for role, data in payload["roles"].items():
            table.add_row(
                role,
                ",".join(data.get("inherits") or []) or "-",
                ",".join(data.get("permissions") or []),
            )
    else:
        table.add_column("Roles")
        table.add_column("Permission")
        table.add_column("Granted")
        table.add_column("Errors")
        table.add_row(
            ",".join(payload.get("roles") or []),
            str(payload.get("permission") or "-"),
            "yes" if payload.get("granted") else "no",
            "; ".join(payload.get("errors") or []) or "-",
        )
    console.print(table)


def _render_alert_table(payload: dict[str, Any]) -> None:
    table = Table(title="PortMap-AI Alert Integration")
    table.add_column("Format")
    table.add_column("Sent")
    table.add_column("Status")
    table.add_column("Destination")
    delivery = payload.get("delivery") or {}
    table.add_row(
        str(payload.get("format") or "-"),
        "yes" if delivery.get("ok") and not delivery.get("dry_run") else "no",
        str(delivery.get("status") or "formatted"),
        str(delivery.get("destination") or "-"),
    )
    console.print(table)


def _render_cluster_plan_table(payload: dict[str, Any]) -> None:
    summary = payload.get("summary") or {}
    table = Table(title="PortMap-AI Cluster Scan Plan")
    table.add_column("Job")
    table.add_column("Workers", justify="right")
    table.add_column("Tasks", justify="right")
    table.add_column("Assigned", justify="right")
    table.add_column("Queued", justify="right")
    table.add_column("Probes", justify="right")
    table.add_column("Mode")
    table.add_row(
        str((payload.get("job") or {}).get("job_id") or "-"),
        str(summary.get("available_workers", 0)),
        str(summary.get("task_count", 0)),
        str(summary.get("assigned_tasks", 0)),
        str(summary.get("queued_tasks", 0)),
        str(summary.get("total_probes", 0)),
        str(payload.get("mode", "dry_run")),
    )
    console.print(table)


def _render_visibility_table(payload: dict[str, Any]) -> None:
    if "deltas" in payload:
        _render_visibility_delta_table(payload)
        return
    summary = payload.get("summary") or {}
    table = Table(title="PortMap-AI Visibility Summary")
    table.add_column("Assets", justify="right")
    table.add_column("Services", justify="right")
    table.add_column("Flows", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Review Drafts", justify="right")
    table.add_row(
        str(summary.get("asset_count", 0)),
        str(summary.get("service_count", 0)),
        str(summary.get("flow_count", 0)),
        str(summary.get("finding_count", 0)),
        str(summary.get("response_workflow_count", 0)),
    )
    console.print(table)

    findings = payload.get("findings") or []
    if not findings:
        return
    finding_table = Table(title="Categorized Findings")
    finding_table.add_column("Severity")
    finding_table.add_column("Category")
    finding_table.add_column("Type")
    finding_table.add_column("Target")
    finding_table.add_column("Action")
    for item in findings:
        finding_table.add_row(
            str(item.get("severity") or "-"),
            str(item.get("category") or "-"),
            str(item.get("type") or "-"),
            str(item.get("target") or "-"),
            str(item.get("recommended_action") or "-"),
        )
    console.print(finding_table)


def _render_visibility_delta_table(payload: dict[str, Any]) -> None:
    summary = payload.get("summary") or {}
    table = Table(title="PortMap-AI Visibility Baseline Deltas")
    table.add_column("Baseline")
    table.add_column("Current")
    table.add_column("Deltas", justify="right")
    table.add_column("Review Drafts", justify="right")
    table.add_row(
        str(payload.get("baseline_snapshot_id") or "-"),
        str(payload.get("current_snapshot_id") or "-"),
        str(summary.get("delta_count", 0)),
        str(summary.get("response_workflow_count", 0)),
    )
    console.print(table)

    deltas = payload.get("deltas") or []
    if not deltas:
        return
    delta_table = Table(title="Safe Anomaly Deltas")
    delta_table.add_column("Severity")
    delta_table.add_column("Type")
    delta_table.add_column("Target")
    delta_table.add_column("Action")
    for item in deltas:
        delta_table.add_row(
            str(item.get("severity") or "-"),
            str(item.get("type") or "-"),
            str(item.get("target") or "-"),
            str(item.get("recommended_action") or "-"),
        )
    console.print(delta_table)


def _endpoint_text(endpoint: dict[str, Any]) -> str:
    host = str(endpoint.get("ip") or "-")
    port = endpoint.get("port")
    return f"{host}:{port}" if port else host


def _parse_ports(value: str | None) -> list[int] | None:
    if value is None:
        return None
    ports: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                raise argparse.ArgumentTypeError("port ranges must be ascending")
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(item))
    return ports


def _parse_cluster_workers(worker_args: list[str] | None, workers_json: str | None) -> list[dict[str, Any]]:
    workers: list[dict[str, Any]] = []
    if workers_json:
        payload = json.loads(workers_json)
        if isinstance(payload, dict) and isinstance(payload.get("workers"), list):
            payload = payload["workers"]
        if not isinstance(payload, list):
            raise ValueError("--workers-json must decode to a list or an object with a workers list")
        workers.extend(item for item in payload if isinstance(item, dict))
    for value in worker_args or []:
        node_id, _, address = value.partition("@")
        node_id = node_id.strip()
        if not node_id:
            raise ValueError("--worker entries must include a node id")
        workers.append({"node_id": node_id, "address": address.strip(), "status": "available", "role": "worker"})
    return workers


def cmd_scan(args: argparse.Namespace) -> int:
    if args.target and args.udp_target:
        print("Scan error: use either --target or --udp-target, not both", file=sys.stderr)
        return 1
    if args.target:
        try:
            rows = scan_dual_stack_targets(
                args.target,
                _parse_ports(args.ports) or [80, 443],
                ip_version=args.ip_version,
                timeout=args.timeout,
                aggressive=args.aggressive,
            )
        except (argparse.ArgumentTypeError, ValueError) as exc:
            print(f"Scan error: {exc}", file=sys.stderr)
            return 1
    elif args.udp_target:
        try:
            rows = scan_udp_target(
                args.udp_target,
                ports=_parse_ports(args.udp_ports),
                timeout=args.udp_timeout,
                retries=args.udp_retries,
                aggressive=args.udp_aggressive,
            )
        except (argparse.ArgumentTypeError, ValueError) as exc:
            print(f"UDP scan error: {exc}", file=sys.stderr)
            return 1
    else:
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


def cmd_discover(args: argparse.Namespace) -> int:
    include_local = args.local_networks or not args.ranges
    try:
        assets = inventory_network_assets(
            args.ranges,
            include_local_networks=include_local,
            methods=args.method,
            tcp_ports=_parse_ports(args.tcp_ports) or [22, 80, 443],
            ip_version=args.ip_version,
            timeout=args.timeout,
            max_targets=args.max_targets,
            aggressive=args.aggressive,
        )
    except (argparse.ArgumentTypeError, ValueError) as exc:
        print(f"Discovery error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        payload: dict[str, Any] = {
            "assets": assets,
            "telemetry": asset_telemetry_events(assets, node_id=args.node_id),
        }
        if args.topology:
            payload["topology"] = local_topology_snapshot(include_arp="arp" in (args.method or ["arp", "tcp"]))
        _print_json(payload)
    else:
        _render_discovery_table(assets)
    return 0


def cmd_services(args: argparse.Namespace) -> int:
    try:
        rows = enumerate_services(
            args.target,
            ports=_parse_ports(args.ports),
            ip_version=args.ip_version,
            timeout=args.timeout,
            max_targets=args.max_targets,
            max_ports=args.max_ports,
            aggressive=args.aggressive,
        )
    except (argparse.ArgumentTypeError, ValueError) as exc:
        print(f"Service enumeration error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(rows)
    else:
        _render_service_table(rows)
    return 0


def cmd_os(args: argparse.Namespace) -> int:
    try:
        if args.observation_json:
            observation = json.loads(args.observation_json)
            if not isinstance(observation, dict):
                raise ValueError("--observation-json must decode to an object")
            rows = [fingerprint_observation(observation)]
        else:
            if not args.target:
                raise ValueError("--target is required unless --observation-json is provided")
            rows = fingerprint_targets(
                args.target,
                ports=_parse_ports(args.ports),
                ip_version=args.ip_version,
                timeout=args.timeout,
                max_targets=args.max_targets,
                max_ports=args.max_ports,
                aggressive=args.aggressive,
                ttl=args.ttl,
                tcp_window=args.tcp_window,
                tcp_options=args.tcp_options,
            )
    except (argparse.ArgumentTypeError, json.JSONDecodeError, ValueError) as exc:
        print(f"OS fingerprint error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(rows)
    else:
        _render_os_table(rows)
    return 0


def cmd_fast_scan(args: argparse.Namespace) -> int:
    try:
        rows = fast_scan_targets(
            args.target,
            _parse_ports(args.ports) or [80, 443],
            ip_version=args.ip_version,
            timeout=args.timeout,
            concurrency=args.concurrency,
            rate_per_second=args.rate,
            max_targets=args.max_targets,
            max_ports=args.max_ports,
            aggressive=args.aggressive,
        )
    except (argparse.ArgumentTypeError, ValueError) as exc:
        print(f"Fast scan error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(rows)
    else:
        _render_scan_table(rows)
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    try:
        payload = capture_live(
            interface=args.interface,
            duration=args.duration,
            max_packets=args.max_packets,
            capture_filter=args.filter,
            pcap_path=args.pcap,
            dissect=args.dissect,
            dpi=args.dpi,
            flows=args.flows,
        )
    except ValueError as exc:
        print(f"Capture error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(payload)
    else:
        _render_capture_table(payload)
    return 0


def cmd_dpi(args: argparse.Namespace) -> int:
    try:
        observation = json.loads(args.observation_json)
        payload = analyze_observation(observation, include_payload_preview=args.include_payload_preview)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"DPI error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(payload)
    else:
        findings = payload.get("findings") or []
        print(f"DPI protocol: {payload.get('protocol', 'unknown')}")
        print(f"Risk score: {payload.get('risk_score', 0)}")
        print(f"Findings: {len(findings)}")
        for finding in findings:
            print(f"  {finding.get('severity')}: {finding.get('type')} ({finding.get('evidence')})")
    return 0


def cmd_flows(args: argparse.Namespace) -> int:
    try:
        events = json.loads(args.events_json)
        if not isinstance(events, list):
            raise ValueError("--events-json must decode to a list of packet, capture, or DPI records")
        payload = build_flow_report(events, window_seconds=args.window)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Flow reconstruction error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(payload)
    else:
        _render_flow_table(payload)
    return 0


def cmd_behavior(args: argparse.Namespace) -> int:
    try:
        events = json.loads(args.events_json)
        if not isinstance(events, list):
            raise ValueError("--events-json must decode to a list of flow, packet, or scan records")
        baseline = load_baseline(args.baseline)
        payload = analyze_events(events, baseline, learn=args.learn)
        if args.learn:
            path = save_baseline(payload["baseline"], args.baseline)
            payload["baseline_path"] = str(path)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Behavior analysis error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(payload)
    else:
        _render_behavior_table(payload)
    return 0


def cmd_payload(args: argparse.Namespace) -> int:
    try:
        events = json.loads(args.events_json)
        if isinstance(events, dict):
            events = [events]
        if not isinstance(events, list):
            raise ValueError("--events-json must decode to an object or list of payload observations")
        payload = classify_payload_events(events, include_payload_preview=args.include_payload_preview)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Payload classification error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(payload)
    else:
        _render_payload_table(payload)
    return 0


def cmd_correlate(args: argparse.Namespace) -> int:
    try:
        events = json.loads(args.events_json)
        if not isinstance(events, list):
            raise ValueError("--events-json must decode to a list of normalized or raw event records")
        payload = correlate_events(events, window_seconds=args.window)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Threat correlation error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(payload)
    else:
        _render_correlation_table(payload)
    return 0


def cmd_recommend(args: argparse.Namespace) -> int:
    try:
        payload = json.loads(args.incidents_json)
        if isinstance(payload, dict) and isinstance(payload.get("incidents"), list):
            incidents = payload["incidents"]
        else:
            incidents = payload
        if not isinstance(incidents, list):
            raise ValueError("--incidents-json must decode to a list of incidents or a correlation report object")
        result = generate_recommendations(
            incidents,
            review_threshold=args.review_threshold,
            approval_threshold=args.approval_threshold,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Recommendation error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(result)
    else:
        _render_recommendation_table(result)
    return 0


def cmd_tls(args: argparse.Namespace) -> int:
    try:
        if args.observation_json:
            observation = json.loads(args.observation_json)
            rows = [analyze_tls_observation(observation)]
        else:
            if not args.target:
                raise ValueError("--target is required unless --observation-json is provided")
            rows = inspect_tls_targets(
                args.target,
                ports=_parse_ports(args.ports),
                server_name=args.server_name,
                ip_version=args.ip_version,
                timeout=args.timeout,
                max_targets=args.max_targets,
                max_ports=args.max_ports,
                aggressive=args.aggressive,
            )
    except (argparse.ArgumentTypeError, json.JSONDecodeError, ValueError) as exc:
        print(f"TLS intelligence error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(rows)
    else:
        _render_tls_table(rows)
    return 0


def cmd_cve(args: argparse.Namespace) -> int:
    try:
        if args.update:
            fetched = fetch_nvd_cves(
                keyword=args.query,
                cve_id=args.cve_id,
                api_key=args.api_key,
                limit=args.limit,
            )
            existing = load_cve_cache(args.cache)
            records = merge_cve_records(existing.get("records") or [], fetched["records"])
            saved = save_cve_cache(
                records,
                path=args.cache,
                metadata={"source": "nvd", "query": fetched["query"]},
            )
            payload = {
                "ok": True,
                "mode": "update",
                "fetched_count": fetched["record_count"],
                "stored_count": saved["record_count"],
                "cache_path": saved["cache_path"],
                "records": fetched["records"],
                "automatic_changes": False,
                "raw_payload_stored": False,
            }
        else:
            if args.cve_json:
                cves = load_cves_from_json(args.cve_json)
                source = "inline"
            else:
                cache = load_cve_cache(args.cache)
                cves = cache.get("records") or []
                source = "cache"
            if args.service_json:
                service_payload = json.loads(args.service_json)
                if isinstance(service_payload, dict):
                    if isinstance(service_payload.get("services"), list):
                        services = service_payload["services"]
                    elif isinstance(service_payload.get("results"), list):
                        services = service_payload["results"]
                    else:
                        services = [service_payload]
                elif isinstance(service_payload, list):
                    services = service_payload
                else:
                    raise ValueError("--service-json must decode to a service object/list")
                payload = analyze_service_cves(services, cves, min_confidence=args.min_confidence)
                payload["source"] = source
            else:
                payload = {
                    "ok": True,
                    "mode": "list",
                    "source": source,
                    "record_count": len(cves),
                    "records": cves,
                    "automatic_changes": False,
                    "raw_payload_stored": False,
                }
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        print(f"CVE intelligence error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(payload)
    else:
        _render_cve_table(payload)
    return 0


def cmd_vuln(args: argparse.Namespace) -> int:
    try:
        services: list[dict[str, Any]] = []
        cve_matches: list[dict[str, Any]] | None = None
        cves: list[dict[str, Any]] | None = None
        if args.service_json:
            services = _extract_json_rows(args.service_json, list_keys=("services", "results"))
        if args.cve_matches_json:
            cve_matches = _extract_json_rows(args.cve_matches_json, list_keys=("matches", "cve_matches"))
        if args.cve_json:
            cves = load_cves_from_json(args.cve_json)
        payload = correlate_vulnerabilities(
            services=services,
            cve_matches=cve_matches,
            cves=cves,
            min_confidence=args.min_confidence,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Vulnerability correlation error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(payload)
    else:
        _render_vulnerability_table(payload)
    return 0


def cmd_rbac(args: argparse.Namespace) -> int:
    if args.permission:
        payload = authorize(args.roles or [], args.permission)
    else:
        payload = role_report()
    if args.output == "json":
        _print_json(payload)
    else:
        _render_rbac_table(payload)
    return 0


def cmd_alert(args: argparse.Namespace) -> int:
    try:
        event = json.loads(args.event_json)
        if not isinstance(event, dict):
            raise ValueError("--event-json must decode to an object")
        payload = _format_alert_payload(args.format, event, args)
        delivery = None
        if args.send:
            delivery = _send_alert_payload(args.format, payload, args)
        else:
            delivery = {"ok": True, "integration": args.format, "destination": args.url or args.smtp_host or "", "status": "dry_run", "dry_run": True}
        result = {
            "ok": bool(delivery.get("ok")),
            "format": args.format,
            "payload": _email_payload_summary(payload) if args.format == "email" else payload,
            "delivery": delivery,
            "automatic_changes": False,
            "raw_payload_stored": False,
        }
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Alert integration error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(result)
    else:
        _render_alert_table(result)
    return 0


def cmd_cluster_plan(args: argparse.Namespace) -> int:
    try:
        payload = plan_distributed_scan(
            args.target,
            _parse_ports(args.ports) or [80, 443],
            workers=_parse_cluster_workers(args.worker, args.workers_json),
            ip_version=args.ip_version,
            timeout=args.timeout,
            concurrency=args.concurrency,
            rate_per_second=args.rate,
            max_targets=args.max_targets,
            max_ports=args.max_ports,
            target_chunk_size=args.target_chunk_size,
            port_chunk_size=args.port_chunk_size,
            aggressive=args.aggressive,
        )
    except (argparse.ArgumentTypeError, json.JSONDecodeError, ValueError) as exc:
        print(f"Cluster plan error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(payload)
    else:
        _render_cluster_plan_table(payload)
    return 0


def cmd_visibility(args: argparse.Namespace) -> int:
    try:
        if args.baseline_json or args.current_json:
            if not args.baseline_json or not args.current_json:
                raise ValueError("--baseline-json and --current-json must be provided together")
            baseline = _json_object(args.baseline_json, label="--baseline-json", allow_file=True)
            current = _json_object(args.current_json, label="--current-json", allow_file=True)
            payload = compare_visibility_snapshots(
                baseline,
                current,
                require_approval=not args.no_approval,
            )
            if args.output == "json":
                _print_json(payload)
            else:
                _render_visibility_table(payload)
            return 0

        assets = _extract_json_rows(args.assets_json, list_keys=("assets", "records"), allow_file=True) if args.assets_json else []
        services = _extract_json_rows(args.services_json, list_keys=("services", "results"), allow_file=True) if args.services_json else []
        flows_payload: list[dict[str, Any]] | dict[str, Any] = []
        if args.flows_json:
            parsed_flows = _load_json_arg(args.flows_json)
            if isinstance(parsed_flows, dict):
                flows_payload = parsed_flows
            elif isinstance(parsed_flows, list):
                flows_payload = [row for row in parsed_flows if isinstance(row, dict)]
            else:
                raise ValueError("--flows-json must decode to a flow report object or list")
        policy = _json_object(args.policy_json, label="--policy-json", allow_file=True) if args.policy_json else None
        payload = build_visibility_report(
            assets=assets,
            services=services,
            flows=flows_payload,
            policy=policy,
        )
        if args.include_snapshot or args.snapshot_output:
            snapshot = build_visibility_snapshot(
                assets=assets,
                services=services,
                flows=flows_payload,
                label=args.snapshot_label or "",
                observed_at=args.observed_at,
            )
            payload["snapshot"] = snapshot
            if args.snapshot_output:
                output_path = Path(args.snapshot_output)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as handle:
                    json.dump(snapshot, handle, indent=2, sort_keys=True)
                    handle.write("\n")
                payload["snapshot_output"] = str(output_path)
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        print(f"Visibility summary error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(payload)
    else:
        _render_visibility_table(payload)
    return 0


def cmd_workspace(args: argparse.Namespace) -> int:
    try:
        tenant = _json_object(args.tenant_json, label="--tenant-json")
        organizations = _extract_json_rows(args.org_json, list_keys=("organizations", "orgs"))
        teams = _extract_json_rows(args.team_json, list_keys=("teams",)) if args.team_json else []
        user_roles = _json_object(args.user_roles_json, label="--user-roles-json") if args.user_roles_json else {}
        payload = build_org_directory(
            tenant=tenant,
            organizations=organizations,
            teams=teams,
            user_roles=user_roles,
        )
        if args.user:
            payload["user_access"] = effective_user_access(payload, args.user)
        if args.workspace_json:
            workspace = _json_object(args.workspace_json, label="--workspace-json")
            if args.workspace_output:
                save_result = save_workspace_config(workspace, args.workspace_output)
                payload["workspace_persistence"] = save_result
            else:
                payload["workspace"] = WorkspaceConfig(**workspace).to_dict()
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"Workspace management error: {exc}", file=sys.stderr)
        return 1

    _print_json(payload)
    return 0


def cmd_license(args: argparse.Namespace) -> int:
    try:
        license_data = _json_object(args.license_json, label="--license-json")
        usage_data = _json_object(args.usage_json, label="--usage-json")
        payload = usage_summary(license_data, usage_data)
        if args.feature:
            payload["feature_gate"] = feature_enabled(license_data, args.feature)
        if args.quota:
            payload["quota_check"] = check_quota(license_data, usage_data, args.quota)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"License accounting error: {exc}", file=sys.stderr)
        return 1

    _print_json(payload)
    return 0


def cmd_cloud_sync(args: argparse.Namespace) -> int:
    try:
        if args.import_manifest_json:
            manifest = _json_object(args.import_manifest_json, label="--import-manifest-json")
            payload = import_sync_manifest(manifest, key=args.key)
        elif args.conflicts_json:
            conflict_payload = _json_object(args.conflicts_json, label="--conflicts-json")
            payload = resolve_sync_conflicts(
                conflict_payload.get("local") or [],
                conflict_payload.get("remote") or [],
                key_field=args.key_field,
                policy=args.conflict_policy,
            )
        else:
            source = _json_object(args.payload_json, label="--payload-json")
            payload = export_sync_manifest(
                source,
                tenant_id=args.tenant_id,
                workspace_id=args.workspace_id,
                key=args.key,
                payload_type=args.payload_type,
            )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"Cloud sync error: {exc}", file=sys.stderr)
        return 1

    _print_json(payload)
    return 0


def cmd_advisory_workflow(args: argparse.Namespace) -> int:
    try:
        recommendations = _extract_json_rows(args.recommendation_json, list_keys=("recommendations", "records"))
        if args.transition_id:
            workflow = ReviewWorkflow(recommendations)
            workflow.transition(
                args.transition_id,
                new_state=args.state,
                actor=args.actor,
                actor_roles=args.roles or [],
                note=args.note or "",
            )
            payload = {
                "ok": True,
                "records": workflow.list_records(),
                "audit_events": workflow.audit_events(tenant_id=args.tenant_id),
                "automatic_execution": False,
                "administrator_controlled": True,
            }
        else:
            payload = build_review_packet(recommendations)
    except (json.JSONDecodeError, PermissionError, ValueError, KeyError) as exc:
        print(f"Advisory workflow error: {exc}", file=sys.stderr)
        return 1

    _print_json(payload)
    return 0


def _format_alert_payload(fmt: str, event: dict[str, Any], args: argparse.Namespace) -> Any:
    if fmt in {"generic", "slack", "teams"}:
        return format_webhook_alert(event, style="generic" if fmt == "generic" else fmt)
    if fmt == "splunk":
        return format_splunk_hec_event(event, index=args.index, sourcetype=args.sourcetype)
    if fmt == "elastic":
        if args.bulk:
            return format_elastic_bulk([event], index=args.index or "portmap-alerts")
        return format_elastic_document(event, data_stream=args.data_stream)
    if fmt == "sentinel":
        return format_sentinel_event(event)
    if fmt == "email":
        if not args.sender or not args.recipient:
            raise ValueError("--sender and --recipient are required for email format")
        return format_email_alert(event, sender=args.sender, recipients=args.recipient, subject_prefix=args.subject_prefix)
    raise ValueError(f"unsupported alert format: {fmt}")


def _send_alert_payload(fmt: str, payload: Any, args: argparse.Namespace) -> dict[str, Any]:
    if fmt == "email":
        if not args.smtp_host:
            raise ValueError("--smtp-host is required with --send for email")
        return send_email_alert(
            smtp_host=args.smtp_host,
            smtp_port=args.smtp_port,
            sender=args.sender,
            recipients=args.recipient,
            message=payload,
            dry_run=False,
        )
    if not args.url:
        raise ValueError("--url is required with --send for webhook/SIEM formats")
    if fmt == "splunk":
        if not args.token:
            raise ValueError("--token is required with --send for splunk")
        return send_splunk_hec(args.url, args.token, payload, dry_run=False)
    if fmt == "elastic" and isinstance(payload, str):
        return send_elastic_bulk(args.url, payload, api_key=args.token, dry_run=False)
    return send_webhook_alert(args.url, payload, dry_run=False)


def _email_payload_summary(message: Any) -> dict[str, Any]:
    return {
        "subject": message.get("Subject"),
        "from": message.get("From"),
        "to": message.get("To"),
        "body": message.get_content(),
    }


def _load_json_arg(value: str) -> Any:
    stripped = value.strip()
    if stripped.startswith(("{", "[")):
        return json.loads(value)
    candidate = Path(value)
    if candidate.exists() and candidate.is_file():
        with open(candidate, "r", encoding="utf-8") as handle:
            return json.load(handle)
    return json.loads(value)


def _extract_json_rows(value: str, *, list_keys: tuple[str, ...], allow_file: bool = False) -> list[dict[str, Any]]:
    payload = _load_json_arg(value) if allow_file else json.loads(value)
    if isinstance(payload, dict):
        for key in list_keys:
            if isinstance(payload.get(key), list):
                return [row for row in payload[key] if isinstance(row, dict)]
        return [payload]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    raise ValueError("JSON input must decode to an object, list, or supported report object")


def _json_object(value: str, *, label: str, allow_file: bool = False) -> dict[str, Any]:
    payload = _load_json_arg(value) if allow_file else json.loads(value)
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must decode to an object")
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="portmap", description="PortMap-AI unified local CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan local network sockets")
    scan.add_argument("--kind", choices=["inet", "tcp", "udp"], default="inet", help="psutil connection kind")
    scan.add_argument("--output", choices=["table", "json"], default="table", help="Output format")
    scan.add_argument("--target", help="Run an active TCP scan against this authorized IPv4/IPv6 target or CIDR")
    scan.add_argument("--ports", help="Comma-separated TCP ports/ranges for --target, for example 22,80,443 or 8000-8010")
    scan.add_argument("--ip-version", choices=["auto", "4", "6"], default="auto", help="Target IP version for active TCP scans")
    scan.add_argument("--timeout", type=float, default=1.0, help="Active TCP scan timeout in seconds")
    scan.add_argument("--aggressive", action="store_true", help="Allow active TCP scans above the default safe target/port limits")
    scan.add_argument("--udp-target", help="Run an active UDP probe scan against this authorized target")
    scan.add_argument("--udp-ports", help="Comma-separated UDP ports/ranges, for example 53,123,161 or 53-55")
    scan.add_argument("--udp-timeout", type=float, default=1.0, help="UDP probe timeout in seconds")
    scan.add_argument("--udp-retries", type=int, default=1, help="UDP retry count per port")
    scan.add_argument("--udp-aggressive", action="store_true", help="Allow UDP scans above the default safe port limit")
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

    discover = subparsers.add_parser("discover", help="Inventory authorized network assets")
    discover.add_argument("--range", dest="ranges", action="append", help="Authorized IP, hostname, or CIDR range to inventory")
    discover.add_argument("--local-networks", action="store_true", help="Include detected local private networks")
    discover.add_argument("--method", action="append", choices=["arp", "ping", "tcp"], help="Discovery method; repeat to combine")
    discover.add_argument("--tcp-ports", default="22,80,443", help="Comma-separated TCP ports/ranges for availability checks")
    discover.add_argument("--ip-version", choices=["auto", "4", "6"], default="auto", help="Target IP version")
    discover.add_argument("--timeout", type=float, default=1.0, help="Discovery timeout in seconds")
    discover.add_argument("--max-targets", type=int, default=256, help="Safe target expansion limit")
    discover.add_argument("--aggressive", action="store_true", help="Allow inventory above the default safe target limit")
    discover.add_argument("--node-id", help="Attach a node_id to generated telemetry events")
    discover.add_argument("--topology", action="store_true", help="Include local topology context in JSON output")
    discover.add_argument("--output", choices=["table", "json"], default="table", help="Output format")
    discover.set_defaults(func=cmd_discover)

    services = subparsers.add_parser("services", help="Enumerate services and versions on authorized targets")
    services.add_argument("--target", required=True, help="Authorized IP, hostname, or CIDR range to enumerate")
    services.add_argument("--ports", default="21,22,25,53,80,443,445,587,3389,8080,8443", help="Comma-separated TCP ports/ranges")
    services.add_argument("--ip-version", choices=["auto", "4", "6"], default="auto", help="Target IP version")
    services.add_argument("--timeout", type=float, default=2.0, help="Service probe timeout in seconds")
    services.add_argument("--max-targets", type=int, default=64, help="Safe target expansion limit")
    services.add_argument("--max-ports", type=int, default=128, help="Safe port limit")
    services.add_argument("--aggressive", action="store_true", help="Allow enumeration above the default safe limits")
    services.add_argument("--output", choices=["table", "json"], default="table", help="Output format")
    services.set_defaults(func=cmd_services)

    os_scan = subparsers.add_parser("os", help="Infer probable OS family from passive and service evidence")
    os_scan.add_argument("--target", help="Authorized IP, hostname, or CIDR range to fingerprint")
    os_scan.add_argument("--ports", default="22,80,443,445,3389", help="Comma-separated TCP ports/ranges for service evidence")
    os_scan.add_argument("--ip-version", choices=["auto", "4", "6"], default="auto", help="Target IP version")
    os_scan.add_argument("--timeout", type=float, default=2.0, help="Service probe timeout in seconds")
    os_scan.add_argument("--max-targets", type=int, default=64, help="Safe target expansion limit")
    os_scan.add_argument("--max-ports", type=int, default=128, help="Safe port limit")
    os_scan.add_argument("--aggressive", action="store_true", help="Allow fingerprinting above the default safe limits")
    os_scan.add_argument("--ttl", type=int, help="Observed TTL from passive traffic, if available")
    os_scan.add_argument("--tcp-window", type=int, help="Observed TCP window size, if available")
    os_scan.add_argument("--tcp-options", help="Observed TCP options, comma-separated")
    os_scan.add_argument("--observation-json", help="Passive observation JSON object to fingerprint without probing")
    os_scan.add_argument("--output", choices=["table", "json"], default="table", help="Output format")
    os_scan.set_defaults(func=cmd_os)

    fast_scan = subparsers.add_parser("fast-scan", help="Run safe async TCP scanning on authorized targets")
    fast_scan.add_argument("--target", required=True, help="Authorized IP, hostname, or CIDR range to scan")
    fast_scan.add_argument("--ports", default="80,443", help="Comma-separated TCP ports/ranges")
    fast_scan.add_argument("--ip-version", choices=["auto", "4", "6"], default="auto", help="Target IP version")
    fast_scan.add_argument("--timeout", type=float, default=1.0, help="Per-port timeout in seconds")
    fast_scan.add_argument("--concurrency", type=int, default=64, help="Maximum concurrent probes")
    fast_scan.add_argument("--rate", type=float, default=128.0, help="Maximum probe start rate per second")
    fast_scan.add_argument("--max-targets", type=int, default=256, help="Safe target expansion limit")
    fast_scan.add_argument("--max-ports", type=int, default=1024, help="Safe port limit")
    fast_scan.add_argument("--aggressive", action="store_true", help="Allow higher scan volume; only use on authorized networks")
    fast_scan.add_argument("--output", choices=["table", "json"], default="table", help="Output format")
    fast_scan.set_defaults(func=cmd_fast_scan)

    capture = subparsers.add_parser("capture", help="Capture packet metadata on a supported local interface")
    capture.add_argument("--interface", help="Network interface name; defaults to the first detected non-loopback interface")
    capture.add_argument("--duration", type=float, default=5.0, help="Capture duration in seconds")
    capture.add_argument("--max-packets", type=int, default=100, help="Maximum packets to retain in metadata output")
    capture.add_argument("--filter", help="Simple capture filter: tcp, udp, icmp, arp, ip, ipv6, host IP, port N, src/dst host IP, or src/dst port N")
    capture.add_argument("--pcap", help="Optional path to save filtered packets as a classic PCAP file")
    capture.add_argument("--dissect", action="store_true", help="Attach safe protocol dissection summaries to captured packet metadata")
    capture.add_argument("--dpi", action="store_true", help="Attach passive DPI metadata and findings to captured packet metadata")
    capture.add_argument("--flows", action="store_true", help="Attach passive traffic-flow summaries for captured packet metadata")
    capture.add_argument("--output", choices=["table", "json"], default="table", help="Output format")
    capture.set_defaults(func=cmd_capture)

    dpi = subparsers.add_parser("dpi", help="Analyze a passive packet/payload observation without storing raw payload output")
    dpi.add_argument("--observation-json", required=True, help="JSON object with metadata plus payload_text, payload_hex, or payload_b64")
    dpi.add_argument("--include-payload-preview", action="store_true", help="Include a short redacted payload preview")
    dpi.add_argument("--output", choices=["text", "json"], default="json", help="Output format")
    dpi.set_defaults(func=cmd_dpi)

    flows = subparsers.add_parser("flows", help="Reconstruct passive traffic flows from packet, capture, or DPI records")
    flows.add_argument("--events-json", required=True, help="JSON list of packet metadata, capture rows, or DPI records")
    flows.add_argument("--window", type=float, default=60.0, help="Maximum idle gap in seconds before opening a new flow")
    flows.add_argument("--output", choices=["table", "json"], default="json", help="Output format")
    flows.set_defaults(func=cmd_flows)

    behavior = subparsers.add_parser("behavior", help="Analyze local behavior against learned device baselines")
    behavior.add_argument("--events-json", required=True, help="JSON list of flow, packet, scan, or service records")
    behavior.add_argument("--baseline", help="Behavior baseline JSON path; defaults to ~/.portmap-ai/data/behavior_baseline.json")
    behavior.add_argument("--learn", action="store_true", help="Update the baseline with the supplied events after analysis")
    behavior.add_argument("--output", choices=["table", "json"], default="json", help="Output format")
    behavior.set_defaults(func=cmd_behavior)

    payload = subparsers.add_parser("payload", help="Classify payload observations using local AI metadata rules")
    payload.add_argument("--events-json", required=True, help="JSON object/list with payload_text, payload_hex, payload_b64, or payload metadata")
    payload.add_argument("--include-payload-preview", action="store_true", help="Include short redacted payload previews")
    payload.add_argument("--output", choices=["table", "json"], default="json", help="Output format")
    payload.set_defaults(func=cmd_payload)

    correlate = subparsers.add_parser("correlate", help="Correlate local security events into advisory threat incidents")
    correlate.add_argument("--events-json", required=True, help="JSON list of behavior, payload, flow, scan, or service events")
    correlate.add_argument("--window", type=float, default=300.0, help="Correlation window in seconds")
    correlate.add_argument("--output", choices=["table", "json"], default="json", help="Output format")
    correlate.set_defaults(func=cmd_correlate)

    recommend = subparsers.add_parser("recommend", help="Generate advisory recommendations from correlated incidents")
    recommend.add_argument("--incidents-json", required=True, help="JSON list of incidents or a correlation report with incidents")
    recommend.add_argument("--review-threshold", type=float, default=0.6, help="Review threshold for advisory recommendations")
    recommend.add_argument("--approval-threshold", type=float, default=0.8, help="Score threshold for dry-run approval-required recommendations")
    recommend.add_argument("--output", choices=["table", "json"], default="json", help="Output format")
    recommend.set_defaults(func=cmd_recommend)

    tls = subparsers.add_parser("tls", help="Inspect TLS posture for authorized endpoints")
    tls.add_argument("--target", help="Authorized IP, hostname, or CIDR range to inspect")
    tls.add_argument("--ports", default="443", help="Comma-separated TLS ports/ranges")
    tls.add_argument("--server-name", help="SNI and certificate hostname to evaluate")
    tls.add_argument("--ip-version", choices=["auto", "4", "6"], default="auto", help="Target IP version")
    tls.add_argument("--timeout", type=float, default=3.0, help="TLS handshake timeout in seconds")
    tls.add_argument("--max-targets", type=int, default=32, help="Safe target expansion limit")
    tls.add_argument("--max-ports", type=int, default=32, help="Safe port limit")
    tls.add_argument("--aggressive", action="store_true", help="Allow inspection above the default safe limits")
    tls.add_argument("--observation-json", help="Offline TLS observation JSON object to evaluate without a network handshake")
    tls.add_argument("--output", choices=["table", "json"], default="json", help="Output format")
    tls.set_defaults(func=cmd_tls)

    cve = subparsers.add_parser("cve", help="Match service evidence against local or NVD CVE intelligence")
    cve.add_argument("--service-json", help="Service row/list or service enumeration report to match")
    cve.add_argument("--cve-json", help="Inline CVE list/object or NVD response JSON for offline analysis")
    cve.add_argument("--cache", help="Local CVE cache path; defaults to ~/.portmap-ai/data/cve_cache.json")
    cve.add_argument("--min-confidence", type=float, default=0.25, help="Minimum local match confidence")
    cve.add_argument("--update", action="store_true", help="Fetch CVEs from NVD and update the local cache")
    cve.add_argument("--query", help="NVD keyword query for --update")
    cve.add_argument("--cve-id", help="Specific CVE ID for --update")
    cve.add_argument("--api-key", help="Optional NVD API key")
    cve.add_argument("--limit", type=int, default=50, help="Maximum NVD records to fetch")
    cve.add_argument("--output", choices=["table", "json"], default="json", help="Output format")
    cve.set_defaults(func=cmd_cve)

    vuln = subparsers.add_parser("vuln", help="Prioritize advisory vulnerability findings from service and CVE evidence")
    vuln.add_argument("--service-json", help="Service row/list or service enumeration report")
    vuln.add_argument("--cve-matches-json", help="CVE match row/list or CVE intelligence report")
    vuln.add_argument("--cve-json", help="Inline CVE list/object or NVD response JSON for matching against services")
    vuln.add_argument("--min-confidence", type=float, default=0.25, help="Minimum CVE match confidence when matching raw CVEs")
    vuln.add_argument("--output", choices=["table", "json"], default="json", help="Output format")
    vuln.set_defaults(func=cmd_vuln)

    rbac = subparsers.add_parser("rbac", help="Inspect local enterprise RBAC permissions")
    rbac.add_argument("--roles", action="append", help="Role or comma-separated roles to evaluate")
    rbac.add_argument("--permission", help="Permission to check, for example read:nodes")
    rbac.add_argument("--output", choices=["table", "json"], default="json", help="Output format")
    rbac.set_defaults(func=cmd_rbac)

    alert = subparsers.add_parser("alert", help="Format or explicitly send alert/SIEM payloads")
    alert.add_argument("--event-json", required=True, help="Alert event JSON object")
    alert.add_argument("--format", choices=["generic", "slack", "teams", "splunk", "elastic", "sentinel", "email"], default="generic")
    alert.add_argument("--send", action="store_true", help="Actually deliver the payload; default is dry-run formatting")
    alert.add_argument("--url", help="Webhook, Splunk HEC, or Elastic endpoint URL for --send")
    alert.add_argument("--token", help="Splunk HEC token or Elastic API key")
    alert.add_argument("--index", help="Splunk index or Elastic index")
    alert.add_argument("--sourcetype", default="portmap:alert", help="Splunk source type")
    alert.add_argument("--data-stream", default="logs-portmap.alerts-default", help="Elastic data stream")
    alert.add_argument("--bulk", action="store_true", help="Format Elastic output as bulk NDJSON")
    alert.add_argument("--sender", help="Email sender address")
    alert.add_argument("--recipient", action="append", help="Email recipient; repeat to add recipients")
    alert.add_argument("--subject-prefix", default="[PortMap-AI]", help="Email subject prefix")
    alert.add_argument("--smtp-host", help="SMTP host for --send email")
    alert.add_argument("--smtp-port", type=int, default=25, help="SMTP port for --send email")
    alert.add_argument("--output", choices=["table", "json"], default="json", help="Output format")
    alert.set_defaults(func=cmd_alert)

    cluster = subparsers.add_parser("cluster", help="Distributed cluster scanning utilities")
    cluster_subparsers = cluster.add_subparsers(dest="cluster_command", required=True)
    cluster_plan = cluster_subparsers.add_parser("plan", help="Build a dry-run distributed scan job plan")
    cluster_plan.add_argument("--target", required=True, help="Authorized IP, hostname, or CIDR range to partition")
    cluster_plan.add_argument("--ports", default="80,443", help="Comma-separated TCP ports/ranges")
    cluster_plan.add_argument("--worker", action="append", help="Available worker as node_id or node_id@address; repeat to add workers")
    cluster_plan.add_argument("--workers-json", help="Worker list JSON or object with workers list")
    cluster_plan.add_argument("--ip-version", choices=["auto", "4", "6"], default="auto", help="Target IP version")
    cluster_plan.add_argument("--timeout", type=float, default=1.0, help="Per-task scan timeout in seconds")
    cluster_plan.add_argument("--concurrency", type=int, default=64, help="Maximum per-worker probe concurrency")
    cluster_plan.add_argument("--rate", type=float, default=128.0, help="Maximum per-worker probe start rate")
    cluster_plan.add_argument("--max-targets", type=int, default=256, help="Safe target expansion limit")
    cluster_plan.add_argument("--max-ports", type=int, default=1024, help="Safe port limit")
    cluster_plan.add_argument("--target-chunk-size", type=int, default=16, help="Targets per distributed task")
    cluster_plan.add_argument("--port-chunk-size", type=int, default=64, help="Ports per distributed task")
    cluster_plan.add_argument("--aggressive", action="store_true", help="Allow planning above default safe limits")
    cluster_plan.add_argument("--output", choices=["table", "json"], default="json", help="Output format")
    cluster_plan.set_defaults(func=cmd_cluster_plan)

    visibility = subparsers.add_parser("visibility", help="Summarize assets, services, flows, and operator review drafts")
    visibility.add_argument("--assets-json", help="Asset inventory row/list, discover JSON report, or JSON file path")
    visibility.add_argument("--services-json", help="Service row/list, services JSON report, or JSON file path")
    visibility.add_argument("--flows-json", help="Flow row/list, flow report JSON, or JSON file path")
    visibility.add_argument("--policy-json", help="Optional visibility policy JSON object or JSON file path")
    visibility.add_argument("--include-snapshot", action="store_true", help="Include a stable visibility snapshot in the report")
    visibility.add_argument("--snapshot-output", help="Optional path to write the generated visibility snapshot JSON")
    visibility.add_argument("--snapshot-label", help="Optional label for a generated snapshot")
    visibility.add_argument("--observed-at", help="Optional timestamp or label for the generated snapshot observation time")
    visibility.add_argument("--baseline-json", help="Baseline visibility snapshot JSON object or file path for comparison")
    visibility.add_argument("--current-json", help="Current visibility snapshot JSON object or file path for comparison")
    visibility.add_argument("--no-approval", action="store_true", help="Mark comparison review drafts as not requiring approval")
    visibility.add_argument("--output", choices=["table", "json"], default="json", help="Output format")
    visibility.set_defaults(func=cmd_visibility)

    workspace = subparsers.add_parser("workspace", help="Manage local tenant, organization, team, and workspace metadata")
    workspace.add_argument("--tenant-json", required=True, help="Tenant record JSON object")
    workspace.add_argument("--org-json", required=True, help="Organization record/list JSON")
    workspace.add_argument("--team-json", help="Team record/list JSON")
    workspace.add_argument("--user-roles-json", help="Mapping of user IDs to direct roles")
    workspace.add_argument("--user", help="Show effective access for a user")
    workspace.add_argument("--workspace-json", help="Workspace configuration JSON object")
    workspace.add_argument("--workspace-output", help="Optional path to persist workspace configuration")
    workspace.set_defaults(func=cmd_workspace)

    license_cmd = subparsers.add_parser("license", help="Summarize local license metadata and usage counters")
    license_cmd.add_argument("--license-json", required=True, help="License metadata JSON object")
    license_cmd.add_argument("--usage-json", required=True, help="Usage counter JSON object")
    license_cmd.add_argument("--feature", help="Feature gate to evaluate")
    license_cmd.add_argument("--quota", help="Quota name to evaluate")
    license_cmd.set_defaults(func=cmd_license)

    cloud_sync = subparsers.add_parser("cloud-sync", help="Export, import, or compare optional encrypted sync manifests")
    cloud_sync.add_argument("--payload-json", help="Configuration or observability metadata JSON object to export")
    cloud_sync.add_argument("--tenant-id", help="Tenant ID for manifest export")
    cloud_sync.add_argument("--workspace-id", help="Workspace ID for manifest export")
    cloud_sync.add_argument("--key", required=True, help="Local sync encryption key")
    cloud_sync.add_argument("--payload-type", default="configuration", help="Manifest payload type")
    cloud_sync.add_argument("--import-manifest-json", help="Manifest JSON object to import/decrypt")
    cloud_sync.add_argument("--conflicts-json", help="JSON object with local and remote record lists for conflict resolution")
    cloud_sync.add_argument("--key-field", default="id", help="Record identifier field for conflict resolution")
    cloud_sync.add_argument("--conflict-policy", choices=["prefer_local", "prefer_remote", "manual_review"], default="manual_review")
    cloud_sync.set_defaults(func=cmd_cloud_sync)

    advisory = subparsers.add_parser("advisory", help="Create administrator-facing recommendation review workflows")
    advisory.add_argument("--recommendation-json", required=True, help="Recommendation object/list or review packet JSON")
    advisory.add_argument("--transition-id", help="Recommendation ID to transition")
    advisory.add_argument("--state", default="pending_review", help="New review state when --transition-id is used")
    advisory.add_argument("--actor", default="operator", help="Actor recording the transition")
    advisory.add_argument("--roles", action="append", help="Actor role or comma-separated roles")
    advisory.add_argument("--tenant-id", help="Tenant ID for generated audit events")
    advisory.add_argument("--note", help="Review note")
    advisory.set_defaults(func=cmd_advisory_workflow)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
