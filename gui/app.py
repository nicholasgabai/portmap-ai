from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib import error, request

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Static, Label

from core_engine.config_loader import load_settings, save_settings
from core_engine.log_exporter import export_logs, resolve_export_dir

ORCHESTRATOR_STATE = Path.home() / ".portmap-ai" / "data" / "orchestrator_state.json"
MASTER_LOG = Path.home() / ".portmap-ai" / "logs" / "master.log"
MASTER_EVENTS_LOG = Path.home() / ".portmap-ai" / "logs" / "master_events.log"
REMEDIATION_LOG = Path.home() / ".portmap-ai" / "logs" / "remediation_events.jsonl"
COMMAND_AUDIT_LOG = Path.home() / ".portmap-ai" / "logs" / "command_events.jsonl"
DEFAULT_ORCHESTRATOR_URL = os.environ.get("PORTMAP_ORCHESTRATOR_URL", "http://127.0.0.1:9100")
DEFAULT_ORCHESTRATOR_TOKEN = os.environ.get("PORTMAP_ORCHESTRATOR_TOKEN", "test-token")


def _format_score_factors(event: Dict[str, Any], limit: int = 2) -> str:
    factors = event.get("score_factors") or []
    if not factors:
        action = str(event.get("action") or "").lower()
        reason = str(event.get("reason") or "")
        if action == "monitor" and reason.startswith("score<"):
            return "below_threshold"
        return "-"
    trimmed = [str(item) for item in factors[:limit]]
    suffix = "..." if len(factors) > limit else ""
    return ", ".join(trimmed) + suffix


def _format_command_result(event: Dict[str, Any]) -> str:
    if event.get("error"):
        return str(event["error"])
    result = event.get("result") or {}
    if not result:
        return "-"
    parts = [f"{key}={value}" for key, value in result.items()]
    return ", ".join(parts[:3])


def _format_risk_score(value: Any) -> str:
    if value in {"", "-", None}:
        return "-"
    try:
        return f"{float(value):.3f}"
    except Exception:
        return str(value)


def _format_timestamp(value: Any) -> str:
    if value in {"", "-", None}:
        return "-"
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return str(value)


def _scan_rows_from_telemetry(events: List[Dict[str, Any]], limit: int = 20) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for event in events:
        node_id = event.get("node_id", "-")
        event_score = event.get("risk_score", event.get("score", "-"))
        event_factors = event.get("score_factors") or []
        for port in event.get("ports_sample") or []:
            if not isinstance(port, dict):
                continue
            rows.append(
                {
                    "timestamp": event.get("timestamp", "-"),
                    "node_id": node_id,
                    "program": port.get("program") or "-",
                    "port": port.get("port", "-"),
                    "protocol": port.get("protocol") or port.get("service_name") or "-",
                    "status": port.get("status") or "-",
                    "score": port.get("score", event_score),
                    "score_factors": port.get("score_factors") or event_factors,
                    "risk_explanation": port.get("risk_explanation") or "",
                    "ai_provider": port.get("ai_provider") or "-",
                }
            )
    return rows[-limit:]


def _scan_rows_from_remediation(events: List[Dict[str, Any]], limit: int = 20) -> List[Dict[str, Any]]:
    rows = []
    for event in events:
        if not event.get("port"):
            continue
        rows.append(
            {
                "timestamp": event.get("timestamp", "-"),
                "node_id": event.get("node_id", "-"),
                "program": event.get("program") or "-",
                "port": event.get("port", "-"),
                "protocol": event.get("protocol") or "-",
                "status": event.get("status") or "-",
                "score": event.get("risk_score", event.get("score", "-")),
                "score_factors": event.get("score_factors") or [],
                "risk_explanation": event.get("reason") or "",
                "ai_provider": event.get("ai_provider") or "-",
            }
        )
    return rows[-limit:]


def _service_from_event(event: Dict[str, Any]) -> Dict[str, Any] | None:
    port = event.get("port")
    if not port:
        return None
    service = {
        "port": int(port),
        "program": event.get("program") or "",
        "protocol": event.get("protocol") or "",
        "reason": "dashboard allowlist",
    }
    return {key: value for key, value in service.items() if value not in {"", None}}


def _service_key(service: Dict[str, Any]) -> str:
    return "|".join(
        [
            str(service.get("port") or ""),
            str(service.get("protocol") or "").upper(),
            str(service.get("program") or "").lower(),
        ]
    )


def _service_label(service: Dict[str, Any] | None) -> str:
    if not service:
        return "-"
    program = service.get("program") or "any"
    protocol = service.get("protocol") or "any"
    port = service.get("port") or "?"
    reason = service.get("reason")
    label = f"{program} {protocol}:{port}"
    return f"{label} ({reason})" if reason else label


def _merge_expected_service(settings: Dict[str, Any], service: Dict[str, Any]) -> bool:
    expected = [item for item in settings.get("expected_services", []) if isinstance(item, dict)]
    service_key = _service_key(service)
    if any(_service_key(item) == service_key for item in expected):
        return False
    expected.append(service)
    settings["expected_services"] = expected
    return True


def _remove_expected_service(settings: Dict[str, Any], service: Dict[str, Any]) -> bool:
    expected = [item for item in settings.get("expected_services", []) if isinstance(item, dict)]
    service_key = _service_key(service)
    filtered = [item for item in expected if _service_key(item) != service_key]
    if len(filtered) == len(expected):
        return False
    settings["expected_services"] = filtered
    return True


def _panel_heading(title: str, subtitle: str) -> str:
    return f"{title}\n{subtitle}"


def _resolve_firewall_status(settings: Dict[str, Any]) -> Dict[str, str]:
    firewall = settings.get("firewall") or {}
    options = firewall.get("options") or {}
    plugin = str(firewall.get("plugin") or "noop")
    if "dry_run" in firewall:
        dry_run = bool(firewall["dry_run"])
    elif "dry_run" in options:
        dry_run = bool(options["dry_run"])
    else:
        dry_run = True
    enforcement = "dry_run" if dry_run else "active"
    return {"plugin": plugin, "enforcement": enforcement}


def _operator_help_text(export_dir: Path, firewall_status: Dict[str, str]) -> str:
    return (
        "PortMap-AI Dashboard\n\n"
        "Start here:\n"
        "1. Confirm a worker is online in Node Overview.\n"
        "2. Press Scan Now to ask that worker to scan immediately.\n"
        "3. Review Remediation Feed for the decision and Signals.\n\n"
        "Terms:\n"
        "- monitor: observed but not risky enough to act.\n"
        "- prompt_operator: score crossed the threshold; human review is needed.\n"
        "- block: remediation would block the connection when enforcement is enabled.\n"
        "- Signals: short explanations for why a connection scored the way it did.\n"
        "- below_threshold: score was lower than the remediation threshold.\n\n"
        "Safety:\n"
        f"- Firewall plugin: {firewall_status.get('plugin', 'noop')}\n"
        f"- Enforcement mode: {firewall_status.get('enforcement', 'dry_run')}\n"
        "- dry_run means PortMap-AI logs what it would do without changing the firewall.\n\n"
        "Panels:\n"
        "- Node Overview: registered workers and last heartbeat.\n"
        "- Scan Results: latest sampled ports with risk scores, provider, and signals.\n"
        "- Remediation Feed: recent decisions for scanned connections.\n"
        "- Expected Services: move normal services into the allowlist so scoring explains them as expected.\n"
        "- Command Outcomes: whether queued commands were received, applied, failed, or ignored.\n"
        "- Master Log Tail: most recent master-node runtime lines.\n\n"
        f"Export destination: {export_dir}\n"
        "Shortcuts: ? help, e export logs"
    )


class NodeTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Node ID")
        self.add_column("Role")
        self.add_column("Status")
        self.add_column("Last Seen")

    def update_nodes(self, nodes: List[Dict[str, Any]]):
        self.clear()
        for node in nodes:
            self.add_row(
                node.get("node_id", "-"),
                node.get("role", "-"),
                node.get("status", "-"),
                str(node.get("last_seen", "-")),
                key=node.get("node_id", "-"),
            )


def _compute_metrics(nodes: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(nodes)
    online = sum(1 for n in nodes if (n.get("status") or "").lower() in {"online", "ready"})
    last_seen = None
    if nodes:
        last_seen = max((n.get("last_seen") for n in nodes if n.get("last_seen")), default=None)
    counts = {"monitor": 0, "review": 0, "block": 0}
    for event in events:
        action = (event.get("action") or "").lower()
        if action in counts:
            counts[action] += 1
    return {
        "total_nodes": total,
        "online_nodes": online,
        "last_seen": last_seen,
        "counts": counts,
    }


class MetricsPanel(Static):
    def update_metrics(self, metrics: Dict[str, Any]) -> None:
        last_seen = metrics.get("last_seen")
        if last_seen:
            try:
                last_seen_str = datetime.fromtimestamp(last_seen).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                last_seen_str = str(last_seen)
        else:
            last_seen_str = "-"
        counts = metrics.get("counts", {})
        firewall_status = metrics.get("firewall_status", {})
        text = (
            f"Nodes online: {metrics.get('online_nodes', 0)}/{metrics.get('total_nodes', 0)}\n"
            f"Last heartbeat: {last_seen_str}\n"
            f"Remediation totals - monitor: {counts.get('monitor', 0)}, "
            f"review: {counts.get('review', 0)}, block: {counts.get('block', 0)}\n"
            f"Firewall: {firewall_status.get('plugin', 'noop')} "
            f"({firewall_status.get('enforcement', 'dry_run')})"
        )
        health = metrics.get("orchestrator_health") or {}
        if health:
            counters = health.get("metrics") or {}
            text += (
                f"\nOrchestrator: {health.get('status', 'unknown')} at {health.get('url', '-')}\n"
                f"API counters - registers: {counters.get('registers', '-')}, "
                f"heartbeats: {counters.get('heartbeats', '-')}, "
                f"queued: {counters.get('commands_queued', '-')}"
            )
        self.update(text)


class LogPanel(Static):
    MAX_LINES = 200  # hard guard so we don't flood the view even when tail size grows

    def update_log(self, lines: List[str]) -> None:
        text = "\n".join(lines[-self.MAX_LINES :])
        self.update(text)


class HelpModal(ModalScreen[None]):
    def __init__(self, export_dir: Path, firewall_status: Dict[str, str]):
        super().__init__()
        self.export_dir = export_dir
        self.firewall_status = firewall_status

    def compose(self) -> ComposeResult:
        yield Container(Label(_operator_help_text(self.export_dir, self.firewall_status)))

    def on_key(self, event) -> None:  # type: ignore[override]
        self.dismiss(None)


class RemediationPanel(DataTable):
    def on_mount(self) -> None:
        self.add_column("Timestamp")
        self.add_column("Node")
        self.add_column("Action")
        self.add_column("Enforcement")
        self.add_column("Reason")
        self.add_column("Score")
        self.add_column("Signals")

    def update_events(self, events: List[Dict[str, Any]]) -> None:
        self.clear()
        for event in events:
            self.add_row(
                event.get("timestamp", "-"),
                event.get("node_id", "-"),
                event.get("action", "-"),
                event.get("enforcement", "dry_run" if event.get("dry_run") else "-"),
                event.get("reason", "-"),
                f"{event.get('score', '-')}",
                _format_score_factors(event),
            )


class ScanResultsPanel(DataTable):
    def on_mount(self) -> None:
        self.add_column("Timestamp")
        self.add_column("Node")
        self.add_column("Program")
        self.add_column("Port")
        self.add_column("Protocol")
        self.add_column("Status")
        self.add_column("Score")
        self.add_column("Provider")
        self.add_column("Signals")

    def update_results(self, rows: List[Dict[str, Any]]) -> None:
        self.clear()
        for row in rows:
            self.add_row(
                _format_timestamp(row.get("timestamp")),
                str(row.get("node_id", "-")),
                str(row.get("program", "-")),
                str(row.get("port", "-")),
                str(row.get("protocol", "-")),
                str(row.get("status", "-")),
                _format_risk_score(row.get("score")),
                str(row.get("ai_provider", "-")),
                _format_score_factors(row),
            )


class CommandPanel(DataTable):
    def on_mount(self) -> None:
        self.add_column("Timestamp")
        self.add_column("Node")
        self.add_column("Command")
        self.add_column("Status")
        self.add_column("Result")

    def update_commands(self, events: List[Dict[str, Any]]) -> None:
        self.clear()
        for event in events:
            self.add_row(
                event.get("timestamp", "-"),
                event.get("node_id", "-"),
                event.get("command_type", "-"),
                event.get("status", "-"),
                _format_command_result(event),
            )


class ExpectedServicesPanel(DataTable):
    def on_mount(self) -> None:
        self.add_column("Observed Candidates")
        self.add_column("Allowlisted Services")

    def update_services(
        self,
        candidates: List[Dict[str, Any]],
        expected_services: List[Dict[str, Any]],
    ) -> None:
        self.clear()
        rows = max(len(candidates), len(expected_services), 1)
        for index in range(rows):
            candidate = candidates[index] if index < len(candidates) else None
            expected = expected_services[index] if index < len(expected_services) else None
            self.add_row(_service_label(candidate), _service_label(expected), key=str(index))


class PortMapDashboard(App):
    CSS = """
    .panel-heading {
        padding: 0 1;
        color: $text-muted;
    }
    #log-panel {
        height: 12;
        overflow-y: auto;
    }
    #command-bar {
        height: 3;
        dock: bottom;
        background: $surface;
    }
    #status-msg {
        padding-left: 1;
        color: $text-muted;
    }
    """

    BINDINGS = [
        ("?", "show_help", "Show help"),
        ("e", "export_logs", "Export logs"),
    ]

    scan_interval = reactive(5)
    tail_size = reactive(10)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container():
            yield Static(
                _panel_heading(
                    "Start Here",
                    "Confirm worker online, press Scan Now, then review Remediation Feed and Signals. Press ? for definitions.",
                ),
                classes="panel-heading",
            )
            with Horizontal():
                with Container():
                    yield Static(
                        _panel_heading("Node Overview", "Workers, role, current status, and last heartbeat"),
                        classes="panel-heading",
                    )
                    self.node_table = NodeTable()
                    yield self.node_table
                with Container():
                    self.metrics_panel = MetricsPanel()
                    yield self.metrics_panel
                    yield Static(
                        _panel_heading(
                            "Scan Results",
                            "Latest sampled ports, risk scores, AI provider, and scoring signals.",
                        ),
                        classes="panel-heading",
                    )
                    self.scan_results_panel = ScanResultsPanel()
                    yield self.scan_results_panel
                    yield Static(
                        _panel_heading(
                            "Remediation Feed",
                            "Each row is a remediation event. Enforcement shows dry-run vs active mode.",
                        ),
                        classes="panel-heading",
                    )
                    self.remediation_panel = RemediationPanel()
                    yield self.remediation_panel
            yield Static(
                _panel_heading(
                    "Expected Services",
                    "Observed candidates are auto-detected. Add normal services to reduce noise.",
                ),
                classes="panel-heading",
            )
            self.expected_services_panel = ExpectedServicesPanel()
            yield self.expected_services_panel
            yield Static(
                _panel_heading(
                    "Command Outcomes",
                    "Recent worker command audit events: received, applied, failed, or ignored.",
                ),
                classes="panel-heading",
            )
            self.command_panel = CommandPanel()
            yield self.command_panel
            yield Static(
                _panel_heading("Master Log Tail", "Most recent master-node log lines for the active stack session"),
                classes="panel-heading",
            )
            self.log_panel = LogPanel(id="log-panel")
            yield self.log_panel
            self.command_bar = Horizontal(
                Button("Scan Now", id="cmd-scan"),
                Button("Toggle Autolearn", id="cmd-autolearn"),
                Button("Detect Orchestrator", id="cmd-detect"),
                Button("Export Logs", id="cmd-export"),
                Button("Allowlist Selected", id="cmd-allowlist-add"),
                Button("Remove Allowlist", id="cmd-allowlist-remove"),
                Button("Tail: 10", id="cmd-tail"),
                Static("", id="status-msg"),
                id="command-bar",
            )
            yield self.command_bar
        yield Footer()

    async def on_mount(self) -> None:
        self._load_orchestrator_defaults()
        self.runtime_settings = load_settings(defaults={})
        self.firewall_status = _resolve_firewall_status(self.runtime_settings)
        self.export_dir = resolve_export_dir()
        self._allowlist_candidates: List[Dict[str, Any]] = []
        self._expected_services: List[Dict[str, Any]] = []
        self._nodes_cache: List[Dict[str, Any]] = []
        self.refresh_task = asyncio.create_task(self.auto_refresh())
        self._set_status(f"Export destination: {self.export_dir}")

    async def on_unmount(self) -> None:
        if hasattr(self, "refresh_task"):
            self.refresh_task.cancel()

    async def auto_refresh(self) -> None:
        while True:
            try:
                self.refresh_state()
            except Exception as exc:
                self.log("Failed to refresh dashboard: %s", exc)
            await asyncio.sleep(self.scan_interval)

    def refresh_state(self) -> None:
        nodes = self._load_nodes()
        self._nodes_cache = nodes
        self.node_table.update_nodes(nodes)
        logs = self._tail_log()
        self.log_panel.update_log(logs)
        remediation_events = self._load_remediation_events(limit=self.tail_size)
        self.remediation_panel.update_events(remediation_events)
        scan_results = self._load_scan_results(remediation_events, limit=self.tail_size)
        self.scan_results_panel.update_results(scan_results)
        self._allowlist_candidates = self._build_allowlist_candidates(remediation_events)
        self._expected_services = [
            item for item in self.runtime_settings.get("expected_services", []) if isinstance(item, dict)
        ]
        self.expected_services_panel.update_services(self._allowlist_candidates, self._expected_services)
        command_events = self._load_command_events(limit=self.tail_size)
        self.command_panel.update_commands(command_events)
        if hasattr(self, "metrics_panel"):
            metrics = _compute_metrics(nodes, remediation_events)
            metrics["firewall_status"] = getattr(self, "firewall_status", _resolve_firewall_status({}))
            metrics["orchestrator_health"] = self._load_orchestrator_health()
            self.metrics_panel.update_metrics(metrics)

    def _load_orchestrator_defaults(self) -> None:
        # Environment variables take precedence
        url = os.environ.get("PORTMAP_ORCHESTRATOR_URL")
        token = os.environ.get("PORTMAP_ORCHESTRATOR_TOKEN")

        if not url or token is None:
            try:
                settings = load_settings(defaults={})
            except Exception:
                settings = {}
            url = url or settings.get("orchestrator_url")
            token = token if token is not None else settings.get("orchestrator_token")

        self.orchestrator_url = url or DEFAULT_ORCHESTRATOR_URL
        # Fall back to dev token if nothing provided to avoid 401s in dev stacks
        self.orchestrator_token = token or DEFAULT_ORCHESTRATOR_TOKEN

    def _load_nodes(self) -> List[Dict[str, Any]]:
        if not ORCHESTRATOR_STATE.exists():
            return []
        try:
            data = json.loads(ORCHESTRATOR_STATE.read_text())
            return list(data.get("nodes", {}).values())
        except Exception:
            return []

    def _tail_log(self) -> List[str]:
        if not MASTER_LOG.exists():
            return []
        try:
            lines = MASTER_LOG.read_text().splitlines()
            # limit by user tail size then hard-cap by panel max
            return lines[-min(LogPanel.MAX_LINES, self.tail_size) :]
        except Exception:
            return []

    def _load_remediation_events(self, limit: int = 200) -> List[Dict[str, Any]]:
        if not REMEDIATION_LOG.exists():
            return []
        events = []
        try:
            for line in REMEDIATION_LOG.read_text().splitlines()[-limit:]:
                try:
                    events.append(json.loads(line))
                except Exception:
                    continue
        except Exception:
            return []
        return events

    def _load_worker_telemetry_events(self, limit: int = 200) -> List[Dict[str, Any]]:
        if not MASTER_EVENTS_LOG.exists():
            return []
        events = []
        try:
            for line in MASTER_EVENTS_LOG.read_text().splitlines()[-limit:]:
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "worker_telemetry":
                        events.append(event)
                except Exception:
                    continue
        except Exception:
            return []
        return events

    def _load_scan_results(
        self,
        remediation_events: List[Dict[str, Any]] | None = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        telemetry_rows = _scan_rows_from_telemetry(self._load_worker_telemetry_events(limit=limit), limit=limit)
        if telemetry_rows:
            return telemetry_rows
        return _scan_rows_from_remediation(remediation_events or [], limit=limit)

    def _build_allowlist_candidates(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        candidates = []
        seen = set()
        expected_keys = {_service_key(service) for service in self.runtime_settings.get("expected_services", []) if isinstance(service, dict)}
        for event in reversed(events):
            service = _service_from_event(event)
            if not service:
                continue
            key = _service_key(service)
            if key in seen or key in expected_keys:
                continue
            seen.add(key)
            candidates.append(service)
        return list(reversed(candidates))

    def _load_command_events(self, limit: int = 200) -> List[Dict[str, Any]]:
        if not COMMAND_AUDIT_LOG.exists():
            return []
        events = []
        try:
            for line in COMMAND_AUDIT_LOG.read_text().splitlines()[-limit:]:
                try:
                    events.append(json.loads(line))
                except Exception:
                    continue
        except Exception:
            return []
        return events

    def _load_orchestrator_health(self) -> Dict[str, Any]:
        url = getattr(self, "orchestrator_url", DEFAULT_ORCHESTRATOR_URL)
        if not url:
            return {"url": "-", "status": "not_configured", "metrics": {}}

        headers = {}
        token = getattr(self, "orchestrator_token", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            health_req = request.Request(f"{url.rstrip('/')}/healthz", method="GET", headers=headers)
            with request.urlopen(health_req, timeout=0.75) as resp:
                body = resp.read().decode("utf-8")
                health = json.loads(body) if body else {}
                status = str(health.get("status") or "ok")
        except error.HTTPError as exc:
            return {"url": url, "status": f"http_{exc.code}", "metrics": {}}
        except Exception:
            return {"url": url, "status": "unreachable", "metrics": {}}

        metrics = {}
        try:
            metrics_req = request.Request(f"{url.rstrip('/')}/metrics", method="GET", headers=headers)
            with request.urlopen(metrics_req, timeout=0.75) as resp:
                body = resp.read().decode("utf-8")
                metrics = json.loads(body) if body else {}
        except Exception:
            metrics = {}
        return {"url": url, "status": status, "metrics": metrics}

    def action_scan_now(self) -> None:
        node = self._resolve_selected_node()
        if not node:
            self.log("No nodes available to scan.")
            return
        self._queue_command(node["node_id"], {"type": "scan_now"})

    def action_toggle_autolearn(self) -> None:
        node = self._resolve_selected_node()
        if not node:
            self.log("No nodes available to toggle autolearn.")
            return
        node_id = node["node_id"]
        meta = self._get_node_meta(node_id)
        current = bool(meta.get("autolearn", False)) if meta else False
        self._queue_command(node_id, {"type": "set_autolearn", "value": not current})

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "cmd-scan":
            self.action_scan_now()
        elif button_id == "cmd-autolearn":
            self.action_toggle_autolearn()
        elif button_id == "cmd-detect":
            self.detect_orchestrator()
        elif button_id == "cmd-tail":
            self.action_toggle_tail_size()
        elif button_id == "cmd-export":
            self.action_export_logs()
        elif button_id == "cmd-allowlist-add":
            self.action_allowlist_selected()
        elif button_id == "cmd-allowlist-remove":
            self.action_remove_allowlist()

    def _queue_command(self, node_id: str, command: Dict[str, Any]) -> None:
        if not self.orchestrator_url:
            self.log("No orchestrator URL configured; set PORTMAP_ORCHESTRATOR_URL")
            self._set_status("No orchestrator URL set")
            return

        payload = json.dumps({"node_id": node_id, "command": command}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.orchestrator_token:
            headers["Authorization"] = f"Bearer {self.orchestrator_token}"

        req = request.Request(
            f"{self.orchestrator_url.rstrip('/')}/commands",
            data=payload,
            headers=headers,
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=5):
                self.log(f"Queued command for {node_id}: {command['type']}")
                self._set_status(f"Queued {command['type']} for {node_id}")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")
            self.log(f"Command failed HTTP {exc.code}: {detail}")
            self._set_status(f"Command failed HTTP {exc.code}")
        except error.URLError as exc:
            self.log(f"Failed to reach orchestrator: {exc.reason}")
            self._set_status("Orchestrator unreachable")

    def _get_node_meta(self, node_id: str) -> Dict[str, Any]:
        if not ORCHESTRATOR_STATE.exists():
            return {}
        try:
            data = json.loads(ORCHESTRATOR_STATE.read_text())
            node = data.get("nodes", {}).get(node_id)
            return node.get("meta", {}) if node else {}
        except Exception:
            return {}

    def _resolve_selected_node(self) -> Optional[Dict[str, Any]]:
        if not self._nodes_cache:
            return None
        selected = self.node_table.cursor_row
        if isinstance(selected, int) and 0 <= selected < len(self._nodes_cache):
            return self._nodes_cache[selected]
        for node in self._nodes_cache:
            if node.get("node_id") == selected:
                return node
        # Fall back to first node if key not found
        return self._nodes_cache[0]

    def detect_orchestrator(self) -> None:
        candidates = [
            self.orchestrator_url,
            "http://127.0.0.1:9100",
            "http://localhost:9100",
        ]
        seen = set()
        for candidate in candidates:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            try:
                headers = {}
                if self.orchestrator_token:
                    headers["Authorization"] = f"Bearer {self.orchestrator_token}"
                req = request.Request(
                    f"{candidate.rstrip('/')}/healthz",
                    method="GET",
                    headers=headers,
                )
                with request.urlopen(req, timeout=3) as resp:
                    if resp.status == 200:
                        self.orchestrator_url = candidate
                        self.log(f"Detected orchestrator at {candidate}")
                        self._set_status(f"Orchestrator: {candidate}")
                        return
            except error.HTTPError:
                continue
            except Exception as exc:
                self.log(f"Detect failed for {candidate}: {exc}")
                continue
        self.log("Could not detect orchestrator automatically; please set PORTMAP_ORCHESTRATOR_URL")
        self._set_status("Orchestrator not found")

    def action_export_logs(self) -> None:
        try:
            archive = export_logs()
            self.log(f"Log archive created at {archive}")
            self._set_status(f"Exported logs → {archive.name} in {archive.parent}")
        except Exception as exc:
            self.log(f"Failed to export logs: {exc}")
            self._set_status("Log export failed")

    def action_show_help(self) -> None:
        self.push_screen(HelpModal(self.export_dir, self.firewall_status))

    def _selected_expected_services_row(self) -> int:
        try:
            selected = self.expected_services_panel.cursor_row
            return int(selected) if selected is not None else 0
        except Exception:
            return 0

    def action_allowlist_selected(self) -> None:
        index = self._selected_expected_services_row()
        if index >= len(self._allowlist_candidates):
            self._set_status("No observed service selected to allowlist")
            return
        service = self._allowlist_candidates[index]
        self.runtime_settings = load_settings(defaults={})
        if _merge_expected_service(self.runtime_settings, service):
            save_settings(self.runtime_settings)
            self._set_status(f"Allowlisted expected service: {_service_label(service)}")
        else:
            self._set_status(f"Service already allowlisted: {_service_label(service)}")
        self.refresh_state()

    def action_remove_allowlist(self) -> None:
        index = self._selected_expected_services_row()
        if index >= len(self._expected_services):
            self._set_status("No allowlisted service selected to remove")
            return
        service = self._expected_services[index]
        self.runtime_settings = load_settings(defaults={})
        if _remove_expected_service(self.runtime_settings, service):
            save_settings(self.runtime_settings)
            self._set_status(f"Removed allowlist service: {_service_label(service)}")
        else:
            self._set_status(f"Allowlist service not found: {_service_label(service)}")
        self.refresh_state()

    # Tail-size controls ------------------------------------------------- #
    def action_toggle_tail_size(self) -> None:
        """Cycle tail size between 5, 10, and 15 rows for both log and remediation panels."""
        next_sizes = {5: 10, 10: 15, 15: 5}
        self.tail_size = next_sizes.get(self.tail_size, 10)
        # refresh immediately to apply new slice
        self.refresh_state()

    def watch_tail_size(self, value: int) -> None:
        """Update button label when tail size changes."""
        try:
            btn = self.query_one("#cmd-tail", Button)
            btn.label = f"Tail: {value}"
        except Exception:
            pass

    # Status helper ------------------------------------------------------ #
    def _set_status(self, message: str) -> None:
        try:
            status = self.query_one("#status-msg", Static)
            status.update(message)
        except Exception:
            pass


def run():
    PortMapDashboard().run()


if __name__ == "__main__":
    run()
