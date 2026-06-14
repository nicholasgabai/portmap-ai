from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
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
from gui.visualization import (
    build_flow_visualization,
    build_risk_timeline,
    flow_rows,
    read_jsonl,
    render_risk_timeline,
    topology_edge_rows,
    visualization_summary,
)
from core_engine.modules.scanner import normalize_scan_snapshot

ORCHESTRATOR_STATE = Path.home() / ".portmap-ai" / "data" / "orchestrator_state.json"
MASTER_LOG = Path.home() / ".portmap-ai" / "logs" / "master.log"
MASTER_EVENTS_LOG = Path.home() / ".portmap-ai" / "logs" / "master_events.log"
REMEDIATION_LOG = Path.home() / ".portmap-ai" / "logs" / "remediation_events.jsonl"
COMMAND_AUDIT_LOG = Path.home() / ".portmap-ai" / "logs" / "command_events.jsonl"
FLOW_EVENTS_LOG = Path.home() / ".portmap-ai" / "logs" / "flow_events.jsonl"
DEFAULT_ORCHESTRATOR_URL = os.environ.get("PORTMAP_ORCHESTRATOR_URL", "http://127.0.0.1:9100")
DEFAULT_ORCHESTRATOR_TOKEN = os.environ.get("PORTMAP_ORCHESTRATOR_TOKEN", "test-token")
SOURCE_MODES = {"live", "simulated", "fixture", "replay", "unknown"}


def _source_mode(value: Any) -> str:
    mode = str(value or "live").strip().lower()
    return mode if mode in SOURCE_MODES else "unknown"


def _display_program_for_source(program: Any, source_mode: Any) -> str:
    mode = _source_mode(source_mode)
    text = str(program or "").strip()
    if text in {"dummy_app", "dummy_db"} and mode not in {"simulated", "fixture"}:
        return "Unattributed"
    return text or "Unattributed"


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


def _short_text(value: Any, *, limit: int = 72) -> str:
    text = " ".join(str(value or "").replace("\n", " ").replace("\r", " ").split())
    if not text:
        return "-"
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 1)].rstrip() + "..."


def _format_risk_score(value: Any) -> str:
    if value in {"", "-", None}:
        return "-"
    try:
        return f"{float(value):.3f}"
    except Exception:
        return str(value)


def _format_timestamp(value: Any) -> str:
    timestamp = _timestamp_to_datetime(value)
    if timestamp is None:
        return "-"
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def _timestamp_to_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return _datetime_from_epoch(float(value))
    if isinstance(value, str):
        stripped = value.strip()
        if stripped in {"", "-", "0"}:
            return None
        try:
            return _datetime_from_epoch(float(stripped))
        except ValueError:
            pass
        try:
            parsed = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
        except ValueError:
            return None
        try:
            if parsed.timestamp() <= 0:
                return None
        except Exception:
            pass
        return parsed
    return None


def _datetime_from_epoch(value: float) -> datetime | None:
    if value <= 0:
        return None
    if value > 10_000_000_000:
        value = value / 1000.0
    try:
        return datetime.fromtimestamp(value)
    except Exception:
        return None


def _scan_rows_from_telemetry(events: List[Dict[str, Any]], limit: int = 20) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    latest_by_node: Dict[str, Dict[str, Any]] = {}
    for event in events:
        node_id = str(event.get("node_id") or "-")
        current = latest_by_node.get(node_id)
        if current is None or str(event.get("timestamp") or "") >= str(current.get("timestamp") or ""):
            latest_by_node[node_id] = event
    for event in sorted(latest_by_node.values(), key=lambda item: str(item.get("timestamp") or "")):
        node_id = event.get("node_id", "-")
        event_score = event.get("risk_score", event.get("score", "-"))
        event_factors = event.get("score_factors") or []
        event_source_mode = _source_mode(event.get("source_mode") or event.get("data_source"))
        event_ports = []
        for port in event.get("ports_sample") or []:
            if isinstance(port, dict):
                row = dict(port)
                row.setdefault("source_mode", event_source_mode)
                row.setdefault("data_source", event_source_mode)
                event_ports.append(row)
        snapshot_ports = normalize_scan_snapshot(event_ports, node_id=str(node_id), max_observations=limit)
        for port in snapshot_ports:
            if not isinstance(port, dict):
                continue
            rows.append(
                {
                    "timestamp": event.get("timestamp", "-"),
                    "node_id": node_id,
                    "program": _display_program_for_source(port.get("program"), port.get("source_mode") or event.get("source_mode") or event.get("data_source")),
                    "port": port.get("port", "-"),
                    "protocol": port.get("protocol") or port.get("service_name") or "-",
                    "status": port.get("status") or "-",
                    "source_mode": _source_mode(port.get("source_mode") or event.get("source_mode") or event.get("data_source")),
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
                "program": _display_program_for_source(event.get("program"), event.get("source_mode") or event.get("data_source")),
                "port": event.get("port", "-"),
                "protocol": event.get("protocol") or "-",
                "status": event.get("status") or "-",
                "source_mode": _source_mode(event.get("source_mode") or event.get("data_source")),
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


@dataclass(frozen=True)
class TuiTab:
    tab_id: str
    label: str
    shortcut: str
    summary: str
    readiness_items: tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tab_id": self.tab_id,
            "label": self.label,
            "shortcut": self.shortcut,
            "summary": self.summary,
            "readiness_items": list(self.readiness_items),
            "preview_only": True,
            "destructive_action": False,
        }


TUI_TAB_REGISTRY: tuple[TuiTab, ...] = (
    TuiTab(
        "dashboard",
        "Dashboard",
        "1",
        "Current live runtime dashboard; remains the default operator surface.",
        (
            "Node Overview",
            "Scan Results",
            "Remediation Feed",
            "Expected Services",
            "Risk Timeline",
            "Topology Edges",
            "Traffic Flows",
            "Command Outcomes",
            "Master Log Tail",
        ),
    ),
    TuiTab(
        "risk",
        "Risk",
        "2",
        "Risk and remediation readiness surface.",
        ("Risk Timeline", "Remediation Feed", "review recommendations", "future risk panels"),
    ),
    TuiTab(
        "exports",
        "Exports",
        "3",
        "Export readiness and validation surface.",
        ("Last Export Summary", "Export validation status", "Export destination", "future Runtime Export Validation Panel"),
    ),
    TuiTab(
        "governance",
        "Governance",
        "4",
        "Compliance and governance readiness surface.",
        (
            "Audit Logging",
            "Compliance Profiles",
            "Data Governance",
            "Operator Accountability",
            "Security Reviews",
            "Privacy Safeguards",
        ),
    ),
    TuiTab(
        "deployment",
        "Deployment",
        "5",
        "Packaging and deployment readiness surface.",
        (
            "Windows installer readiness",
            "macOS packaging readiness",
            "Linux packaging readiness",
            "Container deployment readiness",
            "Secure updater readiness",
            "Deployment wizard readiness",
        ),
    ),
    TuiTab(
        "ai",
        "AI",
        "6",
        "Future AI evolution readiness surface.",
        (
            "Probabilistic Application Models",
            "Continuous Learning Profiles",
            "Graph-Based Behavioral AI",
            "Threat Prediction Models",
            "Federated Intelligence",
            "Autonomous Investigation Chains",
        ),
    ),
    TuiTab(
        "packet",
        "Packet",
        "7",
        "Future packet intelligence placeholder; no packet capture is implemented here.",
        (
            "Packet Capture",
            "Protocol Intelligence",
            "Packet Timeline",
            "Packet Visualization",
            "Packet Hunting",
            "Packet Intelligence Integration",
        ),
    ),
)
DEFAULT_TUI_TAB = "dashboard"
TUI_TAB_IDS = {tab.tab_id for tab in TUI_TAB_REGISTRY}


def tui_tab_shortcut_mapping() -> Dict[str, str]:
    return {tab.shortcut: tab.tab_id for tab in TUI_TAB_REGISTRY}


def serialize_tui_tab_registry() -> List[Dict[str, Any]]:
    return [tab.to_dict() for tab in TUI_TAB_REGISTRY]


def render_tab_nav(active_tab: str = DEFAULT_TUI_TAB) -> str:
    parts = []
    for tab in TUI_TAB_REGISTRY:
        label = f"{tab.shortcut} {tab.label}"
        parts.append(f"[{label}]" if tab.tab_id == active_tab else label)
    return "Tabs: " + " | ".join(parts)


def render_placeholder_tab(tab_id: str) -> str:
    tab = _tab_by_id(tab_id)
    if tab is None:
        return "Unknown tab\nNo readiness surface is registered for this tab."
    rows = [f"{tab.label}", tab.summary, "", "Readiness:"]
    rows.extend(f"- {item}" for item in tab.readiness_items)
    rows.extend(
        [
            "",
            "This tab is a navigation placeholder.",
            "No collectors, packet capture, network calls, installers, governance enforcement, or runtime actions are started here.",
        ]
    )
    return "\n".join(rows)


def _sanitize_risk_signal(value: Any, *, limit: int = 48) -> str:
    return _short_text(value, limit=limit)


def _numeric_risk_score(event: Dict[str, Any]) -> float | None:
    for key in ("risk_score", "score", "confidence"):
        try:
            return float(event[key])
        except (KeyError, TypeError, ValueError):
            continue
    return None


def _risk_action_counts(events: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"monitor": 0, "review": 0, "block": 0}
    for event in events:
        action = str(event.get("action") or "").lower()
        if action == "monitor":
            counts["monitor"] += 1
        elif action in {"prompt_operator", "review"}:
            counts["review"] += 1
        elif action == "block":
            counts["block"] += 1
    return counts


def _latest_risk_timestamp(events: List[Dict[str, Any]]) -> Any:
    best: tuple[datetime, Any] | None = None
    for event in events:
        raw = event.get("timestamp") or event.get("generated_at")
        parsed = _timestamp_to_datetime(raw)
        if parsed is None:
            continue
        if best is None or parsed > best[0]:
            best = (parsed, raw)
    return best[1] if best else None


def _provider_model_summary(events: List[Dict[str, Any]]) -> str:
    counts: Dict[str, int] = {}
    for event in events:
        provider = event.get("ai_provider") or event.get("provider") or event.get("model") or event.get("model_name")
        label = _short_text(provider, limit=32)
        if label == "-":
            continue
        counts[label] = counts.get(label, 0) + 1
    if not counts:
        return "-"
    rows = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ", ".join(f"{label}={count}" for label, count in rows[:4])


def _anomaly_count(events: List[Dict[str, Any]]) -> int:
    count = 0
    for event in events:
        try:
            count += int(event.get("anomaly_count") or 0)
        except (TypeError, ValueError):
            pass
        anomalies = event.get("anomalies")
        if isinstance(anomalies, list):
            count += len(anomalies)
        elif event.get("anomaly") is True:
            count += 1
    return count


def _format_risk_summary(
    remediation_events: List[Dict[str, Any]],
    scan_results: List[Dict[str, Any]],
) -> str:
    events = [*remediation_events, *scan_results]
    scores = [score for event in events if (score := _numeric_risk_score(event)) is not None]
    counts = _risk_action_counts(remediation_events)
    latest_score = scores[-1] if scores else None
    average_score = sum(scores) / len(scores) if scores else None
    return "\n".join(
        [
            "Risk Summary",
            f"- Current findings: {len(events)}",
            f"- Queue counts: monitor={counts['monitor']} review={counts['review']} block={counts['block']}",
            f"- Latest score: {_format_risk_score(latest_score)}",
            f"- Max score: {_format_risk_score(max(scores) if scores else None)}",
            f"- Average score: {_format_risk_score(average_score)}",
            f"- Latest update: {_format_timestamp(_latest_risk_timestamp(events))}",
            f"- Anomalies: {_anomaly_count(events)}",
            f"- Providers/models: {_provider_model_summary(events)}",
        ]
    )


def _signals_from_event(event: Dict[str, Any]) -> List[str]:
    values: List[Any] = []
    for key in ("score_factors", "signals", "findings"):
        item = event.get(key)
        if isinstance(item, list):
            values.extend(item)
        elif item not in {None, "", "-"}:
            values.append(item)
    signals = []
    for value in values:
        signal = _sanitize_risk_signal(value)
        if signal != "-":
            signals.append(signal)
    return signals


def _format_top_risk_signals(
    remediation_events: List[Dict[str, Any]],
    scan_results: List[Dict[str, Any]],
    *,
    limit: int = 8,
) -> str:
    counts: Dict[str, int] = {}
    for event in [*remediation_events, *scan_results]:
        for signal in _signals_from_event(event):
            counts[signal] = counts.get(signal, 0) + 1
    if not counts:
        return "Top Risk Signals\n- No risk signals available."
    rows = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[: max(limit, 0)]
    return "\n".join(["Top Risk Signals", *[f"- {signal} ({count})" for signal, count in rows]])


def _format_remediation_feed(events: List[Dict[str, Any]], *, limit: int = 6) -> str:
    rows = ["Recent Remediation Feed"]
    recent = list(events)[-max(limit, 0) :]
    if not recent:
        rows.append("- No remediation preview events yet.")
        return "\n".join(rows)
    for event in reversed(recent):
        action = _short_text(event.get("action"), limit=18)
        enforcement = _short_text(event.get("enforcement") or ("dry_run" if event.get("dry_run") else "-"), limit=18)
        reason = _short_text(event.get("reason"), limit=44)
        signals = _short_text(_format_score_factors(event), limit=44)
        rows.append(
            f"- {action} {enforcement} score={_format_risk_score(_numeric_risk_score(event))} "
            f"reason={reason} signals={signals}"
        )
    return "\n".join(rows)


def _format_risk_timeline(timeline: List[Dict[str, Any]], *, limit: int = 6) -> str:
    rows = ["Risk Timeline"]
    recent = list(timeline)[-max(limit, 0) :]
    if not recent:
        rows.append("- No scored events yet.")
        return "\n".join(rows)
    for bucket in reversed(recent):
        actions = bucket.get("actions") or {}
        review_count = actions.get("prompt_operator", actions.get("review", 0))
        rows.append(
            " ".join(
                [
                    f"- {_format_timestamp(bucket.get('bucket_start'))}",
                    f"events={bucket.get('event_count', 0)}",
                    f"avg={_format_risk_score(bucket.get('average_score'))}",
                    f"max={_format_risk_score(bucket.get('max_score'))}",
                    f"monitor={actions.get('monitor', 0)}",
                    f"review={review_count}",
                    f"block={actions.get('block', 0)}",
                ]
            )
        )
    return "\n".join(rows)


def _format_allowlist_status(
    candidates: List[Dict[str, Any]],
    expected_services: List[Dict[str, Any]],
    *,
    selected_index: int = 0,
) -> str:
    selected = candidates[selected_index] if 0 <= selected_index < len(candidates) else None
    status = "candidate selected" if selected else "no observed candidate selected"
    return "\n".join(
        [
            "Allowlist Status",
            f"- Observed candidates: {len(candidates)}",
            f"- Allowlisted services: {len(expected_services)}",
            f"- Selected candidate: {_service_label(selected)}",
            f"- Dashboard allowlist status: {status}",
            "- Mutations: use existing footer actions only.",
        ]
    )


def build_risk_tab_text(
    *,
    remediation_events: List[Dict[str, Any]] | None = None,
    scan_results: List[Dict[str, Any]] | None = None,
    risk_timeline: List[Dict[str, Any]] | None = None,
    allowlist_candidates: List[Dict[str, Any]] | None = None,
    expected_services: List[Dict[str, Any]] | None = None,
    selected_index: int = 0,
) -> str:
    remediation = list(remediation_events or [])
    scans = list(scan_results or [])
    timeline = list(risk_timeline or [])
    candidates = list(allowlist_candidates or [])
    expected = list(expected_services or [])
    return "\n\n".join(
        [
            _format_risk_summary(remediation, scans),
            _format_top_risk_signals(remediation, scans),
            _format_remediation_feed(remediation),
            _format_risk_timeline(timeline),
            _format_allowlist_status(candidates, expected, selected_index=selected_index),
            (
                "Safety Boundary\n"
                "- Read-only risk visibility only.\n"
                "- No enforcement, blocking, remediation execution, firewall changes, process changes, "
                "service changes, packet capture, or new collectors."
            ),
        ]
    )


def tab_shortcuts_help_text() -> str:
    return "Tab shortcuts: " + ", ".join(f"{tab.shortcut} {tab.label}" for tab in TUI_TAB_REGISTRY)


def _tab_by_id(tab_id: str) -> TuiTab | None:
    for tab in TUI_TAB_REGISTRY:
        if tab.tab_id == tab_id:
            return tab
    return None


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
        "Visualization:\n"
        "- Risk Timeline: recent score buckets for quick trend review.\n"
        "- Topology Edges: passive flow relationships from flow telemetry when available.\n"
        "- Traffic Flows: bidirectional session summaries without raw payload storage.\n\n"
        f"{tab_shortcuts_help_text()}\n\n"
        f"Export destination: {export_dir}\n"
        "Shortcuts: ? help, e export logs"
    )


def _flow_events_from_master_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for event in events:
        if event.get("event_type") in {"traffic_flow", "packet_metadata", "dpi_observation"}:
            rows.append(event)
            continue
        fallback_timestamp = event.get("timestamp") or event.get("generated_at")
        for key in ("flows", "events", "packet_events"):
            nested = event.get(key)
            if not isinstance(nested, list):
                continue
            for item in nested:
                if not isinstance(item, dict):
                    continue
                row = dict(item)
                if fallback_timestamp and not (row.get("timestamp") or row.get("generated_at")):
                    row["generated_at"] = fallback_timestamp
                rows.append(row)
    return rows


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
        visualization = metrics.get("visualization") or {}
        if visualization:
            text += (
                "\nVisualization - "
                f"flows: {visualization.get('flow_count', 0)}, "
                f"topology: {visualization.get('topology_nodes', 0)} nodes/"
                f"{visualization.get('topology_edges', 0)} edges, "
                f"latest max score: {_format_risk_score(visualization.get('latest_max_score'))}"
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
        self.add_column("Source")
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
                str(row.get("source_mode", "unknown")),
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


class RiskTimelinePanel(Static):
    def update_timeline(self, timeline: List[Dict[str, Any]]) -> None:
        self.update(render_risk_timeline(timeline))


class TopologyPanel(DataTable):
    def on_mount(self) -> None:
        self.add_column("Source")
        self.add_column("Destination")
        self.add_column("Flows")
        self.add_column("Packets")
        self.add_column("Bytes")
        self.add_column("Transport")
        self.add_column("Application")

    def update_topology(self, rows: List[Dict[str, Any]]) -> None:
        self.clear()
        for row in rows:
            self.add_row(
                str(row.get("src_ip", "-")),
                str(row.get("dst_ip", "-")),
                str(row.get("flow_count", 0)),
                str(row.get("packet_count", 0)),
                str(row.get("payload_bytes", 0)),
                str(row.get("protocols", "-")),
                str(row.get("application_protocols", "-")),
            )


class TrafficFlowsPanel(DataTable):
    def on_mount(self) -> None:
        self.add_column("First")
        self.add_column("Last")
        self.add_column("Flow")
        self.add_column("Application")
        self.add_column("Packets")
        self.add_column("Bytes")
        self.add_column("Findings")

    def update_flows(self, rows: List[Dict[str, Any]]) -> None:
        self.clear()
        for row in rows:
            self.add_row(
                _format_timestamp(row.get("first_seen")),
                _format_timestamp(row.get("last_seen")),
                str(row.get("flow", "-")),
                str(row.get("application_protocols", "-")),
                str(row.get("packet_count", 0)),
                str(row.get("payload_bytes", 0)),
                str(row.get("findings", "-")),
            )


class PortMapDashboard(App):
    CSS = """
    .panel-heading {
        padding: 0 1;
        color: $text-muted;
    }
    #tab-nav {
        padding: 0 1;
        background: $surface;
        color: $accent;
    }
    .placeholder-tab {
        padding: 1 2;
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
        ("1", "tab_dashboard", "Dashboard"),
        ("2", "tab_risk", "Risk"),
        ("3", "tab_exports", "Exports"),
        ("4", "tab_governance", "Governance"),
        ("5", "tab_deployment", "Deployment"),
        ("6", "tab_ai", "AI"),
        ("7", "tab_packet", "Packet"),
        ("?", "show_help", "Show help"),
        ("e", "export_logs", "Export logs"),
    ]

    scan_interval = reactive(5)
    tail_size = reactive(10)
    active_tab = reactive(DEFAULT_TUI_TAB)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        self.tab_nav = Static(render_tab_nav(DEFAULT_TUI_TAB), id="tab-nav")
        yield self.tab_nav
        with Container(id="tab-dashboard", classes="tab-panel"):
            yield from self._compose_dashboard_tab()
        for tab in TUI_TAB_REGISTRY:
            if tab.tab_id == DEFAULT_TUI_TAB:
                continue
            if tab.tab_id == "risk":
                self.risk_tab_panel = Static(build_risk_tab_text(), id="risk-tab-panel")
                yield Container(self.risk_tab_panel, id="tab-risk", classes="tab-panel placeholder-tab")
                continue
            yield Container(
                Static(render_placeholder_tab(tab.tab_id)),
                id=f"tab-{tab.tab_id}",
                classes="tab-panel placeholder-tab",
            )
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

    def _compose_dashboard_tab(self) -> ComposeResult:
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
        with Horizontal():
            with Container():
                yield Static(
                    _panel_heading(
                        "Risk Timeline",
                        "Recent score buckets for quick historical trend review.",
                    ),
                    classes="panel-heading",
                )
                self.risk_timeline_panel = RiskTimelinePanel()
                yield self.risk_timeline_panel
            with Container():
                yield Static(
                    _panel_heading(
                        "Topology Edges",
                        "Passive initiator-to-responder relationships when flow telemetry exists.",
                    ),
                    classes="panel-heading",
                )
                self.topology_panel = TopologyPanel()
                yield self.topology_panel
        yield Static(
            _panel_heading(
                "Traffic Flows",
                "Bidirectional flow summaries with packet and byte counts, no raw payload storage.",
            ),
            classes="panel-heading",
        )
        self.traffic_flows_panel = TrafficFlowsPanel()
        yield self.traffic_flows_panel
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

    async def on_mount(self) -> None:
        self._load_orchestrator_defaults()
        self.runtime_settings = load_settings(defaults={})
        self.firewall_status = _resolve_firewall_status(self.runtime_settings)
        self.export_dir = resolve_export_dir()
        self._allowlist_candidates: List[Dict[str, Any]] = []
        self._expected_services: List[Dict[str, Any]] = []
        self._nodes_cache: List[Dict[str, Any]] = []
        self._apply_active_tab()
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
        risk_timeline = build_risk_timeline([*remediation_events, *scan_results], limit=self.tail_size)
        flow_visualization = self._load_flow_visualization(limit=max(self.tail_size * 4, 20))
        if hasattr(self, "risk_timeline_panel"):
            self.risk_timeline_panel.update_timeline(risk_timeline)
        if hasattr(self, "topology_panel"):
            self.topology_panel.update_topology(topology_edge_rows(flow_visualization.get("topology"), limit=self.tail_size))
        if hasattr(self, "traffic_flows_panel"):
            self.traffic_flows_panel.update_flows(flow_rows(flow_visualization.get("flows") or [], limit=self.tail_size))
        self._allowlist_candidates = self._build_allowlist_candidates(remediation_events)
        self._expected_services = [
            item for item in self.runtime_settings.get("expected_services", []) if isinstance(item, dict)
        ]
        self.expected_services_panel.update_services(self._allowlist_candidates, self._expected_services)
        if hasattr(self, "risk_tab_panel"):
            self.risk_tab_panel.update(
                build_risk_tab_text(
                    remediation_events=remediation_events,
                    scan_results=scan_results,
                    risk_timeline=risk_timeline,
                    allowlist_candidates=self._allowlist_candidates,
                    expected_services=self._expected_services,
                    selected_index=self._selected_expected_services_row(),
                )
            )
        command_events = self._load_command_events(limit=self.tail_size)
        self.command_panel.update_commands(command_events)
        if hasattr(self, "metrics_panel"):
            metrics = _compute_metrics(nodes, remediation_events)
            metrics["firewall_status"] = getattr(self, "firewall_status", _resolve_firewall_status({}))
            metrics["orchestrator_health"] = self._load_orchestrator_health()
            metrics["visualization"] = visualization_summary(
                nodes=nodes,
                risk_timeline=risk_timeline,
                flows=flow_visualization.get("flows") or [],
                topology=flow_visualization.get("topology"),
            )
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
        return [
            event
            for event in self._load_master_events(limit=limit)
            if event.get("event_type") == "worker_telemetry"
        ]

    def _load_master_events(self, limit: int = 200) -> List[Dict[str, Any]]:
        if not MASTER_EVENTS_LOG.exists():
            return []
        return read_jsonl(MASTER_EVENTS_LOG, limit=limit)

    def _load_flow_visualization(self, limit: int = 200) -> Dict[str, Any]:
        flow_events = read_jsonl(FLOW_EVENTS_LOG, limit=limit)
        if not flow_events:
            flow_events = _flow_events_from_master_events(self._load_master_events(limit=limit))
        try:
            return build_flow_visualization(flow_events)
        except Exception:
            return {"ok": False, "flows": [], "topology": {"nodes": [], "edges": []}, "raw_payload_stored": False}

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

    def switch_tab(self, tab_id: str) -> None:
        if tab_id not in TUI_TAB_IDS:
            self._set_status(f"Unknown tab: {tab_id}")
            return
        self.active_tab = tab_id
        self._apply_active_tab()
        tab = _tab_by_id(tab_id)
        if tab:
            self._set_status(f"Tab: {tab.label}")

    def watch_active_tab(self, value: str) -> None:
        self._apply_active_tab()

    def _apply_active_tab(self) -> None:
        active_tab = self.active_tab if self.active_tab in TUI_TAB_IDS else DEFAULT_TUI_TAB
        try:
            self.query_one("#tab-nav", Static).update(render_tab_nav(active_tab))
        except Exception:
            pass
        for tab in TUI_TAB_REGISTRY:
            try:
                self.query_one(f"#tab-{tab.tab_id}", Container).display = tab.tab_id == active_tab
            except Exception:
                continue

    def action_tab_dashboard(self) -> None:
        self.switch_tab("dashboard")

    def action_tab_risk(self) -> None:
        self.switch_tab("risk")

    def action_tab_exports(self) -> None:
        self.switch_tab("exports")

    def action_tab_governance(self) -> None:
        self.switch_tab("governance")

    def action_tab_deployment(self) -> None:
        self.switch_tab("deployment")

    def action_tab_ai(self) -> None:
        self.switch_tab("ai")

    def action_tab_packet(self) -> None:
        self.switch_tab("packet")

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
