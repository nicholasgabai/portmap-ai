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
from textual.containers import Container, Grid, Horizontal
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Static, Label

from core_engine.config_loader import load_settings, save_settings
from core_engine.deployment import build_deployment_manifest_catalog
from core_engine.log_exporter import export_logs, resolve_export_dir
from core_engine.packaging import (
    build_auto_updater_readiness,
    build_container_deployment_readiness,
    build_linux_packaging_readiness,
    build_macos_packaging_readiness,
    build_windows_installer_readiness,
)
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
AUDIT_EVENTS_LOG = Path.home() / ".portmap-ai" / "logs" / "audit_events.jsonl"
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


def _format_compact_risk_score(value: Any) -> str:
    if value in {"", "-", None}:
        return "-"
    try:
        score = float(value)
    except Exception:
        return _short_text(value, limit=6)
    formatted = f"{score:.2f}"
    if 0 <= score < 1:
        return formatted[1:]
    return formatted


def _format_timestamp(value: Any) -> str:
    timestamp = _timestamp_to_datetime(value)
    if timestamp is None:
        return "-"
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def _format_time(value: Any) -> str:
    timestamp = _timestamp_to_datetime(value)
    if timestamp is None:
        return "-"
    return timestamp.strftime("%H:%M")


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
DASHBOARD_SECTION_LABELS: tuple[str, ...] = (
    "Start Here",
    "Node Overview",
    "Metrics",
    "Risk Overview",
    "Scan Results",
    "Expected Services",
    "Topology Edges",
    "Traffic Flows",
    "Command Outcomes",
    "Master Log Tail",
)
RISK_WORKSPACE_SECTION_ORDER: tuple[str, ...] = (
    "risk_summary",
    "queue_summary",
    "active_findings",
    "top_signals",
    "remediation_feed",
    "risk_timeline",
    "allowlist_status",
    "safety_boundary",
)
RISK_WORKSPACE_HEADING_LABELS: tuple[str, ...] = (
    "Risk Status",
    "Active Risk Findings",
    "Finding Details",
    "Top Risk Signals",
    "Recent Remediation Feed",
    "Risk Timeline",
)
RISK_WORKSPACE_CONTENT_CLASS = "risk-section"
RISK_WORKSPACE_LAYOUT_ROWS: tuple[str, ...] = (
    "risk-status-row",
    "risk-active-heading-row",
    "risk-active-table-row",
    "risk-support-tables-row",
    "risk-footer-status-row",
)
RISK_ACTIVE_FINDING_LIMIT = 24
EXPORT_WORKSPACE_HEADING_LABELS: tuple[str, ...] = (
    "Export Status",
    "Recent Exports",
    "Export Details",
    "Export Types",
    "Recent Export Events",
    "Validation Timeline",
)
EXPORT_WORKSPACE_CONTENT_CLASS = "export-section"
EXPORT_WORKSPACE_LAYOUT_ROWS: tuple[str, ...] = (
    "export-status-row",
    "export-active-heading-row",
    "export-active-table-row",
    "export-support-tables-row",
)
EXPORT_ACTIVITY_LIMIT = 24
GOVERNANCE_WORKSPACE_HEADING_LABELS: tuple[str, ...] = (
    "Governance Status",
    "Governance Evidence",
    "Governance Details",
    "Evidence Categories",
    "Recent Governance Events",
    "Governance Timeline",
)
GOVERNANCE_WORKSPACE_CONTENT_CLASS = "governance-section"
GOVERNANCE_WORKSPACE_LAYOUT_ROWS: tuple[str, ...] = (
    "governance-status-row",
    "governance-active-heading-row",
    "governance-active-table-row",
    "governance-support-tables-row",
)
GOVERNANCE_EVIDENCE_LIMIT = 24
DEPLOYMENT_WORKSPACE_HEADING_LABELS: tuple[str, ...] = (
    "Deployment Readiness Catalog",
    "Deployment Targets / Readiness Records",
    "Deployment Details",
    "Platform Types",
    "Recent Deployment Events",
    "Deployment Timeline",
)
DEPLOYMENT_WORKSPACE_CONTENT_CLASS = "deployment-section"
DEPLOYMENT_WORKSPACE_LAYOUT_ROWS: tuple[str, ...] = (
    "deployment-status-row",
    "deployment-active-heading-row",
    "deployment-active-table-row",
    "deployment-support-tables-row",
)
DEPLOYMENT_READINESS_LIMIT = 24
AI_WORKSPACE_HEADING_LABELS: tuple[str, ...] = (
    "AI Summary",
    "AI Provider / Model",
    "AI Details",
    "Provider Summary",
    "Recent AI Activity",
    "AI Timeline",
)
AI_WORKSPACE_CONTENT_CLASS = "ai-section"
AI_WORKSPACE_LAYOUT_ROWS: tuple[str, ...] = (
    "ai-status-row",
    "ai-active-heading-row",
    "ai-active-table-row",
    "ai-support-tables-row",
)
AI_ACTIVITY_LIMIT = 24


def tui_tab_shortcut_mapping() -> Dict[str, str]:
    return {tab.shortcut: tab.tab_id for tab in TUI_TAB_REGISTRY}


def serialize_tui_tab_registry() -> List[Dict[str, Any]]:
    return [tab.to_dict() for tab in TUI_TAB_REGISTRY]


def dashboard_section_labels() -> tuple[str, ...]:
    return DASHBOARD_SECTION_LABELS


def risk_workspace_section_order() -> tuple[str, ...]:
    return RISK_WORKSPACE_SECTION_ORDER


def risk_workspace_heading_labels() -> tuple[str, ...]:
    return RISK_WORKSPACE_HEADING_LABELS


def risk_workspace_content_class() -> str:
    return RISK_WORKSPACE_CONTENT_CLASS


def risk_workspace_layout_rows() -> tuple[str, ...]:
    return RISK_WORKSPACE_LAYOUT_ROWS


def export_workspace_heading_labels() -> tuple[str, ...]:
    return EXPORT_WORKSPACE_HEADING_LABELS


def export_workspace_content_class() -> str:
    return EXPORT_WORKSPACE_CONTENT_CLASS


def export_workspace_layout_rows() -> tuple[str, ...]:
    return EXPORT_WORKSPACE_LAYOUT_ROWS


def governance_workspace_heading_labels() -> tuple[str, ...]:
    return GOVERNANCE_WORKSPACE_HEADING_LABELS


def governance_workspace_content_class() -> str:
    return GOVERNANCE_WORKSPACE_CONTENT_CLASS


def governance_workspace_layout_rows() -> tuple[str, ...]:
    return GOVERNANCE_WORKSPACE_LAYOUT_ROWS


def deployment_workspace_heading_labels() -> tuple[str, ...]:
    return DEPLOYMENT_WORKSPACE_HEADING_LABELS


def deployment_workspace_content_class() -> str:
    return DEPLOYMENT_WORKSPACE_CONTENT_CLASS


def deployment_workspace_layout_rows() -> tuple[str, ...]:
    return DEPLOYMENT_WORKSPACE_LAYOUT_ROWS


def ai_workspace_heading_labels() -> tuple[str, ...]:
    return AI_WORKSPACE_HEADING_LABELS


def ai_workspace_content_class() -> str:
    return AI_WORKSPACE_CONTENT_CLASS


def ai_workspace_layout_rows() -> tuple[str, ...]:
    return AI_WORKSPACE_LAYOUT_ROWS


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
    latest_score = scores[-1] if scores else None
    average_score = sum(scores) / len(scores) if scores else None
    return "\n".join(
        [
            " | ".join(
                [
                    f"Current:{len(events)}",
                    f"Latest:{_format_compact_risk_score(latest_score)}",
                    f"Max:{_format_compact_risk_score(max(scores) if scores else None)}",
                    f"Avg:{_format_compact_risk_score(average_score)}",
                ]
            ),
            " | ".join(
                [
                    f"Updated:{_format_time(_latest_risk_timestamp(events))}",
                    f"Anom:{_anomaly_count(events)}",
                    f"Providers:{_provider_model_summary(events)}",
                ]
            ),
        ]
    )


def _format_queue_summary(events: List[Dict[str, Any]]) -> str:
    counts = _risk_action_counts(events)
    total = counts["monitor"] + counts["review"] + counts["block"]
    return "\n".join(
        [
            f"Monitor:{counts['monitor']} | Review:{counts['review']} | Block:{counts['block']} | Total:{total}",
            "Mode: preview only | Actions: disabled",
        ]
    )


def _format_risk_status_strip(risk_summary: str, queue_summary: str) -> str:
    summary = _short_text(" ".join(risk_summary.splitlines()), limit=92)
    queue = _short_text(" ".join(queue_summary.splitlines()), limit=76)
    return f"{summary} || {queue}"


def _risk_status_table_row(
    remediation_events: List[Dict[str, Any]],
    scan_results: List[Dict[str, Any]],
) -> Dict[str, str]:
    events = [*remediation_events, *scan_results]
    scores = [score for event in events if (score := _numeric_risk_score(event)) is not None]
    queue = _queue_status_table_row(remediation_events)
    latest_score = scores[-1] if scores else None
    average_score = sum(scores) / len(scores) if scores else None
    return {
        "current": str(len(events)),
        "latest": _format_compact_risk_score(latest_score),
        "max": _format_compact_risk_score(max(scores) if scores else None),
        "avg": _format_compact_risk_score(average_score),
        "updated": _format_time(_latest_risk_timestamp(events)),
        "provider": _provider_model_summary(events),
        "monitor": queue["monitor"],
        "review": queue["review"],
        "block": queue["block"],
        "total": queue["total"],
        "mode": "preview",
    }


def _queue_status_table_row(events: List[Dict[str, Any]]) -> Dict[str, str]:
    counts = _risk_action_counts(events)
    total = counts["monitor"] + counts["review"] + counts["block"]
    return {
        "monitor": str(counts["monitor"]),
        "review": str(counts["review"]),
        "block": str(counts["block"]),
        "total": str(total),
    }


def _format_risk_status_table(
    remediation_events: List[Dict[str, Any]],
    scan_results: List[Dict[str, Any]],
) -> str:
    row = _risk_status_table_row(remediation_events, scan_results)
    return "\n".join(
        [
            "Current | Latest | Max | Avg | Updated | Provider | Monitor | Review | Block | Total | Mode",
            (
                f"{row['current']} | {row['latest']} | {row['max']} | {row['avg']} | {row['updated']} | "
                f"{row['provider']} | {row['monitor']} | {row['review']} | {row['block']} | {row['total']} | {row['mode']}"
            ),
        ]
    )


def _format_dashboard_risk_overview(
    remediation_events: List[Dict[str, Any]],
    scan_results: List[Dict[str, Any]],
) -> str:
    events = [*remediation_events, *scan_results]
    scores = [score for event in events if (score := _numeric_risk_score(event)) is not None]
    counts = _risk_action_counts(remediation_events)
    latest_score = scores[-1] if scores else None
    return "\n".join(
        [
            "Risk Overview",
            f"Latest score: {_format_risk_score(latest_score)}",
            f"Max score: {_format_risk_score(max(scores) if scores else None)}",
            f"Queues: monitor={counts['monitor']} review={counts['review']} block={counts['block']}",
            f"Latest update: {_format_timestamp(_latest_risk_timestamp(events))}",
            "Details: press 2 for the Risk workspace.",
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
    limit: int = 9,
) -> str:
    rows = _top_risk_signal_rows(remediation_events, scan_results, limit=limit)
    if not rows:
        return "- No risk signals available."
    return "\n".join(["Signal | Count", *[f"{row['signal']:<22} {row['count']}" for row in rows]])


def _top_risk_signal_rows(
    remediation_events: List[Dict[str, Any]],
    scan_results: List[Dict[str, Any]],
    *,
    limit: int = 9,
) -> List[Dict[str, str]]:
    counts: Dict[str, int] = {}
    for event in [*remediation_events, *scan_results]:
        for signal in _signals_from_event(event):
            counts[signal] = counts.get(signal, 0) + 1
    rows = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[: max(limit, 0)]
    return [{"signal": _short_text(signal, limit=22), "count": str(count)} for signal, count in rows]


def _risk_finding_sort_key(event: Dict[str, Any]) -> tuple[float, float]:
    score = _numeric_risk_score(event)
    parsed = _timestamp_to_datetime(event.get("timestamp") or event.get("generated_at"))
    timestamp = parsed.timestamp() if parsed else 0.0
    return (score if score is not None else -1.0, timestamp)


def _risk_severity_label(score: float | None) -> str:
    if score is None:
        return "-"
    if score >= 0.75:
        return "HIGH"
    if score >= 0.4:
        return "MED"
    if score > 0:
        return "LOW"
    return "INFO"


def _risk_finding_target(event: Dict[str, Any]) -> str:
    return _short_text(
        event.get("node_id") or event.get("node") or event.get("target") or event.get("program") or "-",
        limit=16,
    )


def _risk_finding_service(event: Dict[str, Any]) -> str:
    protocol = str(event.get("protocol") or "").upper()
    port = event.get("port")
    service = event.get("service") or event.get("service_name")
    parts = []
    if protocol:
        parts.append(protocol)
    if port not in {"", "-", None}:
        parts.append(str(port))
    if service not in {"", "-", None}:
        parts.append(str(service))
    if not parts:
        program = event.get("program")
        if program not in {"", "-", None}:
            parts.append(str(program))
    return _short_text("/".join(parts) if parts else "-", limit=16)


def _risk_finding_summary(event: Dict[str, Any]) -> str:
    signal = _format_score_factors(event, limit=1)
    if signal != "-":
        return _short_text(signal, limit=28)
    return _short_text(event.get("risk_explanation") or event.get("reason") or event.get("status") or "-", limit=28)


def _risk_finding_node(event: Dict[str, Any]) -> str:
    return _short_text(event.get("node_id") or event.get("node") or event.get("target") or "-", limit=24)


def _risk_finding_port(event: Dict[str, Any]) -> str:
    port = event.get("port")
    return _short_text(port, limit=12) if port not in {"", "-", None} else "-"


def _risk_finding_protocol(event: Dict[str, Any]) -> str:
    protocol = event.get("protocol")
    return _short_text(str(protocol).upper(), limit=12) if protocol not in {"", "-", None} else "-"


def _risk_finding_service_name(event: Dict[str, Any]) -> str:
    service = event.get("service") or event.get("service_name") or event.get("program")
    return _short_text(service, limit=24) if service not in {"", "-", None} else "-"


def _risk_finding_provider(event: Dict[str, Any]) -> str:
    return _short_text(
        event.get("ai_provider") or event.get("provider") or event.get("model") or event.get("model_name") or "-",
        limit=24,
    )


def _risk_finding_state(event: Dict[str, Any]) -> str:
    return _short_text(
        event.get("state")
        or event.get("status")
        or event.get("source_mode")
        or event.get("data_source")
        or event.get("_finding_source")
        or "-",
        limit=24,
    )


def _risk_finding_current_status(event: Dict[str, Any]) -> str:
    return _short_text(
        event.get("current_status")
        or event.get("status")
        or event.get("action")
        or event.get("reason")
        or "-",
        limit=24,
    )


def _risk_finding_source(event: Dict[str, Any]) -> str:
    return _short_text(
        event.get("risk_source")
        or event.get("_finding_source")
        or event.get("event_type")
        or event.get("source_mode")
        or event.get("data_source")
        or "-",
        limit=24,
    )


def _risk_finding_count(event: Dict[str, Any]) -> str:
    for key in ("count", "event_count", "seen_count", "occurrences"):
        value = event.get(key)
        if value not in {"", "-", None}:
            return _short_text(value, limit=12)
    return "-"


def _format_optional_timestamp(value: Any) -> str:
    formatted = _format_timestamp(value)
    return formatted if formatted != "-" else "-"


def _risk_signal_category(signal: str) -> str:
    head = signal.split(":", 1)[0].split("=", 1)[0].strip()
    return _short_text(head or signal, limit=18)


def _risk_signal_summary(event: Dict[str, Any]) -> Dict[str, str]:
    signals = _signals_from_event(event)
    categories: List[str] = []
    for signal in signals:
        category = _risk_signal_category(signal)
        if category != "-" and category not in categories:
            categories.append(category)
    return {
        "signal_count": str(len(signals)) if signals else "-",
        "top_signal": _short_text(signals[0], limit=28) if signals else "-",
        "related_signals": _short_text(", ".join(signals[:3]), limit=48) if signals else "-",
        "strongest_signal": _short_text(signals[0], limit=28) if signals else "-",
        "signal_categories": ", ".join(categories[:4]) if categories else "-",
        "signal_set": "|".join(sorted(signals)),
    }


def _risk_finding_identity(event: Dict[str, Any]) -> str:
    return "|".join(
        [
            _risk_finding_target(event),
            _risk_finding_service(event),
            _risk_finding_summary(event),
            _risk_finding_source(event),
        ]
    )


def _risk_finding_key(event: Dict[str, Any]) -> str:
    score = _format_compact_risk_score(_numeric_risk_score(event))
    return "|".join(
        [
            _risk_finding_target(event),
            _risk_finding_service(event),
            _risk_finding_summary(event),
            score,
            _format_time(event.get("timestamp") or event.get("generated_at")),
        ]
    )


def _risk_timeline_bucket_time(value: Any, *, bucket_seconds: int = 300) -> str:
    times = _risk_timeline_bucket_times(value, bucket_seconds=bucket_seconds)
    return times[0] if times else "-"


def _risk_timeline_bucket_times(value: Any, *, bucket_seconds: int = 300) -> List[str]:
    parsed = _timestamp_to_datetime(value)
    if parsed is None:
        return []
    wall_bucket = parsed.replace(
        minute=(parsed.minute // max(bucket_seconds // 60, 1)) * max(bucket_seconds // 60, 1),
        second=0,
        microsecond=0,
    ).strftime("%H:%M")
    bucket_epoch = int(parsed.timestamp() // bucket_seconds * bucket_seconds)
    epoch_bucket = _format_time(bucket_epoch)
    times = []
    for value in (wall_bucket, epoch_bucket):
        if value != "-" and value not in times:
            times.append(value)
    return times


def _risk_finding_history(events: List[Dict[str, Any]]) -> Dict[str, Dict[str, str]]:
    history: Dict[str, Dict[str, Any]] = {}
    for event in events:
        identity = _risk_finding_identity(event)
        item = history.setdefault(identity, {"count": 0, "first": None, "last": None})
        try:
            item["count"] += int(event.get("count") or event.get("event_count") or event.get("seen_count") or 1)
        except (TypeError, ValueError):
            item["count"] += 1
        for raw in (
            event.get("first_seen"),
            event.get("last_seen"),
            event.get("timestamp") or event.get("generated_at"),
        ):
            parsed = _timestamp_to_datetime(raw)
            if parsed is None:
                continue
            if item["first"] is None or parsed < item["first"]:
                item["first"] = parsed
            if item["last"] is None or parsed > item["last"]:
                item["last"] = parsed
    return {
        identity: {
            "first_seen": value["first"].strftime("%Y-%m-%d %H:%M:%S") if value["first"] else "-",
            "last_seen": value["last"].strftime("%Y-%m-%d %H:%M:%S") if value["last"] else "-",
            "occurrence_count": str(value["count"]) if value["count"] else "-",
        }
        for identity, value in history.items()
    }


def _format_active_risk_findings(
    remediation_events: List[Dict[str, Any]],
    scan_results: List[Dict[str, Any]],
    *,
    limit: int = RISK_ACTIVE_FINDING_LIMIT,
) -> str:
    findings = _active_risk_finding_rows(remediation_events, scan_results, limit=limit)
    if not findings:
        return "- No active risk findings available."
    rows = ["Severity | Asset | Service | Finding | Score | Action | Time"]
    rows.extend(
        f"{row['severity']:<4} | {row['asset']:<16} | {row['service']:<16} | {row['finding']:<28} | "
        f"{row['score']:<5} | {row['action']:<12} | {row['time']}"
        for row in findings
    )
    return "\n".join(rows)


def _active_risk_finding_rows(
    remediation_events: List[Dict[str, Any]],
    scan_results: List[Dict[str, Any]],
    *,
    limit: int = RISK_ACTIVE_FINDING_LIMIT,
) -> List[Dict[str, str]]:
    events: List[Dict[str, Any]] = []
    for event in remediation_events:
        enriched = dict(event)
        enriched.setdefault("_finding_source", "remediation")
        events.append(enriched)
    for event in scan_results:
        enriched = dict(event)
        enriched.setdefault("_finding_source", "sampled_port")
        events.append(enriched)
    history = _risk_finding_history(events)
    rows = []
    for event in sorted(events, key=_risk_finding_sort_key, reverse=True)[: max(limit, 0)]:
        score_value = _numeric_risk_score(event)
        identity = _risk_finding_identity(event)
        signal_summary = _risk_signal_summary(event)
        history_row = history.get(identity, {})
        rows.append(
            {
                "severity": _risk_severity_label(score_value),
                "asset": _risk_finding_target(event),
                "service": _risk_finding_service(event),
                "finding": _risk_finding_summary(event),
                "score": _format_compact_risk_score(score_value),
                "action": _short_text(event.get("action") or event.get("status") or event.get("reason"), limit=12),
                "time": _format_time(event.get("timestamp") or event.get("generated_at")),
                "node": _risk_finding_node(event),
                "port": _risk_finding_port(event),
                "protocol": _risk_finding_protocol(event),
                "service_name": _risk_finding_service_name(event),
                "provider": _risk_finding_provider(event),
                "state": _risk_finding_state(event),
                "first_seen": _format_optional_timestamp(event.get("first_seen")) if event.get("first_seen") else history_row.get("first_seen", "-"),
                "last_seen": _format_optional_timestamp(event.get("last_seen")) if event.get("last_seen") else history_row.get("last_seen", "-"),
                "count": _risk_finding_count(event) if _risk_finding_count(event) != "-" else history_row.get("occurrence_count", "-"),
                "occurrence_count": history_row.get("occurrence_count", _risk_finding_count(event)),
                "signal_count": signal_summary["signal_count"],
                "top_signal": signal_summary["top_signal"],
                "related_signals": signal_summary["related_signals"],
                "strongest_signal": signal_summary["strongest_signal"],
                "signal_categories": signal_summary["signal_categories"],
                "signal_set": signal_summary["signal_set"],
                "risk_source": _risk_finding_source(event),
                "current_status": _risk_finding_current_status(event),
                "timeline_bucket": _risk_timeline_bucket_time(event.get("timestamp") or event.get("generated_at")),
                "timeline_buckets": "|".join(
                    _risk_timeline_bucket_times(event.get("timestamp") or event.get("generated_at"))
                ),
                "identity": identity,
                "key": _risk_finding_key(event),
            }
        )
    return rows


def _finding_detail_rows(finding: Dict[str, str] | None) -> List[tuple[str, str]]:
    row = finding or {}
    return [
        ("Asset", row.get("asset", "-")),
        ("Service", row.get("service", "-")),
        ("Node", row.get("node", "-")),
        ("Port", row.get("port", "-")),
        ("Protocol", row.get("protocol", "-")),
        ("Service Name", row.get("service_name", "-")),
        ("Finding", row.get("finding", "-")),
        ("Provider", row.get("provider", "-")),
        ("Score", row.get("score", "-")),
        ("Action", row.get("action", "-")),
        ("Time", row.get("time", "-")),
        ("State", row.get("state", "-")),
        ("First Seen", row.get("first_seen", "-")),
        ("Last Seen", row.get("last_seen", "-")),
        ("Occurrence Count", row.get("occurrence_count", row.get("count", "-"))),
        ("Signal Count", row.get("signal_count", "-")),
        ("Top Signal", row.get("top_signal", "-")),
        ("Related Signals", row.get("related_signals", "-")),
        ("Strongest Signal", row.get("strongest_signal", "-")),
        ("Signal Categories", row.get("signal_categories", "-")),
        ("Risk Source", row.get("risk_source", "-")),
        ("Current Status", row.get("current_status", "-")),
    ]


def _format_remediation_feed(events: List[Dict[str, Any]], *, limit: int = 9) -> str:
    feed = _remediation_feed_rows(events, limit=limit)
    if not feed:
        return "- No remediation preview events yet."
    rows = ["Time | Action | Score | Signal"]
    rows.extend(f"{row['time']} | {row['action']:<14} | {row['score']:<5} | {row['signal']}" for row in feed)
    return "\n".join(rows)


def _remediation_feed_rows(events: List[Dict[str, Any]], *, limit: int = 9) -> List[Dict[str, str]]:
    recent = list(events)[-max(limit, 0) :]
    rows = []
    for event in reversed(recent):
        signal_summary = _risk_signal_summary(event)
        rows.append(
            {
                "time": _format_time(event.get("timestamp") or event.get("generated_at")),
                "action": _short_text(event.get("action"), limit=14),
                "score": _format_compact_risk_score(_numeric_risk_score(event)),
                "signal": _short_text(_format_score_factors(event, limit=1), limit=24),
                "identity": _risk_finding_identity(event),
                "signal_set": signal_summary["signal_set"],
                "timeline_bucket": _risk_timeline_bucket_time(event.get("timestamp") or event.get("generated_at")),
                "key": "|".join(
                    [
                        _format_time(event.get("timestamp") or event.get("generated_at")),
                        _short_text(event.get("action"), limit=14),
                        _format_compact_risk_score(_numeric_risk_score(event)),
                        _short_text(_format_score_factors(event, limit=1), limit=24),
                    ]
                ),
            }
        )
    return rows


def _format_risk_timeline(timeline: List[Dict[str, Any]], *, limit: int = 9) -> str:
    buckets = _risk_timeline_rows(timeline, limit=limit)
    if not buckets:
        return "- No scored events yet."
    rows = ["Time | Avg | Max | Events | Trend"]
    rows.extend(
        f"{row['time']} | {row['avg']:<5} | {row['max']:<5} | {row['events']:<6} | {row['trend']}"
        for row in buckets
    )
    return "\n".join(rows)


def _risk_timeline_rows(timeline: List[Dict[str, Any]], *, limit: int = 9) -> List[Dict[str, str]]:
    recent = list(timeline)[-max(limit, 0) :]
    rows = []
    previous_average: float | None = None
    for bucket in recent:
        try:
            average = float(bucket.get("average_score"))
        except (TypeError, ValueError):
            average = None
        if average is None or previous_average is None:
            trend = "-"
        elif average > previous_average:
            trend = "up"
        elif average < previous_average:
            trend = "down"
        else:
            trend = "flat"
        rows.append(
            {
                "time": _format_time(bucket.get("bucket_start")),
                "avg": _format_compact_risk_score(bucket.get("average_score")),
                "max": _format_compact_risk_score(bucket.get("max_score")),
                "events": str(bucket.get("event_count", 0)),
                "trend": trend,
                "identity": _short_text(bucket.get("identity"), limit=64),
                "signal_set": "|".join(_signals_from_event(bucket)),
                "timeline_bucket": _format_time(bucket.get("bucket_start")),
                "key": "|".join(
                    [
                        _format_time(bucket.get("bucket_start")),
                        _format_compact_risk_score(bucket.get("average_score")),
                        _format_compact_risk_score(bucket.get("max_score")),
                        str(bucket.get("event_count", 0)),
                    ]
                ),
            }
        )
        previous_average = average
    return rows


def _signal_set_values(value: Any) -> set[str]:
    if not value or value == "-":
        return set()
    return {item for item in str(value).split("|") if item}


def _row_matches_selected_finding(finding: Dict[str, str] | None, row: Dict[str, str]) -> bool:
    if not finding:
        return False
    if finding.get("identity") and finding.get("identity") == row.get("identity"):
        return True
    finding_signals = _signal_set_values(finding.get("signal_set"))
    row_signals = _signal_set_values(row.get("signal_set"))
    if finding_signals and row_signals and finding_signals.intersection(row_signals):
        return True
    finding_buckets = _signal_set_values(finding.get("timeline_buckets") or finding.get("timeline_bucket"))
    row_bucket = row.get("timeline_bucket")
    return bool(row_bucket and row_bucket != "-" and row_bucket in finding_buckets)


def _format_allowlist_status(
    candidates: List[Dict[str, Any]],
    expected_services: List[Dict[str, Any]],
    *,
    selected_index: int = 0,
) -> str:
    selected = candidates[selected_index] if 0 <= selected_index < len(candidates) else None
    status = "candidate selected" if selected else "no observed candidate selected"
    return f"Observed:{len(candidates)} | Allowlisted:{len(expected_services)} | Selected:{_service_label(selected)} | Status:{status}"


def _format_safety_boundary() -> str:
    return "Read-only; no enforcement, blocking, remediation execution, packet capture, collectors, or runtime actions."


def _format_footer_status(allowlist_status: str, safety_boundary: str) -> str:
    allowlist = _short_text(allowlist_status, limit=88)
    safety = _short_text(safety_boundary, limit=86)
    return f"Allowlist: {allowlist} || Safety: {safety}"


def build_risk_workspace_sections(
    *,
    remediation_events: List[Dict[str, Any]] | None = None,
    scan_results: List[Dict[str, Any]] | None = None,
    risk_timeline: List[Dict[str, Any]] | None = None,
    allowlist_candidates: List[Dict[str, Any]] | None = None,
    expected_services: List[Dict[str, Any]] | None = None,
    selected_index: int = 0,
) -> Dict[str, str]:
    remediation = list(remediation_events or [])
    scans = list(scan_results or [])
    timeline = list(risk_timeline or [])
    candidates = list(allowlist_candidates or [])
    expected = list(expected_services or [])
    return {
        "risk_summary": _format_risk_summary(remediation, scans),
        "queue_summary": _format_queue_summary(remediation),
        "active_findings": _format_active_risk_findings(remediation, scans),
        "top_signals": _format_top_risk_signals(remediation, scans),
        "remediation_feed": _format_remediation_feed(remediation),
        "risk_timeline": _format_risk_timeline(timeline),
        "allowlist_status": _format_allowlist_status(candidates, expected, selected_index=selected_index),
        "safety_boundary": _format_safety_boundary(),
    }


def _side_by_side_text(left: str, right: str, *, width: int) -> str:
    column_width = max((width - 3) // 2, 24)
    left_lines = left.splitlines() or ["-"]
    right_lines = right.splitlines() or ["-"]
    row_count = max(len(left_lines), len(right_lines))
    rows = []
    for index in range(row_count):
        left_line = _short_text(left_lines[index] if index < len(left_lines) else "", limit=column_width)
        right_line = _short_text(right_lines[index] if index < len(right_lines) else "", limit=column_width)
        rows.append(f"{left_line:<{column_width}} | {right_line}")
    return "\n".join(rows)


def _three_column_text(left: str, center: str, right: str, *, width: int) -> str:
    column_width = max((width - 6) // 3, 20)
    left_lines = left.splitlines() or ["-"]
    center_lines = center.splitlines() or ["-"]
    right_lines = right.splitlines() or ["-"]
    row_count = max(len(left_lines), len(center_lines), len(right_lines))
    rows = []
    for index in range(row_count):
        left_line = _short_text(left_lines[index] if index < len(left_lines) else "", limit=column_width)
        center_line = _short_text(center_lines[index] if index < len(center_lines) else "", limit=column_width)
        right_line = _short_text(right_lines[index] if index < len(right_lines) else "", limit=column_width)
        rows.append(f"{left_line:<{column_width}} | {center_line:<{column_width}} | {right_line}")
    return "\n".join(rows)


def render_risk_workspace_layout(
    *,
    remediation_events: List[Dict[str, Any]] | None = None,
    scan_results: List[Dict[str, Any]] | None = None,
    risk_timeline: List[Dict[str, Any]] | None = None,
    allowlist_candidates: List[Dict[str, Any]] | None = None,
    expected_services: List[Dict[str, Any]] | None = None,
    selected_index: int = 0,
    width: int = 100,
) -> str:
    remediation = list(remediation_events or [])
    scans = list(scan_results or [])
    sections = build_risk_workspace_sections(
        remediation_events=remediation,
        scan_results=scans,
        risk_timeline=risk_timeline,
        allowlist_candidates=allowlist_candidates,
        expected_services=expected_services,
        selected_index=selected_index,
    )
    return "\n\n".join(
        [
            f"Risk Status\n{_format_risk_status_table(remediation, scans)}",
            f"Active Risk Findings\n{sections['active_findings']}",
            "Finding Details\n"
            + "\n".join(
                f"{field}: {value}"
                for field, value in _finding_detail_rows(
                    (_active_risk_finding_rows(remediation, scans, limit=1) or [None])[0]
                )
            ),
            _three_column_text(
                f"Top Risk Signals\n{sections['top_signals']}",
                f"Recent Remediation Feed\n{sections['remediation_feed']}",
                f"Risk Timeline\n{sections['risk_timeline']}",
                width=width,
            ),
            _format_footer_status(sections["allowlist_status"], sections["safety_boundary"]),
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
    return render_risk_workspace_layout(
        remediation_events=remediation_events,
        scan_results=scan_results,
        risk_timeline=risk_timeline,
        allowlist_candidates=allowlist_candidates,
        expected_services=expected_services,
        selected_index=selected_index,
        width=80,
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
        "3. Press 2 Risk for detailed remediation feed, timeline, and signals.\n\n"
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
        "- Risk Overview: compact score, queue, and update summary; press 2 for detail.\n"
        "- Expected Services: move normal services into the allowlist so scoring explains them as expected.\n"
        "- Command Outcomes: whether queued commands were received, applied, failed, or ignored.\n"
        "- Master Log Tail: most recent master-node runtime lines.\n\n"
        "Visualization:\n"
        "- Risk tab: detailed remediation feed, risk timeline, queue summary, and top signals.\n"
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


def _format_export_size(value: Any) -> str:
    try:
        size = int(value)
    except (TypeError, ValueError):
        return "-"
    if size < 0:
        return "-"
    units = ("B", "KB", "MB", "GB")
    amount = float(size)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(amount)} B"
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{size} B"


def _export_type_from_path(path: Path) -> str:
    name = path.name.lower()
    if name.startswith("portmap-logs-"):
        return "logs"
    for label in ("topology", "findings", "snapshots", "reports", "risk", "flows"):
        if label in name:
            return label
    suffixes = "".join(path.suffixes).lstrip(".")
    return suffixes or "file"


def _export_rows_from_dir(export_dir: Path, *, limit: int = EXPORT_ACTIVITY_LIMIT) -> List[Dict[str, str]]:
    if not export_dir.exists():
        return []
    rows: List[Dict[str, str]] = []
    try:
        paths = [path for path in export_dir.iterdir() if path.is_file() and not path.name.startswith(".")]
    except Exception:
        return []
    for path in paths:
        try:
            stat = path.stat()
        except Exception:
            rows.append(
                {
                    "export_id": path.name,
                    "timestamp": "-",
                    "export_type": _export_type_from_path(path),
                    "status": "unreadable",
                    "destination": str(path.parent),
                    "files": "-",
                    "size": "-",
                    "duration": "-",
                    "started": "-",
                    "completed": "-",
                    "validation_result": "unreadable",
                    "key": path.name,
                    "_mtime": "0",
                }
            )
            continue
        completed = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        validation = "valid" if stat.st_size > 0 else "empty"
        rows.append(
            {
                "export_id": path.name,
                "timestamp": completed,
                "export_type": _export_type_from_path(path),
                "status": "available" if validation == "valid" else "empty",
                "destination": str(path.parent),
                "files": "1",
                "size": _format_export_size(stat.st_size),
                "duration": "-",
                "started": "-",
                "completed": completed,
                "validation_result": validation,
                "key": path.name,
                "_mtime": str(stat.st_mtime),
            }
        )
    rows.sort(key=lambda row: float(row.get("_mtime") or 0), reverse=True)
    return rows[: max(limit, 0)]


def _export_status_table_row(export_rows: List[Dict[str, str]], export_dir: Path) -> Dict[str, str]:
    successes = sum(1 for row in export_rows if row.get("validation_result") == "valid")
    failures = sum(1 for row in export_rows if row.get("validation_result") not in {"valid", None})
    if not export_rows:
        validation = "no_exports"
        last_export = "-"
    elif failures:
        validation = "attention"
        last_export = export_rows[0].get("timestamp", "-")
    else:
        validation = "ready"
        last_export = export_rows[0].get("timestamp", "-")
    return {
        "last_export": last_export,
        "export_count": str(len(export_rows)),
        "success_count": str(successes),
        "failure_count": str(failures),
        "destination": str(export_dir),
        "validation_state": validation,
    }


def _export_detail_rows(export_row: Dict[str, str] | None) -> List[tuple[str, str]]:
    row = export_row or {}
    return [
        ("Export ID", row.get("export_id", "-")),
        ("Export Type", row.get("export_type", "-")),
        ("Started", row.get("started", "-")),
        ("Completed", row.get("completed", "-")),
        ("Destination", row.get("destination", "-")),
        ("Files Generated", row.get("files", "-")),
        ("Validation Result", row.get("validation_result", "-")),
        ("Status", row.get("status", "-")),
        ("Duration", row.get("duration", "-")),
        ("Size", row.get("size", "-")),
    ]


def _export_type_rows(export_rows: List[Dict[str, str]], *, limit: int = 9) -> List[Dict[str, str]]:
    counts: Dict[str, int] = {}
    for row in export_rows:
        export_type = row.get("export_type") or "-"
        counts[export_type] = counts.get(export_type, 0) + 1
    return [
        {"export_type": _short_text(export_type, limit=24), "count": str(count)}
        for export_type, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[: max(limit, 0)]
    ]


def _export_event_rows(export_rows: List[Dict[str, str]], *, limit: int = 9) -> List[Dict[str, str]]:
    recent = list(export_rows)[: max(limit, 0)]
    return [
        {
            "time": row.get("timestamp", "-"),
            "export_type": row.get("export_type", "-"),
            "status": row.get("status", "-"),
            "result": row.get("validation_result", "-"),
            "key": row.get("key", row.get("export_id", "-")),
        }
        for row in reversed(recent)
    ]


def _export_validation_timeline_rows(export_rows: List[Dict[str, str]], *, limit: int = 9) -> List[Dict[str, str]]:
    buckets: Dict[str, Dict[str, int]] = {}
    for row in export_rows:
        timestamp = row.get("timestamp") or "-"
        bucket = timestamp[:10] if timestamp != "-" else "-"
        item = buckets.setdefault(bucket, {"valid": 0, "failed": 0, "total": 0})
        item["total"] += 1
        if row.get("validation_result") == "valid":
            item["valid"] += 1
        else:
            item["failed"] += 1
    return [
        {"time": bucket, "valid": str(values["valid"]), "failed": str(values["failed"]), "total": str(values["total"])}
        for bucket, values in sorted(buckets.items(), reverse=True)[: max(limit, 0)]
    ]


def _governance_event_time(event: Dict[str, Any]) -> str:
    return _format_timestamp(event.get("created_at") or event.get("timestamp") or event.get("generated_at"))


def _governance_event_category(event: Dict[str, Any], source: str) -> str:
    category = event.get("event_category") or event.get("category")
    if category not in {"", "-", None}:
        return _short_text(category, limit=24)
    event_type = str(event.get("event_type") or event.get("command_type") or event.get("action") or "").lower()
    if source == "command_audit":
        return "operator_action"
    if source == "remediation":
        return "remediation_preview"
    if source == "export":
        return "export"
    if "export" in event_type:
        return "export"
    if "policy" in event_type:
        return "policy_review"
    if "security" in event_type:
        return "security_review"
    if "config" in event_type or "command" in event_type:
        return "configuration"
    return "runtime"


def _governance_evidence_count(event: Dict[str, Any]) -> str:
    evidence = event.get("evidence_references")
    if isinstance(evidence, list):
        return str(len(evidence))
    if isinstance(event.get("details"), dict):
        return "1"
    if event.get("export_id"):
        return "1"
    return "-"


def _governance_row_from_event(event: Dict[str, Any], *, source: str) -> Dict[str, str]:
    event_type = (
        event.get("event_type")
        or event.get("command_type")
        or event.get("action")
        or event.get("export_type")
        or "unknown"
    )
    state = event.get("event_state") or event.get("status") or event.get("validation_result") or "recorded"
    actor = event.get("actor_reference") or event.get("actor") or event.get("node_id") or event.get("source") or "-"
    action = event.get("action_reference") or event.get("action") or event.get("command_type") or event_type
    target = (
        event.get("target_reference")
        or event.get("target")
        or event.get("node_id")
        or event.get("export_id")
        or event.get("port")
        or "-"
    )
    mode = event.get("source_mode") or event.get("data_source") or event.get("source") or source
    time = _governance_event_time(event)
    raw_time = event.get("created_at") or event.get("timestamp") or event.get("generated_at")
    parsed_time = _timestamp_to_datetime(raw_time)
    category = _governance_event_category(event, source)
    row = {
        "time": time,
        "category": category,
        "event_type": _short_text(event_type, limit=24),
        "state": _short_text(state, limit=18),
        "actor": _short_text(actor, limit=24),
        "action": _short_text(action, limit=28),
        "target": _short_text(target, limit=28),
        "source": _short_text(mode, limit=24),
        "evidence": _governance_evidence_count(event),
        "preview_only": str(bool(event.get("preview_only", True))),
        "destructive_action": str(bool(event.get("destructive_action", False))),
        "key": "|".join(
            [
                source,
                time,
                category,
                _short_text(event_type, limit=40),
                _short_text(target, limit=40),
            ]
        ),
        "_sort_time": f"{parsed_time.timestamp():020.6f}" if parsed_time else str(raw_time or ""),
    }
    return row


def _governance_rows_from_sources(
    *,
    audit_events: List[Dict[str, Any]] | None = None,
    command_events: List[Dict[str, Any]] | None = None,
    remediation_events: List[Dict[str, Any]] | None = None,
    export_rows: List[Dict[str, str]] | None = None,
    limit: int = GOVERNANCE_EVIDENCE_LIMIT,
) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    rows.extend(_governance_row_from_event(event, source="audit") for event in list(audit_events or []))
    rows.extend(_governance_row_from_event(event, source="command_audit") for event in list(command_events or []))
    rows.extend(_governance_row_from_event(event, source="remediation") for event in list(remediation_events or []))
    for export in list(export_rows or []):
        event = {
            "timestamp": export.get("timestamp"),
            "event_type": "export_available",
            "event_category": "export",
            "event_state": export.get("validation_result"),
            "actor_reference": "local_export_dir",
            "action_reference": export.get("export_type"),
            "target_reference": export.get("export_id"),
            "source_mode": "local_file",
            "export_id": export.get("export_id"),
            "preview_only": True,
            "destructive_action": False,
        }
        rows.append(_governance_row_from_event(event, source="export"))
    rows.sort(key=lambda row: row.get("_sort_time") or row.get("time") or "", reverse=True)
    return rows[: max(limit, 0)]


def _governance_status_table_row(governance_rows: List[Dict[str, str]]) -> Dict[str, str]:
    failures = sum(1 for row in governance_rows if row.get("state") in {"invalid", "degraded", "failed", "empty"})
    destructive = sum(1 for row in governance_rows if row.get("destructive_action") == "True")
    preview = sum(1 for row in governance_rows if row.get("preview_only") == "True")
    latest = governance_rows[0].get("time", "-") if governance_rows else "-"
    if not governance_rows:
        readiness = "no_evidence"
    elif destructive:
        readiness = "review_required"
    elif failures:
        readiness = "attention"
    else:
        readiness = "ready"
    return {
        "latest": latest,
        "evidence_count": str(len(governance_rows)),
        "preview_count": str(preview),
        "exception_count": str(failures + destructive),
        "category_count": str(len({row.get("category") for row in governance_rows if row.get("category")})),
        "readiness": readiness,
    }


def _governance_detail_rows(governance_row: Dict[str, str] | None) -> List[tuple[str, str]]:
    row = governance_row or {}
    return [
        ("Time", row.get("time", "-")),
        ("Category", row.get("category", "-")),
        ("Event Type", row.get("event_type", "-")),
        ("State", row.get("state", "-")),
        ("Actor", row.get("actor", "-")),
        ("Action", row.get("action", "-")),
        ("Target", row.get("target", "-")),
        ("Source", row.get("source", "-")),
        ("Evidence Count", row.get("evidence", "-")),
        ("Preview Only", row.get("preview_only", "-")),
        ("Destructive Action", row.get("destructive_action", "-")),
    ]


def _governance_category_rows(governance_rows: List[Dict[str, str]], *, limit: int = 9) -> List[Dict[str, str]]:
    counts: Dict[str, int] = {}
    for row in governance_rows:
        category = row.get("category") or "unknown"
        counts[category] = counts.get(category, 0) + 1
    return [
        {"category": _short_text(category, limit=24), "count": str(count)}
        for category, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[: max(limit, 0)]
    ]


def _governance_recent_event_rows(governance_rows: List[Dict[str, str]], *, limit: int = 9) -> List[Dict[str, str]]:
    recent = list(governance_rows)[: max(limit, 0)]
    return [
        {
            "time": row.get("time", "-"),
            "category": row.get("category", "-"),
            "state": row.get("state", "-"),
            "event_type": row.get("event_type", "-"),
            "key": row.get("key", "-"),
        }
        for row in reversed(recent)
    ]


def _governance_timeline_rows(governance_rows: List[Dict[str, str]], *, limit: int = 9) -> List[Dict[str, str]]:
    buckets: Dict[str, Dict[str, int]] = {}
    for row in governance_rows:
        time = row.get("time") or "-"
        bucket = time[:10] if time != "-" else "-"
        item = buckets.setdefault(bucket, {"events": 0, "exceptions": 0, "preview": 0})
        item["events"] += 1
        if row.get("state") in {"invalid", "degraded", "failed", "empty"} or row.get("destructive_action") == "True":
            item["exceptions"] += 1
        if row.get("preview_only") == "True":
            item["preview"] += 1
    return [
        {
            "time": bucket,
            "events": str(values["events"]),
            "exceptions": str(values["exceptions"]),
            "preview": str(values["preview"]),
        }
        for bucket, values in sorted(buckets.items(), reverse=True)[: max(limit, 0)]
    ]


def _deployment_list_text(values: Any, *, limit: int = 4, text_limit: int = 72) -> str:
    if values is None:
        return "-"
    if not isinstance(values, (dict, list)) and values in {"", "-"}:
        return "-"
    if isinstance(values, dict):
        items = [f"{key}={value}" for key, value in values.items()]
    elif isinstance(values, list):
        items = []
        for value in values:
            if isinstance(value, dict):
                label = value.get("action_summary") or value.get("step_id") or value.get("record_type")
                items.append(str(label or value))
            else:
                items.append(str(value))
    else:
        items = [str(values)]
    items = [_short_text(item, limit=text_limit) for item in items if _short_text(item, limit=text_limit) != "-"]
    if not items:
        return "-"
    suffix = "..." if len(items) > limit else ""
    return ", ".join(items[:limit]) + suffix


def _deployment_platform_type(value: Any) -> str:
    text = str(value or "").lower()
    if "windows" in text or "powershell" in text or "winget" in text or "msi" in text:
        return "windows"
    if "macos" in text or "darwin" in text or "launchd" in text or "app_bundle" in text:
        return "macos"
    if "container" in text or "docker" in text or "podman" in text or "compose" in text:
        return "container"
    if "updater" in text or "update" in text or "channel" in text:
        return "updater"
    if "linux" in text or "raspberry" in text or "debian" in text or "systemd" in text or "arm" in text:
        return "linux"
    return "linux"


def _deployment_status_from_state(value: Any) -> str:
    state = str(value or "").strip().lower()
    if state in {"ready", "supported", "available", "valid"}:
        return "ready"
    if state in {"degraded", "warning", "attention", "partial"}:
        return "warning"
    if state in {"blocked", "unsupported", "unavailable", "failed", "invalid"}:
        return "blocker"
    return state or "unknown"


def _deployment_state_value(record: Dict[str, Any]) -> str:
    for key in ("installer_state", "packaging_state", "deployment_state", "updater_state", "state", "status"):
        value = record.get(key)
        if value not in {"", "-", None}:
            return str(value)
    readiness = record.get("deployment_readiness")
    if isinstance(readiness, dict):
        return str(readiness.get("state") or "unknown")
    return "unknown"


def _deployment_method_value(record: Dict[str, Any]) -> str:
    for key in ("install_method", "package_method", "deployment_method", "update_method", "deployment_mode", "method"):
        value = record.get(key)
        if value not in {"", "-", None}:
            return str(value)
    return "readiness"


def _deployment_validation_notes(record: Dict[str, Any], keys: tuple[str, ...]) -> List[str]:
    notes: List[str] = []
    validation = record.get("validation_summary")
    if isinstance(validation, dict):
        for key in keys:
            value = validation.get(key)
            if isinstance(value, list):
                notes.extend(str(item) for item in value)
            elif value not in {"", "-", None}:
                notes.append(str(value))
    for key in keys:
        value = record.get(key)
        if isinstance(value, list):
            notes.extend(str(item) for item in value)
        elif value not in {"", "-", None}:
            notes.append(str(value))
    deduped: List[str] = []
    for note in notes:
        if note and note not in deduped:
            deduped.append(note)
    return deduped


def _deployment_warning_items(record: Dict[str, Any], state: str) -> List[str]:
    warnings = _deployment_validation_notes(record, ("advisory_notes", "safety_warnings", "warnings"))
    validation = record.get("validation_summary")
    if isinstance(validation, dict) and validation.get("admin_required") is True:
        warnings.append("future_admin_if_operator_approved")
    if _deployment_status_from_state(state) == "warning" and not warnings:
        warnings.append(state)
    return warnings


def _deployment_blocker_items(record: Dict[str, Any], state: str) -> List[str]:
    blockers = _deployment_validation_notes(record, ("blockers", "missing_requirements", "failed_checks"))
    if _deployment_status_from_state(state) == "blocker" and not blockers:
        blockers.append(state)
    return blockers


def _deployment_safety_mode(record: Dict[str, Any]) -> str:
    if record.get("dry_run_only") is True or record.get("dry_run") is True:
        return "dry_run"
    if record.get("preview_only") is True:
        return "preview"
    return "read_only"


def _deployment_local_platform() -> str:
    try:
        system = os.uname().sysname.lower()
    except Exception:
        return "-"
    if system == "darwin":
        return "macos"
    if system == "linux":
        return "linux"
    if system.startswith("win"):
        return "windows"
    return _short_text(system, limit=16)


def _deployment_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _deployment_row_from_manifest(manifest: Dict[str, Any]) -> Dict[str, str]:
    readiness = manifest.get("deployment_readiness") if isinstance(manifest.get("deployment_readiness"), dict) else {}
    state = str(readiness.get("state") or manifest.get("state") or "unknown")
    checks = readiness.get("check_states") if isinstance(readiness.get("check_states"), dict) else {}
    blockers = [f"{key}:{value}" for key, value in checks.items() if value in {"unsupported", "unavailable", "blocked"}]
    warnings = [f"{key}:{value}" for key, value in checks.items() if value in {"degraded", "unknown"}]
    platform = _deployment_platform_type(" ".join(str(item) for item in manifest.get("supported_platforms") or []))
    method = _deployment_method_value(manifest)
    updated = _format_timestamp(manifest.get("generated_at"))
    notes = manifest.get("advisory_notes") or []
    return {
        "platform": platform,
        "method": _short_text(method, limit=24),
        "status": _deployment_status_from_state(state),
        "readiness": _short_text(state, limit=24),
        "warnings": str(len(warnings)),
        "blockers": str(len(blockers)),
        "updated": updated,
        "required_steps": _deployment_list_text(manifest.get("required_components")),
        "warning_details": _deployment_list_text(warnings),
        "blocker_details": _deployment_list_text(blockers),
        "safety_mode": _deployment_safety_mode(manifest),
        "notes": _deployment_list_text(notes),
        "scope": "metadata_only",
        "local_platform": _deployment_local_platform(),
        "tested_locally": "unknown",
        "execution": "not performed",
        "preview_only": str(bool(manifest.get("preview_only", True))),
        "destructive_action": str(bool(manifest.get("destructive_action", False))),
        "key": "|".join(["manifest", method, platform, updated]),
    }


def _deployment_row_from_package(record: Dict[str, Any]) -> Dict[str, str]:
    state = _deployment_state_value(record)
    method = _deployment_method_value(record)
    platform = _deployment_platform_type(
        " ".join(
            [
                str(record.get("target_platform") or ""),
                str(record.get("record_type") or ""),
                method,
            ]
        )
    )
    warnings = _deployment_warning_items(record, state)
    blockers = _deployment_blocker_items(record, state)
    updated = _format_timestamp(record.get("generated_at"))
    required_steps = record.get("install_steps") or record.get("required_permissions") or []
    notes = warnings or _deployment_validation_notes(record, ("advisory_notes",))
    return {
        "platform": platform,
        "method": _short_text(method, limit=24),
        "status": _deployment_status_from_state(state),
        "readiness": _short_text(state, limit=24),
        "warnings": str(len(warnings)),
        "blockers": str(len(blockers)),
        "updated": updated,
        "required_steps": _deployment_list_text(required_steps),
        "warning_details": _deployment_list_text(warnings),
        "blocker_details": _deployment_list_text(blockers),
        "safety_mode": _deployment_safety_mode(record),
        "notes": _deployment_list_text(notes),
        "scope": "metadata_only",
        "local_platform": _deployment_local_platform(),
        "tested_locally": "unknown",
        "execution": "not performed",
        "preview_only": str(bool(record.get("preview_only", True))),
        "destructive_action": str(bool(record.get("destructive_action", False))),
        "key": "|".join(["package", str(record.get("record_type") or "readiness"), platform, method]),
    }


def _default_deployment_generated_at() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _build_default_deployment_readiness_rows(
    *,
    generated_at: str | None = None,
    limit: int = DEPLOYMENT_READINESS_LIMIT,
) -> List[Dict[str, str]]:
    timestamp = generated_at or _default_deployment_generated_at()
    rows: List[Dict[str, str]] = []
    try:
        catalog = build_deployment_manifest_catalog(generated_at=timestamp)
        for manifest in catalog.get("manifests") or []:
            if isinstance(manifest, dict):
                rows.append(_deployment_row_from_manifest(manifest))
    except Exception:
        pass
    for builder in (
        build_windows_installer_readiness,
        build_macos_packaging_readiness,
        build_linux_packaging_readiness,
        build_container_deployment_readiness,
        build_auto_updater_readiness,
    ):
        try:
            record = builder(generated_at=timestamp)
            payload = record.to_dict() if hasattr(record, "to_dict") else record
            if isinstance(payload, dict):
                rows.append(_deployment_row_from_package(payload))
        except Exception:
            continue
    rows.sort(key=lambda row: (row.get("platform", ""), row.get("method", "")))
    return rows[: max(limit, 0)]


def _deployment_status_table_row(deployment_rows: List[Dict[str, str]]) -> Dict[str, str]:
    ready = sum(1 for row in deployment_rows if row.get("status") == "ready")
    warnings = sum(_deployment_int(row.get("warnings")) for row in deployment_rows)
    blockers = sum(_deployment_int(row.get("blockers")) for row in deployment_rows)
    latest = max((row.get("updated") for row in deployment_rows if row.get("updated") not in {"", "-", None}), default="-")
    return {
        "platforms": str(len({row.get("platform") for row in deployment_rows if row.get("platform")})),
        "ready": str(ready),
        "warnings": str(warnings),
        "blockers": str(blockers),
        "last_updated": latest,
        "mode": "read_only",
    }


def _deployment_detail_rows(deployment_row: Dict[str, str] | None) -> List[tuple[str, str]]:
    row = deployment_row or {}
    return [
        ("Platform", row.get("platform", "-")),
        ("Method", row.get("method", "-")),
        ("Status", row.get("status", "-")),
        ("Readiness", row.get("readiness", "-")),
        ("Scope", row.get("scope", "-")),
        ("Local Platform", row.get("local_platform", "-")),
        ("Tested Locally", row.get("tested_locally", "-")),
        ("Execution", row.get("execution", "-")),
        ("Required Steps", row.get("required_steps", "-")),
        ("Warnings", row.get("warning_details", "-")),
        ("Blockers", row.get("blocker_details", "-")),
        ("Safety Mode", row.get("safety_mode", "-")),
        ("Notes", row.get("notes", "-")),
    ]


def _deployment_platform_type_rows(deployment_rows: List[Dict[str, str]], *, limit: int = 9) -> List[Dict[str, str]]:
    platform_order = ("windows", "macos", "linux", "container", "updater")
    counts = {platform: 0 for platform in platform_order}
    for row in deployment_rows:
        platform = row.get("platform") or "linux"
        counts[platform] = counts.get(platform, 0) + 1
    return [
        {"platform": platform, "count": str(count)}
        for platform, count in [(platform, counts[platform]) for platform in platform_order][: max(limit, 0)]
    ]


def _deployment_recent_event_rows(deployment_rows: List[Dict[str, str]], *, limit: int = 9) -> List[Dict[str, str]]:
    recent = sorted(deployment_rows, key=lambda row: row.get("updated") or "", reverse=True)[: max(limit, 0)]
    return [
        {
            "updated": row.get("updated", "-"),
            "platform": row.get("platform", "-"),
            "status": row.get("status", "-"),
            "method": row.get("method", "-"),
            "key": row.get("key", "-"),
        }
        for row in reversed(recent)
    ]


def _deployment_timeline_rows(deployment_rows: List[Dict[str, str]], *, limit: int = 9) -> List[Dict[str, str]]:
    buckets: Dict[str, Dict[str, int]] = {}
    for row in deployment_rows:
        updated = row.get("updated") or "-"
        bucket = updated[:10] if updated != "-" else "-"
        item = buckets.setdefault(bucket, {"ready": 0, "warnings": 0, "blockers": 0, "total": 0})
        item["total"] += 1
        if row.get("status") == "ready":
            item["ready"] += 1
        item["warnings"] += _deployment_int(row.get("warnings"))
        item["blockers"] += _deployment_int(row.get("blockers"))
    return [
        {
            "time": bucket,
            "ready": str(values["ready"]),
            "warnings": str(values["warnings"]),
            "blockers": str(values["blockers"]),
            "total": str(values["total"]),
        }
        for bucket, values in sorted(buckets.items(), reverse=True)[: max(limit, 0)]
    ]


def _ai_raw_time(event: Dict[str, Any]) -> Any:
    return event.get("created_at") or event.get("timestamp") or event.get("generated_at")


def _ai_event_time(event: Dict[str, Any]) -> str:
    return _format_timestamp(_ai_raw_time(event))


def _ai_sort_time(event: Dict[str, Any]) -> float:
    parsed = _timestamp_to_datetime(_ai_raw_time(event))
    return parsed.timestamp() if parsed else 0.0


def _ai_provider_value(event: Dict[str, Any]) -> str:
    return _short_text(
        event.get("ai_provider")
        or event.get("provider")
        or event.get("model_provider")
        or event.get("model_source")
        or "-",
        limit=24,
    )


def _ai_model_value(event: Dict[str, Any]) -> str:
    return _short_text(
        event.get("model")
        or event.get("model_name")
        or event.get("ai_model")
        or event.get("model_id")
        or "-",
        limit=24,
    )


def _ai_status_value(event: Dict[str, Any]) -> str:
    return _short_text(
        event.get("status")
        or event.get("event_state")
        or event.get("action")
        or event.get("decision")
        or event.get("event_type")
        or "observed",
        limit=24,
    )


def _ai_activity_value(event: Dict[str, Any]) -> str:
    return _short_text(
        event.get("decision")
        or event.get("action")
        or event.get("reason")
        or event.get("status")
        or event.get("event_type")
        or "observed",
        limit=28,
    )


def _ai_source_value(event: Dict[str, Any]) -> str:
    return _short_text(
        event.get("_ai_source") or event.get("event_type") or event.get("source_mode") or "-",
        limit=24,
    )


def _is_ai_event(event: Dict[str, Any]) -> bool:
    if any(
        event.get(key) not in {"", "-", None}
        for key in ("ai_provider", "provider", "model", "model_name", "ai_model")
    ):
        return True
    event_type = str(event.get("event_type") or "").lower()
    return "ai" in event_type or "model" in event_type


def _ai_enriched_event(event: Dict[str, Any], source: str) -> Dict[str, Any] | None:
    if not isinstance(event, dict) or not _is_ai_event(event):
        return None
    enriched = dict(event)
    enriched.setdefault("_ai_source", source)
    return enriched


def _ai_events_from_sources(
    *,
    remediation_events: List[Dict[str, Any]] | None = None,
    scan_results: List[Dict[str, Any]] | None = None,
    master_events: List[Dict[str, Any]] | None = None,
    limit: int = AI_ACTIVITY_LIMIT,
) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for source, rows in (
        ("remediation", remediation_events or []),
        ("scan_result", scan_results or []),
        ("master_event", master_events or []),
    ):
        for event in rows:
            enriched = _ai_enriched_event(event, source)
            if enriched is not None:
                events.append(enriched)
    events.sort(key=_ai_sort_time, reverse=True)
    return events[: max(limit, 0)]


def _ai_provider_model_rows(
    events: List[Dict[str, Any]],
    *,
    limit: int = AI_ACTIVITY_LIMIT,
) -> List[Dict[str, str]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for event in events:
        provider = _ai_provider_value(event)
        model = _ai_model_value(event)
        identity = "|".join([provider, model])
        row = grouped.setdefault(
            identity,
            {
                "provider": provider,
                "model": model,
                "decisions": 0,
                "updated": "-",
                "_sort_time": 0.0,
                "status": "-",
                "source": "-",
                "latest_activity": "-",
            },
        )
        row["decisions"] += 1
        sort_time = _ai_sort_time(event)
        if sort_time >= row["_sort_time"]:
            row["_sort_time"] = sort_time
            row["updated"] = _ai_event_time(event)
            row["status"] = _ai_status_value(event)
            row["source"] = _ai_source_value(event)
            row["latest_activity"] = _ai_activity_value(event)
    rows = sorted(
        grouped.values(),
        key=lambda row: (row["_sort_time"], row["provider"], row["model"]),
        reverse=True,
    )
    return [
        {
            "provider": row["provider"],
            "model": row["model"],
            "status": row["status"],
            "decisions": str(row["decisions"]),
            "updated": row["updated"],
            "source": row["source"],
            "latest_activity": row["latest_activity"],
            "mode": "read_only",
            "execution": "not performed",
            "key": "|".join([row["provider"], row["model"]]),
        }
        for row in rows[: max(limit, 0)]
    ]


def _ai_status_table_row(ai_rows: List[Dict[str, str]]) -> Dict[str, str]:
    providers = {row.get("provider") for row in ai_rows if row.get("provider") not in {"", "-", None}}
    models = {row.get("model") for row in ai_rows if row.get("model") not in {"", "-", None}}
    decisions = sum(_deployment_int(row.get("decisions")) for row in ai_rows)
    latest = max(
        (row.get("updated") for row in ai_rows if row.get("updated") not in {"", "-", None}),
        default="-",
    )
    return {
        "providers": str(len(providers)),
        "models": str(len(models)),
        "decisions": str(decisions),
        "last_updated": latest,
        "mode": "read_only",
    }


def _ai_detail_rows(ai_row: Dict[str, str] | None) -> List[tuple[str, str]]:
    row = ai_row or {}
    return [
        ("Provider", row.get("provider", "-")),
        ("Model", row.get("model", "-")),
        ("Status", row.get("status", "-")),
        ("Decisions", row.get("decisions", "-")),
        ("Updated", row.get("updated", "-")),
        ("Source", row.get("source", "-")),
        ("Latest Activity", row.get("latest_activity", "-")),
        ("Mode", row.get("mode", "-")),
        ("Execution", row.get("execution", "-")),
    ]


def _ai_provider_summary_rows(ai_rows: List[Dict[str, str]], *, limit: int = 9) -> List[Dict[str, str]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in ai_rows:
        provider = row.get("provider") or "-"
        item = grouped.setdefault(provider, {"provider": provider, "models": set(), "decisions": 0})
        model = row.get("model")
        if model not in {"", "-", None}:
            item["models"].add(model)
        item["decisions"] += _deployment_int(row.get("decisions"))
    rows = sorted(grouped.values(), key=lambda row: (-row["decisions"], row["provider"]))
    return [
        {"provider": row["provider"], "models": str(len(row["models"])), "decisions": str(row["decisions"])}
        for row in rows[: max(limit, 0)]
    ]


def _ai_recent_activity_rows(events: List[Dict[str, Any]], *, limit: int = 9) -> List[Dict[str, str]]:
    recent = sorted(events, key=_ai_sort_time, reverse=True)[: max(limit, 0)]
    return [
        {
            "time": _ai_event_time(event),
            "provider": _ai_provider_value(event),
            "model": _ai_model_value(event),
            "activity": _ai_activity_value(event),
            "key": "|".join(
                [_ai_event_time(event), _ai_provider_value(event), _ai_model_value(event), _ai_activity_value(event)]
            ),
        }
        for event in reversed(recent)
    ]


def _ai_timeline_rows(events: List[Dict[str, Any]], *, limit: int = 9) -> List[Dict[str, str]]:
    buckets: Dict[str, Dict[str, Any]] = {}
    for event in events:
        time = _ai_event_time(event)
        bucket = time[:10] if time != "-" else "-"
        item = buckets.setdefault(bucket, {"providers": set(), "decisions": 0, "events": 0})
        provider = _ai_provider_value(event)
        if provider != "-":
            item["providers"].add(provider)
        item["decisions"] += 1
        item["events"] += 1
    return [
        {
            "time": bucket,
            "providers": str(len(values["providers"])),
            "decisions": str(values["decisions"]),
            "events": str(values["events"]),
        }
        for bucket, values in sorted(buckets.items(), reverse=True)[: max(limit, 0)]
    ]


def _capture_table_selection(table: DataTable) -> Dict[str, Any]:
    row_index = table.cursor_row if isinstance(table.cursor_row, int) else 0
    selection: Dict[str, Any] = {"row_index": row_index, "row_key": None}
    try:
        if table.row_count > 0 and 0 <= row_index < table.row_count:
            cell_key = table.coordinate_to_cell_key(table.cursor_coordinate)
            selection["row_key"] = getattr(cell_key.row_key, "value", None)
    except Exception:
        pass
    return selection


def _restore_table_selection(table: DataTable, selection: Dict[str, Any]) -> None:
    try:
        row_count = table.row_count
    except Exception:
        return
    if row_count <= 0:
        return

    row_index = None
    row_key = selection.get("row_key")
    if row_key not in {"", "-", None}:
        try:
            row_index = table.get_row_index(str(row_key))
        except Exception:
            row_index = None

    if row_index is None:
        previous_index = selection.get("row_index", 0)
        if not isinstance(previous_index, int):
            previous_index = 0
        row_index = min(max(previous_index, 0), row_count - 1)

    try:
        table.move_cursor(row=row_index, column=0, animate=False, scroll=True)
    except Exception:
        pass


def _unique_table_key(base: Any, seen: set[str]) -> str:
    text = _short_text(base, limit=120)
    if text == "-":
        text = "row"
    candidate = text
    suffix = 2
    while candidate in seen:
        candidate = f"{text}#{suffix}"
        suffix += 1
    seen.add(candidate)
    return candidate


class NodeTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Node ID")
        self.add_column("Role")
        self.add_column("Status")
        self.add_column("Last Seen")

    def update_nodes(self, nodes: List[Dict[str, Any]]):
        selection = _capture_table_selection(self)
        self.clear()
        seen: set[str] = set()
        for node in nodes:
            node_id = str(node.get("node_id", "-"))
            self.add_row(
                node_id,
                node.get("role", "-"),
                node.get("status", "-"),
                str(node.get("last_seen", "-")),
                key=_unique_table_key(node_id, seen),
            )
        _restore_table_selection(self, selection)


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


class CompactRiskPanel(Static):
    def update_risk(
        self,
        remediation_events: List[Dict[str, Any]],
        scan_results: List[Dict[str, Any]],
    ) -> None:
        self.update(_format_dashboard_risk_overview(remediation_events, scan_results))


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
        selection = _capture_table_selection(self)
        self.clear()
        seen: set[str] = set()
        for event in events:
            self.add_row(
                event.get("timestamp", "-"),
                event.get("node_id", "-"),
                event.get("action", "-"),
                event.get("enforcement", "dry_run" if event.get("dry_run") else "-"),
                event.get("reason", "-"),
                f"{event.get('score', '-')}",
                _format_score_factors(event),
                key=_unique_table_key(
                    "|".join(
                        [
                            str(event.get("timestamp", "-")),
                            str(event.get("node_id", "-")),
                            str(event.get("action", "-")),
                            str(event.get("port", "-")),
                        ]
                    ),
                    seen,
                ),
            )
        _restore_table_selection(self, selection)


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
        selection = _capture_table_selection(self)
        self.clear()
        seen: set[str] = set()
        for row in rows:
            row_key = "|".join(
                [
                    str(row.get("timestamp", "-")),
                    str(row.get("node_id", "-")),
                    str(row.get("program", "-")),
                    str(row.get("port", "-")),
                    str(row.get("protocol", "-")),
                    str(row.get("source_mode", "unknown")),
                ]
            )
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
                key=_unique_table_key(row_key, seen),
            )
        _restore_table_selection(self, selection)


class CommandPanel(DataTable):
    def on_mount(self) -> None:
        self.add_column("Timestamp")
        self.add_column("Node")
        self.add_column("Command")
        self.add_column("Status")
        self.add_column("Result")

    def update_commands(self, events: List[Dict[str, Any]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        seen: set[str] = set()
        for event in events:
            self.add_row(
                event.get("timestamp", "-"),
                event.get("node_id", "-"),
                event.get("command_type", "-"),
                event.get("status", "-"),
                _format_command_result(event),
                key=_unique_table_key(
                    "|".join(
                        [
                            str(event.get("timestamp", "-")),
                            str(event.get("node_id", "-")),
                            str(event.get("command_type", "-")),
                            str(event.get("status", "-")),
                        ]
                    ),
                    seen,
                ),
            )
        _restore_table_selection(self, selection)


class ExpectedServicesPanel(DataTable):
    def on_mount(self) -> None:
        self.add_column("Observed Candidates")
        self.add_column("Allowlisted Services")

    def update_services(
        self,
        candidates: List[Dict[str, Any]],
        expected_services: List[Dict[str, Any]],
    ) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        seen: set[str] = set()
        rows = max(len(candidates), len(expected_services), 1)
        for index in range(rows):
            candidate = candidates[index] if index < len(candidates) else None
            expected = expected_services[index] if index < len(expected_services) else None
            candidate_label = _service_label(candidate)
            expected_label = _service_label(expected)
            self.add_row(
                candidate_label,
                expected_label,
                key=_unique_table_key(f"{candidate_label}|{expected_label}", seen),
            )
        _restore_table_selection(self, selection)


class RiskTimelinePanel(Static):
    def update_timeline(self, timeline: List[Dict[str, Any]]) -> None:
        self.update(render_risk_timeline(timeline))


class RiskStatusTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Current")
        self.add_column("Latest")
        self.add_column("Max")
        self.add_column("Avg")
        self.add_column("Updated")
        self.add_column("Provider")
        self.add_column("Monitor")
        self.add_column("Review")
        self.add_column("Block")
        self.add_column("Total")
        self.add_column("Mode")
        self.update_status([], [])

    def update_status(
        self,
        remediation_events: List[Dict[str, Any]],
        scan_results: List[Dict[str, Any]],
    ) -> None:
        selection = _capture_table_selection(self)
        row = _risk_status_table_row(remediation_events, scan_results)
        self.clear()
        self.add_row(
            row["current"],
            row["latest"],
            row["max"],
            row["avg"],
            row["updated"],
            row["provider"],
            row["monitor"],
            row["review"],
            row["block"],
            row["total"],
            row["mode"],
            key="risk-status",
        )
        _restore_table_selection(self, selection)


class RiskActiveFindingsTable(DataTable):
    def on_mount(self) -> None:
        self.finding_rows: List[Dict[str, str]] = []
        self.add_column("Severity")
        self.add_column("Asset")
        self.add_column("Service")
        self.add_column("Finding")
        self.add_column("Score")
        self.add_column("Action")
        self.add_column("Time")
        self.update_findings([], [])

    def update_findings(
        self,
        remediation_events: List[Dict[str, Any]],
        scan_results: List[Dict[str, Any]],
        new_keys: set[str] | None = None,
    ) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _active_risk_finding_rows(remediation_events, scan_results)
        self.finding_rows = rows
        if not rows:
            self.add_row("-", "-", "-", "No active risk findings available.", "-", "-", "-", key="empty")
            _restore_table_selection(self, selection)
            return
        new_keys = new_keys or set()
        seen: set[str] = set()
        for row in rows:
            severity = f"NEW {row['severity']}" if row["key"] in new_keys else row["severity"]
            self.add_row(
                severity,
                row["asset"],
                row["service"],
                row["finding"],
                row["score"],
                row["action"],
                row["time"],
                key=_unique_table_key(row["key"], seen),
            )
        _restore_table_selection(self, selection)

    def selected_finding(self, row_index: int | None = None) -> Dict[str, str] | None:
        if not self.finding_rows:
            return None
        index = self.cursor_row if row_index is None else row_index
        if not isinstance(index, int) or index < 0 or index >= len(self.finding_rows):
            index = 0
        return self.finding_rows[index]


class FindingDetailsTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Field")
        self.add_column("Value")
        self.update_details(None)

    def update_details(self, finding: Dict[str, str] | None) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        for field, value in _finding_detail_rows(finding):
            self.add_row(field, value, key=field)
        _restore_table_selection(self, selection)


class RiskSignalsTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Signal")
        self.add_column("Count")
        self.update_signals([], [])

    def update_signals(
        self,
        remediation_events: List[Dict[str, Any]],
        scan_results: List[Dict[str, Any]],
    ) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _top_risk_signal_rows(remediation_events, scan_results)
        if not rows:
            self.add_row("No risk signals available.", "-", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in rows:
            self.add_row(row["signal"], row["count"], key=_unique_table_key(row["signal"], seen))
        _restore_table_selection(self, selection)


class RiskFeedTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Time")
        self.add_column("Action")
        self.add_column("Score")
        self.add_column("Signal")
        self.update_feed([])

    def update_feed(
        self,
        events: List[Dict[str, Any]],
        new_keys: set[str] | None = None,
        selected_finding: Dict[str, str] | None = None,
    ) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _remediation_feed_rows(events)
        if not rows:
            self.add_row("-", "-", "-", "No remediation preview events yet.", key="empty")
            _restore_table_selection(self, selection)
            return
        new_keys = new_keys or set()
        seen: set[str] = set()
        for row in rows:
            markers = []
            if row["key"] in new_keys:
                markers.append("NEW")
            if _row_matches_selected_finding(selected_finding, row):
                markers.append("MATCH")
            signal = " ".join([*markers, row["signal"]]) if markers else row["signal"]
            self.add_row(row["time"], row["action"], row["score"], signal, key=_unique_table_key(row["key"], seen))
        _restore_table_selection(self, selection)


class RiskTimelineTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Time")
        self.add_column("Avg")
        self.add_column("Max")
        self.add_column("Events")
        self.add_column("Trend")
        self.update_timeline_rows([])

    def update_timeline_rows(
        self,
        timeline: List[Dict[str, Any]],
        new_keys: set[str] | None = None,
        selected_finding: Dict[str, str] | None = None,
    ) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _risk_timeline_rows(timeline)
        if not rows:
            self.add_row("-", "-", "-", "0", "No scored events yet.", key="empty")
            _restore_table_selection(self, selection)
            return
        new_keys = new_keys or set()
        seen: set[str] = set()
        for row in rows:
            trend = "new" if row["key"] in new_keys else row["trend"]
            if _row_matches_selected_finding(selected_finding, row):
                trend = "match" if trend == "-" else f"{trend}+match"
            self.add_row(
                row["time"],
                row["avg"],
                row["max"],
                row["events"],
                trend,
                key=_unique_table_key(row["key"], seen),
            )
        _restore_table_selection(self, selection)


class ExportStatusTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Last Export")
        self.add_column("Exports")
        self.add_column("Success")
        self.add_column("Failure")
        self.add_column("Destination")
        self.add_column("Validation")
        self.update_status([], Path("-"))

    def update_status(self, export_rows: List[Dict[str, str]], export_dir: Path) -> None:
        selection = _capture_table_selection(self)
        row = _export_status_table_row(export_rows, export_dir)
        self.clear()
        self.add_row(
            row["last_export"],
            row["export_count"],
            row["success_count"],
            row["failure_count"],
            row["destination"],
            row["validation_state"],
            key="export-status",
        )
        _restore_table_selection(self, selection)


class ExportActivityTable(DataTable):
    def on_mount(self) -> None:
        self.export_rows: List[Dict[str, str]] = []
        self.add_column("Timestamp")
        self.add_column("Export Type")
        self.add_column("Status")
        self.add_column("Destination")
        self.add_column("Files")
        self.add_column("Size")
        self.add_column("Duration")
        self.update_exports([])

    def update_exports(self, export_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        self.export_rows = export_rows
        if not export_rows:
            self.add_row("-", "-", "No exports available.", "-", "-", "-", "-", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in export_rows:
            self.add_row(
                row.get("timestamp", "-"),
                row.get("export_type", "-"),
                row.get("status", "-"),
                row.get("destination", "-"),
                row.get("files", "-"),
                row.get("size", "-"),
                row.get("duration", "-"),
                key=_unique_table_key(row.get("key") or row.get("export_id"), seen),
            )
        _restore_table_selection(self, selection)

    def selected_export(self, row_index: int | None = None) -> Dict[str, str] | None:
        if not self.export_rows:
            return None
        index = self.cursor_row if row_index is None else row_index
        if not isinstance(index, int) or index < 0 or index >= len(self.export_rows):
            index = 0
        return self.export_rows[index]


class ExportDetailsTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Field")
        self.add_column("Value")
        self.update_details(None)

    def update_details(self, export_row: Dict[str, str] | None) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        for field, value in _export_detail_rows(export_row):
            self.add_row(field, value, key=field)
        _restore_table_selection(self, selection)


class ExportTypesTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Export Type")
        self.add_column("Count")
        self.update_types([])

    def update_types(self, export_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _export_type_rows(export_rows)
        if not rows:
            self.add_row("No export types available.", "-", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in rows:
            self.add_row(
                row["export_type"],
                row["count"],
                key=_unique_table_key(row["export_type"], seen),
            )
        _restore_table_selection(self, selection)


class ExportEventsTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Time")
        self.add_column("Export Type")
        self.add_column("Status")
        self.add_column("Result")
        self.update_events([])

    def update_events(self, export_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _export_event_rows(export_rows)
        if not rows:
            self.add_row("-", "-", "-", "No export events available.", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in rows:
            self.add_row(
                row["time"],
                row["export_type"],
                row["status"],
                row["result"],
                key=_unique_table_key(row["key"], seen),
            )
        _restore_table_selection(self, selection)


class ExportValidationTimelineTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Time")
        self.add_column("Valid")
        self.add_column("Failed")
        self.add_column("Total")
        self.update_timeline([])

    def update_timeline(self, export_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _export_validation_timeline_rows(export_rows)
        if not rows:
            self.add_row("-", "0", "0", "0", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in rows:
            self.add_row(
                row["time"],
                row["valid"],
                row["failed"],
                row["total"],
                key=_unique_table_key(row["time"], seen),
            )
        _restore_table_selection(self, selection)


class GovernanceStatusTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Latest")
        self.add_column("Evidence")
        self.add_column("Preview")
        self.add_column("Exceptions")
        self.add_column("Categories")
        self.add_column("Readiness")
        self.update_status([])

    def update_status(self, governance_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        row = _governance_status_table_row(governance_rows)
        self.clear()
        self.add_row(
            row["latest"],
            row["evidence_count"],
            row["preview_count"],
            row["exception_count"],
            row["category_count"],
            row["readiness"],
            key="governance-status",
        )
        _restore_table_selection(self, selection)


class GovernanceEvidenceTable(DataTable):
    def on_mount(self) -> None:
        self.governance_rows: List[Dict[str, str]] = []
        self.add_column("Time")
        self.add_column("Category")
        self.add_column("Event Type")
        self.add_column("State")
        self.add_column("Actor")
        self.add_column("Target")
        self.add_column("Source")
        self.update_governance([])

    def update_governance(self, governance_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        self.governance_rows = governance_rows
        if not governance_rows:
            self.add_row("-", "-", "No governance evidence available.", "-", "-", "-", "-", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in governance_rows:
            self.add_row(
                row.get("time", "-"),
                row.get("category", "-"),
                row.get("event_type", "-"),
                row.get("state", "-"),
                row.get("actor", "-"),
                row.get("target", "-"),
                row.get("source", "-"),
                key=_unique_table_key(row.get("key"), seen),
            )
        _restore_table_selection(self, selection)

    def selected_governance(self, row_index: int | None = None) -> Dict[str, str] | None:
        if not self.governance_rows:
            return None
        index = self.cursor_row if row_index is None else row_index
        if not isinstance(index, int) or index < 0 or index >= len(self.governance_rows):
            index = 0
        return self.governance_rows[index]


class GovernanceDetailsTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Field")
        self.add_column("Value")
        self.update_details(None)

    def update_details(self, governance_row: Dict[str, str] | None) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        for field, value in _governance_detail_rows(governance_row):
            self.add_row(field, value, key=field)
        _restore_table_selection(self, selection)


class GovernanceCategoriesTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Category")
        self.add_column("Count")
        self.update_categories([])

    def update_categories(self, governance_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _governance_category_rows(governance_rows)
        if not rows:
            self.add_row("No evidence categories available.", "-", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in rows:
            self.add_row(row["category"], row["count"], key=_unique_table_key(row["category"], seen))
        _restore_table_selection(self, selection)


class GovernanceRecentEventsTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Time")
        self.add_column("Category")
        self.add_column("State")
        self.add_column("Event Type")
        self.update_events([])

    def update_events(self, governance_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _governance_recent_event_rows(governance_rows)
        if not rows:
            self.add_row("-", "-", "-", "No governance events available.", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in rows:
            self.add_row(
                row["time"],
                row["category"],
                row["state"],
                row["event_type"],
                key=_unique_table_key(row["key"], seen),
            )
        _restore_table_selection(self, selection)


class GovernanceTimelineTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Time")
        self.add_column("Events")
        self.add_column("Exceptions")
        self.add_column("Preview")
        self.update_timeline([])

    def update_timeline(self, governance_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _governance_timeline_rows(governance_rows)
        if not rows:
            self.add_row("-", "0", "0", "0", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in rows:
            self.add_row(
                row["time"],
                row["events"],
                row["exceptions"],
                row["preview"],
                key=_unique_table_key(row["time"], seen),
            )
        _restore_table_selection(self, selection)


class DeploymentStatusTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Platforms")
        self.add_column("Ready")
        self.add_column("Warnings")
        self.add_column("Blockers")
        self.add_column("Last Updated")
        self.add_column("Mode")
        self.update_status([])

    def update_status(self, deployment_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        row = _deployment_status_table_row(deployment_rows)
        self.clear()
        self.add_row(
            row["platforms"],
            row["ready"],
            row["warnings"],
            row["blockers"],
            row["last_updated"],
            row["mode"],
            key="deployment-status",
        )
        _restore_table_selection(self, selection)


class DeploymentReadinessTable(DataTable):
    def on_mount(self) -> None:
        self.deployment_rows: List[Dict[str, str]] = []
        self.add_column("Platform")
        self.add_column("Method")
        self.add_column("Status")
        self.add_column("Readiness")
        self.add_column("Warnings")
        self.add_column("Blockers")
        self.add_column("Updated")
        self.update_deployments([])

    def update_deployments(self, deployment_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        self.deployment_rows = deployment_rows
        if not deployment_rows:
            self.add_row("-", "-", "No deployment readiness available.", "-", "0", "0", "-", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in deployment_rows:
            self.add_row(
                row.get("platform", "-"),
                row.get("method", "-"),
                row.get("status", "-"),
                row.get("readiness", "-"),
                row.get("warnings", "0"),
                row.get("blockers", "0"),
                row.get("updated", "-"),
                key=_unique_table_key(row.get("key"), seen),
            )
        _restore_table_selection(self, selection)

    def selected_deployment(self, row_index: int | None = None) -> Dict[str, str] | None:
        if not self.deployment_rows:
            return None
        index = self.cursor_row if row_index is None else row_index
        if not isinstance(index, int) or index < 0 or index >= len(self.deployment_rows):
            index = 0
        return self.deployment_rows[index]


class DeploymentDetailsTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Field")
        self.add_column("Value")
        self.update_details(None)

    def update_details(self, deployment_row: Dict[str, str] | None) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        for field, value in _deployment_detail_rows(deployment_row):
            self.add_row(field, value, key=field)
        _restore_table_selection(self, selection)


class DeploymentPlatformTypesTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Platform Type")
        self.add_column("Count")
        self.update_platforms([])

    def update_platforms(self, deployment_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _deployment_platform_type_rows(deployment_rows)
        if not rows:
            self.add_row("No platform types available.", "-", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in rows:
            self.add_row(row["platform"], row["count"], key=_unique_table_key(row["platform"], seen))
        _restore_table_selection(self, selection)


class DeploymentEventsTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Updated")
        self.add_column("Platform")
        self.add_column("Status")
        self.add_column("Method")
        self.update_events([])

    def update_events(self, deployment_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _deployment_recent_event_rows(deployment_rows)
        if not rows:
            self.add_row("-", "-", "-", "No deployment events available.", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in rows:
            self.add_row(
                row["updated"],
                row["platform"],
                row["status"],
                row["method"],
                key=_unique_table_key(row["key"], seen),
            )
        _restore_table_selection(self, selection)


class DeploymentTimelineTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Time")
        self.add_column("Ready")
        self.add_column("Warnings")
        self.add_column("Blockers")
        self.add_column("Total")
        self.update_timeline([])

    def update_timeline(self, deployment_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _deployment_timeline_rows(deployment_rows)
        if not rows:
            self.add_row("-", "0", "0", "0", "0", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in rows:
            self.add_row(
                row["time"],
                row["ready"],
                row["warnings"],
                row["blockers"],
                row["total"],
                key=_unique_table_key(row["time"], seen),
            )
        _restore_table_selection(self, selection)


class AIStatusTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Providers")
        self.add_column("Models")
        self.add_column("Decisions")
        self.add_column("Last Updated")
        self.add_column("Mode")
        self.update_status([])

    def update_status(self, ai_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        row = _ai_status_table_row(ai_rows)
        self.clear()
        self.add_row(
            row["providers"],
            row["models"],
            row["decisions"],
            row["last_updated"],
            row["mode"],
            key="ai-status",
        )
        _restore_table_selection(self, selection)


class AIProviderModelTable(DataTable):
    def on_mount(self) -> None:
        self.ai_rows: List[Dict[str, str]] = []
        self.add_column("Provider")
        self.add_column("Model")
        self.add_column("Status")
        self.add_column("Decisions")
        self.add_column("Updated")
        self.update_ai([])

    def update_ai(self, ai_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        self.ai_rows = ai_rows
        if not ai_rows:
            self.add_row("-", "-", "No AI metadata available.", "0", "-", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in ai_rows:
            self.add_row(
                row.get("provider", "-"),
                row.get("model", "-"),
                row.get("status", "-"),
                row.get("decisions", "0"),
                row.get("updated", "-"),
                key=_unique_table_key(row.get("key"), seen),
            )
        _restore_table_selection(self, selection)

    def selected_ai(self, row_index: int | None = None) -> Dict[str, str] | None:
        if not self.ai_rows:
            return None
        index = self.cursor_row if row_index is None else row_index
        if not isinstance(index, int) or index < 0 or index >= len(self.ai_rows):
            index = 0
        return self.ai_rows[index]


class AIDetailsTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Field")
        self.add_column("Value")
        self.update_details(None)

    def update_details(self, ai_row: Dict[str, str] | None) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        for field, value in _ai_detail_rows(ai_row):
            self.add_row(field, value, key=field)
        _restore_table_selection(self, selection)


class AIProviderSummaryTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Provider")
        self.add_column("Models")
        self.add_column("Decisions")
        self.update_providers([])

    def update_providers(self, ai_rows: List[Dict[str, str]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _ai_provider_summary_rows(ai_rows)
        if not rows:
            self.add_row("No AI providers available.", "0", "0", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in rows:
            self.add_row(
                row["provider"],
                row["models"],
                row["decisions"],
                key=_unique_table_key(row["provider"], seen),
            )
        _restore_table_selection(self, selection)


class AIActivityTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Time")
        self.add_column("Provider")
        self.add_column("Model")
        self.add_column("Activity")
        self.update_activity([])

    def update_activity(self, events: List[Dict[str, Any]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _ai_recent_activity_rows(events)
        if not rows:
            self.add_row("-", "-", "-", "No AI activity available.", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in rows:
            self.add_row(
                row["time"],
                row["provider"],
                row["model"],
                row["activity"],
                key=_unique_table_key(row["key"], seen),
            )
        _restore_table_selection(self, selection)


class AITimelineTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Time")
        self.add_column("Providers")
        self.add_column("Decisions")
        self.add_column("Events")
        self.update_timeline([])

    def update_timeline(self, events: List[Dict[str, Any]]) -> None:
        selection = _capture_table_selection(self)
        self.clear()
        rows = _ai_timeline_rows(events)
        if not rows:
            self.add_row("-", "0", "0", "0", key="empty")
            _restore_table_selection(self, selection)
            return
        seen: set[str] = set()
        for row in rows:
            self.add_row(
                row["time"],
                row["providers"],
                row["decisions"],
                row["events"],
                key=_unique_table_key(row["time"], seen),
            )
        _restore_table_selection(self, selection)


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
        selection = _capture_table_selection(self)
        self.clear()
        seen: set[str] = set()
        for row in rows:
            row_key = "|".join(
                [
                    str(row.get("src_ip", "-")),
                    str(row.get("dst_ip", "-")),
                    str(row.get("protocols", "-")),
                    str(row.get("application_protocols", "-")),
                ]
            )
            self.add_row(
                str(row.get("src_ip", "-")),
                str(row.get("dst_ip", "-")),
                str(row.get("flow_count", 0)),
                str(row.get("packet_count", 0)),
                str(row.get("payload_bytes", 0)),
                str(row.get("protocols", "-")),
                str(row.get("application_protocols", "-")),
                key=_unique_table_key(row_key, seen),
            )
        _restore_table_selection(self, selection)


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
        selection = _capture_table_selection(self)
        self.clear()
        seen: set[str] = set()
        for row in rows:
            row_key = "|".join(
                [
                    str(row.get("first_seen", "-")),
                    str(row.get("last_seen", "-")),
                    str(row.get("flow", "-")),
                    str(row.get("application_protocols", "-")),
                ]
            )
            self.add_row(
                _format_timestamp(row.get("first_seen")),
                _format_timestamp(row.get("last_seen")),
                str(row.get("flow", "-")),
                str(row.get("application_protocols", "-")),
                str(row.get("packet_count", 0)),
                str(row.get("payload_bytes", 0)),
                str(row.get("findings", "-")),
                key=_unique_table_key(row_key, seen),
            )
        _restore_table_selection(self, selection)


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
    #tab-risk {
        height: 1fr;
    }
    #tab-exports {
        height: 1fr;
    }
    #tab-governance {
        height: 1fr;
    }
    #tab-deployment {
        height: 1fr;
    }
    #tab-ai {
        height: 1fr;
    }
    #risk-screen {
        layout: grid;
        grid-size: 3 5;
        grid-columns: 2fr 5fr 3fr;
        grid-rows: 3 1 13fr 7fr 2;
        overflow: hidden;
        height: 1fr;
        padding: 0 1;
    }
    .risk-grid-cell {
        width: 1fr;
        height: 1fr;
        overflow: hidden;
    }
    .risk-grid-span-2 {
        column-span: 2;
    }
    .risk-grid-span-3 {
        column-span: 3;
    }
    .risk-grid-heading {
        height: 1;
        max-height: 1;
        overflow: hidden;
    }
    .risk-status-table {
        height: 2;
        max-height: 2;
    }
    .risk-active-table {
        height: 1fr;
        max-height: 1fr;
    }
    .risk-details-table {
        height: 1fr;
        max-height: 1fr;
    }
    .risk-support-table {
        height: 1fr;
        max-height: 1fr;
    }
    .risk-footer-status {
        height: 2;
        max-height: 2;
    }
    .risk-section {
        padding: 0 1;
        margin: 0 1 0 0;
        width: 1fr;
        height: 1fr;
        overflow-x: hidden;
    }
    #exports-screen {
        layout: grid;
        grid-size: 3 4;
        grid-columns: 2fr 5fr 3fr;
        grid-rows: 3 1 13fr 7fr;
        overflow: hidden;
        height: 1fr;
        padding: 0 1;
    }
    .exports-grid-cell {
        width: 1fr;
        height: 1fr;
        overflow: hidden;
    }
    .exports-grid-span-2 {
        column-span: 2;
    }
    .exports-grid-span-3 {
        column-span: 3;
    }
    .exports-grid-heading {
        height: 1;
        max-height: 1;
        overflow: hidden;
    }
    .exports-status-table {
        height: 2;
        max-height: 2;
    }
    .exports-active-table {
        height: 1fr;
        max-height: 1fr;
    }
    .exports-details-table {
        height: 1fr;
        max-height: 1fr;
    }
    .exports-support-table {
        height: 1fr;
        max-height: 1fr;
    }
    .export-section {
        padding: 0 1;
        margin: 0 1 0 0;
        width: 1fr;
        height: 1fr;
        overflow-x: hidden;
    }
    #governance-screen {
        layout: grid;
        grid-size: 3 4;
        grid-columns: 2fr 5fr 3fr;
        grid-rows: 3 1 13fr 7fr;
        overflow: hidden;
        height: 1fr;
        padding: 0 1;
    }
    .governance-grid-cell {
        width: 1fr;
        height: 1fr;
        overflow: hidden;
    }
    .governance-grid-span-2 {
        column-span: 2;
    }
    .governance-grid-span-3 {
        column-span: 3;
    }
    .governance-grid-heading {
        height: 1;
        max-height: 1;
        overflow: hidden;
    }
    .governance-status-table {
        height: 2;
        max-height: 2;
    }
    .governance-active-table {
        height: 1fr;
        max-height: 1fr;
    }
    .governance-details-table {
        height: 1fr;
        max-height: 1fr;
    }
    .governance-support-table {
        height: 1fr;
        max-height: 1fr;
    }
    .governance-section {
        padding: 0 1;
        margin: 0 1 0 0;
        width: 1fr;
        height: 1fr;
        overflow-x: hidden;
    }
    #deployment-screen {
        layout: grid;
        grid-size: 3 4;
        grid-columns: 2fr 5fr 3fr;
        grid-rows: 3 1 13fr 7fr;
        overflow: hidden;
        height: 1fr;
        padding: 0 1;
    }
    .deployment-grid-cell {
        width: 1fr;
        height: 1fr;
        overflow: hidden;
    }
    .deployment-grid-span-2 {
        column-span: 2;
    }
    .deployment-grid-span-3 {
        column-span: 3;
    }
    .deployment-grid-heading {
        height: 1;
        max-height: 1;
        overflow: hidden;
    }
    .deployment-status-table {
        height: 2;
        max-height: 2;
    }
    .deployment-active-table {
        height: 1fr;
        max-height: 1fr;
    }
    .deployment-details-table {
        height: 1fr;
        max-height: 1fr;
    }
    .deployment-support-table {
        height: 1fr;
        max-height: 1fr;
    }
    .deployment-section {
        padding: 0 1;
        margin: 0 1 0 0;
        width: 1fr;
        height: 1fr;
        overflow-x: hidden;
    }
    #ai-screen {
        layout: grid;
        grid-size: 3 4;
        grid-columns: 2fr 5fr 3fr;
        grid-rows: 3 1 13fr 7fr;
        overflow: hidden;
        height: 1fr;
        padding: 0 1;
    }
    .ai-grid-cell {
        width: 1fr;
        height: 1fr;
        overflow: hidden;
    }
    .ai-grid-span-2 {
        column-span: 2;
    }
    .ai-grid-span-3 {
        column-span: 3;
    }
    .ai-grid-heading {
        height: 1;
        max-height: 1;
        overflow: hidden;
    }
    .ai-status-table {
        height: 2;
        max-height: 2;
    }
    .ai-active-table {
        height: 1fr;
        max-height: 1fr;
    }
    .ai-details-table {
        height: 1fr;
        max-height: 1fr;
    }
    .ai-support-table {
        height: 1fr;
        max-height: 1fr;
    }
    .ai-section {
        padding: 0 1;
        margin: 0 1 0 0;
        width: 1fr;
        height: 1fr;
        overflow-x: hidden;
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
                with Container(id="tab-risk", classes="tab-panel"):
                    yield from self._compose_risk_tab()
                continue
            if tab.tab_id == "exports":
                with Container(id="tab-exports", classes="tab-panel"):
                    yield from self._compose_exports_tab()
                continue
            if tab.tab_id == "governance":
                with Container(id="tab-governance", classes="tab-panel"):
                    yield from self._compose_governance_tab()
                continue
            if tab.tab_id == "deployment":
                with Container(id="tab-deployment", classes="tab-panel"):
                    yield from self._compose_deployment_tab()
                continue
            if tab.tab_id == "ai":
                with Container(id="tab-ai", classes="tab-panel"):
                    yield from self._compose_ai_tab()
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
                "Confirm worker online, press Scan Now, then press 2 Risk for detailed feed, timeline, and signals.",
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
                        "Risk Overview",
                        "Compact risk status. Press 2 for detailed remediation feed and timeline.",
                    ),
                    classes="panel-heading",
                )
                self.compact_risk_panel = CompactRiskPanel()
                yield self.compact_risk_panel
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
                "Expected Services",
                "Observed candidates are auto-detected. Add normal services to reduce noise.",
            ),
            classes="panel-heading",
        )
        self.expected_services_panel = ExpectedServicesPanel()
        yield self.expected_services_panel
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

    def _compose_risk_tab(self) -> ComposeResult:
        with Grid(id="risk-screen"):
            with Container(classes="risk-grid-cell risk-grid-span-3"):
                yield Static(
                    _panel_heading("Risk Status", "Score, queue, provider, and mode from the current refresh."),
                    classes="panel-heading risk-grid-heading",
                )
                self.risk_status_panel = RiskStatusTable(
                    classes=f"{RISK_WORKSPACE_CONTENT_CLASS} risk-status-table"
                )
                yield self.risk_status_panel
            yield Static(
                _panel_heading(
                    "Active Risk Findings",
                    "Primary investigation table from sampled ports and remediation previews.",
                ),
                classes="panel-heading risk-grid-heading risk-grid-span-2",
            )
            yield Static(
                _panel_heading("Finding Details", "Selected finding investigation context."),
                classes="panel-heading risk-grid-heading",
            )
            self.risk_active_findings_panel = RiskActiveFindingsTable(
                classes=f"{RISK_WORKSPACE_CONTENT_CLASS} risk-active-table risk-grid-span-2"
            )
            yield self.risk_active_findings_panel
            self.risk_finding_details_panel = FindingDetailsTable(
                classes=f"{RISK_WORKSPACE_CONTENT_CLASS} risk-details-table"
            )
            yield self.risk_finding_details_panel
            with Container(classes="risk-grid-cell"):
                yield Static(
                    _panel_heading("Top Risk Signals", "Frequency-counted current risk indicators."),
                    classes="panel-heading risk-grid-heading",
                )
                self.risk_signals_panel = RiskSignalsTable(
                    classes=f"{RISK_WORKSPACE_CONTENT_CLASS} risk-support-table"
                )
                yield self.risk_signals_panel
            with Container(classes="risk-grid-cell"):
                yield Static(
                    _panel_heading("Recent Remediation Feed", "Latest preview decisions capped for one-screen review."),
                    classes="panel-heading risk-grid-heading",
                )
                self.risk_feed_panel = RiskFeedTable(classes=f"{RISK_WORKSPACE_CONTENT_CLASS} risk-support-table")
                yield self.risk_feed_panel
            with Container(classes="risk-grid-cell"):
                yield Static(
                    _panel_heading("Risk Timeline", "Recent score buckets and queue activity."),
                    classes="panel-heading risk-grid-heading",
                )
                self.risk_workspace_timeline_panel = RiskTimelineTable(
                    classes=f"{RISK_WORKSPACE_CONTENT_CLASS} risk-support-table",
                )
                yield self.risk_workspace_timeline_panel
            sections = build_risk_workspace_sections()
            self.risk_footer_status_panel = Static(
                _format_footer_status(sections["allowlist_status"], sections["safety_boundary"]),
                classes=f"{RISK_WORKSPACE_CONTENT_CLASS} risk-footer-status risk-grid-span-3",
            )
            yield self.risk_footer_status_panel

    def _compose_exports_tab(self) -> ComposeResult:
        with Grid(id="exports-screen"):
            with Container(classes="exports-grid-cell exports-grid-span-3"):
                yield Static(
                    _panel_heading("Export Status", "Last export, totals, destination, and validation state."),
                    classes="panel-heading exports-grid-heading",
                )
                self.exports_status_panel = ExportStatusTable(
                    classes=f"{EXPORT_WORKSPACE_CONTENT_CLASS} exports-status-table"
                )
                yield self.exports_status_panel
            yield Static(
                _panel_heading(
                    "Recent Exports",
                    "Read-only export activity from the configured export destination.",
                ),
                classes="panel-heading exports-grid-heading exports-grid-span-2",
            )
            yield Static(
                _panel_heading("Export Details", "Selected export validation context."),
                classes="panel-heading exports-grid-heading",
            )
            self.export_activity_panel = ExportActivityTable(
                classes=f"{EXPORT_WORKSPACE_CONTENT_CLASS} exports-active-table exports-grid-span-2"
            )
            yield self.export_activity_panel
            self.export_details_panel = ExportDetailsTable(
                classes=f"{EXPORT_WORKSPACE_CONTENT_CLASS} exports-details-table"
            )
            yield self.export_details_panel
            with Container(classes="exports-grid-cell"):
                yield Static(
                    _panel_heading("Export Types", "Count by export category."),
                    classes="panel-heading exports-grid-heading",
                )
                self.export_types_panel = ExportTypesTable(
                    classes=f"{EXPORT_WORKSPACE_CONTENT_CLASS} exports-support-table"
                )
                yield self.export_types_panel
            with Container(classes="exports-grid-cell"):
                yield Static(
                    _panel_heading("Recent Export Events", "Chronological validation feed."),
                    classes="panel-heading exports-grid-heading",
                )
                self.export_events_panel = ExportEventsTable(
                    classes=f"{EXPORT_WORKSPACE_CONTENT_CLASS} exports-support-table"
                )
                yield self.export_events_panel
            with Container(classes="exports-grid-cell"):
                yield Static(
                    _panel_heading("Validation Timeline", "Bucketed export validation history."),
                    classes="panel-heading exports-grid-heading",
                )
                self.export_validation_timeline_panel = ExportValidationTimelineTable(
                    classes=f"{EXPORT_WORKSPACE_CONTENT_CLASS} exports-support-table",
                )
                yield self.export_validation_timeline_panel

    def _compose_governance_tab(self) -> ComposeResult:
        with Grid(id="governance-screen"):
            with Container(classes="governance-grid-cell governance-grid-span-3"):
                yield Static(
                    _panel_heading("Governance Status", "Audit evidence, preview safety, and readiness state."),
                    classes="panel-heading governance-grid-heading",
                )
                self.governance_status_panel = GovernanceStatusTable(
                    classes=f"{GOVERNANCE_WORKSPACE_CONTENT_CLASS} governance-status-table"
                )
                yield self.governance_status_panel
            yield Static(
                _panel_heading(
                    "Governance Evidence",
                    "Read-only evidence from audit, command, remediation, and export records.",
                ),
                classes="panel-heading governance-grid-heading governance-grid-span-2",
            )
            yield Static(
                _panel_heading("Governance Details", "Selected governance evidence context."),
                classes="panel-heading governance-grid-heading",
            )
            self.governance_evidence_panel = GovernanceEvidenceTable(
                classes=f"{GOVERNANCE_WORKSPACE_CONTENT_CLASS} governance-active-table governance-grid-span-2"
            )
            yield self.governance_evidence_panel
            self.governance_details_panel = GovernanceDetailsTable(
                classes=f"{GOVERNANCE_WORKSPACE_CONTENT_CLASS} governance-details-table"
            )
            yield self.governance_details_panel
            with Container(classes="governance-grid-cell"):
                yield Static(
                    _panel_heading("Evidence Categories", "Count by governance evidence category."),
                    classes="panel-heading governance-grid-heading",
                )
                self.governance_categories_panel = GovernanceCategoriesTable(
                    classes=f"{GOVERNANCE_WORKSPACE_CONTENT_CLASS} governance-support-table"
                )
                yield self.governance_categories_panel
            with Container(classes="governance-grid-cell"):
                yield Static(
                    _panel_heading("Recent Governance Events", "Chronological governance evidence feed."),
                    classes="panel-heading governance-grid-heading",
                )
                self.governance_recent_events_panel = GovernanceRecentEventsTable(
                    classes=f"{GOVERNANCE_WORKSPACE_CONTENT_CLASS} governance-support-table"
                )
                yield self.governance_recent_events_panel
            with Container(classes="governance-grid-cell"):
                yield Static(
                    _panel_heading("Governance Timeline", "Bucketed evidence and exception history."),
                    classes="panel-heading governance-grid-heading",
                )
                self.governance_timeline_panel = GovernanceTimelineTable(
                    classes=f"{GOVERNANCE_WORKSPACE_CONTENT_CLASS} governance-support-table",
                )
                yield self.governance_timeline_panel

    def _compose_deployment_tab(self) -> ComposeResult:
        with Grid(id="deployment-screen"):
            with Container(classes="deployment-grid-cell deployment-grid-span-3"):
                yield Static(
                    _panel_heading(
                        "Deployment Readiness Catalog",
                        "Metadata-only readiness catalog. Not a live install/test result.",
                    ),
                    classes="panel-heading deployment-grid-heading",
                )
                self.deployment_status_panel = DeploymentStatusTable(
                    classes=f"{DEPLOYMENT_WORKSPACE_CONTENT_CLASS} deployment-status-table"
                )
                yield self.deployment_status_panel
            yield Static(
                _panel_heading(
                    "Deployment Targets / Readiness Records",
                    "Target records for supported package/deployment families, not proof of local validation.",
                ),
                classes="panel-heading deployment-grid-heading deployment-grid-span-2",
            )
            yield Static(
                _panel_heading("Deployment Details", "Selected deployment readiness context."),
                classes="panel-heading deployment-grid-heading",
            )
            self.deployment_readiness_panel = DeploymentReadinessTable(
                classes=f"{DEPLOYMENT_WORKSPACE_CONTENT_CLASS} deployment-active-table deployment-grid-span-2"
            )
            yield self.deployment_readiness_panel
            self.deployment_details_panel = DeploymentDetailsTable(
                classes=f"{DEPLOYMENT_WORKSPACE_CONTENT_CLASS} deployment-details-table"
            )
            yield self.deployment_details_panel
            with Container(classes="deployment-grid-cell"):
                yield Static(
                    _panel_heading("Platform Types", "Readiness records by platform family."),
                    classes="panel-heading deployment-grid-heading",
                )
                self.deployment_platform_types_panel = DeploymentPlatformTypesTable(
                    classes=f"{DEPLOYMENT_WORKSPACE_CONTENT_CLASS} deployment-support-table"
                )
                yield self.deployment_platform_types_panel
            with Container(classes="deployment-grid-cell"):
                yield Static(
                    _panel_heading("Recent Deployment Events", "Chronological readiness record feed."),
                    classes="panel-heading deployment-grid-heading",
                )
                self.deployment_events_panel = DeploymentEventsTable(
                    classes=f"{DEPLOYMENT_WORKSPACE_CONTENT_CLASS} deployment-support-table"
                )
                yield self.deployment_events_panel
            with Container(classes="deployment-grid-cell"):
                yield Static(
                    _panel_heading("Deployment Timeline", "Bucketed readiness, warning, and blocker history."),
                    classes="panel-heading deployment-grid-heading",
                )
                self.deployment_timeline_panel = DeploymentTimelineTable(
                    classes=f"{DEPLOYMENT_WORKSPACE_CONTENT_CLASS} deployment-support-table",
                )
                yield self.deployment_timeline_panel

    def _compose_ai_tab(self) -> ComposeResult:
        with Grid(id="ai-screen"):
            with Container(classes="ai-grid-cell ai-grid-span-3"):
                yield Static(
                    _panel_heading(
                        "AI Summary",
                        "Read-only AI metadata from existing observations; no inference or model loading.",
                    ),
                    classes="panel-heading ai-grid-heading",
                )
                self.ai_status_panel = AIStatusTable(classes=f"{AI_WORKSPACE_CONTENT_CLASS} ai-status-table")
                yield self.ai_status_panel
            yield Static(
                _panel_heading(
                    "AI Provider / Model",
                    "Provider and model records from observed AI metadata only.",
                ),
                classes="panel-heading ai-grid-heading ai-grid-span-2",
            )
            yield Static(
                _panel_heading("AI Details", "Selected provider/model metadata context."),
                classes="panel-heading ai-grid-heading",
            )
            self.ai_provider_model_panel = AIProviderModelTable(
                classes=f"{AI_WORKSPACE_CONTENT_CLASS} ai-active-table ai-grid-span-2"
            )
            yield self.ai_provider_model_panel
            self.ai_details_panel = AIDetailsTable(classes=f"{AI_WORKSPACE_CONTENT_CLASS} ai-details-table")
            yield self.ai_details_panel
            with Container(classes="ai-grid-cell"):
                yield Static(
                    _panel_heading("Provider Summary", "Aggregate observed AI metadata by provider."),
                    classes="panel-heading ai-grid-heading",
                )
                self.ai_provider_summary_panel = AIProviderSummaryTable(
                    classes=f"{AI_WORKSPACE_CONTENT_CLASS} ai-support-table"
                )
                yield self.ai_provider_summary_panel
            with Container(classes="ai-grid-cell"):
                yield Static(
                    _panel_heading("Recent AI Activity", "Recent AI-related observations from existing events."),
                    classes="panel-heading ai-grid-heading",
                )
                self.ai_activity_panel = AIActivityTable(classes=f"{AI_WORKSPACE_CONTENT_CLASS} ai-support-table")
                yield self.ai_activity_panel
            with Container(classes="ai-grid-cell"):
                yield Static(
                    _panel_heading("AI Timeline", "Bucketed summary of observed AI metadata."),
                    classes="panel-heading ai-grid-heading",
                )
                self.ai_timeline_panel = AITimelineTable(classes=f"{AI_WORKSPACE_CONTENT_CLASS} ai-support-table")
                yield self.ai_timeline_panel

    async def on_mount(self) -> None:
        self._load_orchestrator_defaults()
        self.runtime_settings = load_settings(defaults={})
        self.firewall_status = _resolve_firewall_status(self.runtime_settings)
        self.export_dir = resolve_export_dir()
        self._allowlist_candidates: List[Dict[str, Any]] = []
        self._expected_services: List[Dict[str, Any]] = []
        self._nodes_cache: List[Dict[str, Any]] = []
        self._risk_finding_keys: set[str] | None = None
        self._risk_feed_keys: set[str] | None = None
        self._risk_timeline_keys: set[str] | None = None
        self._risk_last_remediation_events: List[Dict[str, Any]] = []
        self._risk_last_timeline: List[Dict[str, Any]] = []
        self._risk_last_feed_new_keys: set[str] = set()
        self._risk_last_timeline_new_keys: set[str] = set()
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
        if hasattr(self, "remediation_panel"):
            self.remediation_panel.update_events(remediation_events)
        scan_results = self._load_scan_results(remediation_events, limit=self.tail_size)
        self.scan_results_panel.update_results(scan_results)
        risk_timeline = build_risk_timeline([*remediation_events, *scan_results], limit=self.tail_size)
        flow_visualization = self._load_flow_visualization(limit=max(self.tail_size * 4, 20))
        if hasattr(self, "risk_timeline_panel"):
            self.risk_timeline_panel.update_timeline(risk_timeline)
        if hasattr(self, "compact_risk_panel"):
            self.compact_risk_panel.update_risk(remediation_events, scan_results)
        if hasattr(self, "exports_status_panel"):
            self._update_exports_workspace(self._load_export_rows(limit=max(self.tail_size * 4, EXPORT_ACTIVITY_LIMIT)))
        if hasattr(self, "governance_status_panel"):
            self._update_governance_workspace(
                self._load_governance_rows(
                    remediation_events=remediation_events,
                    export_rows=self._load_export_rows(limit=max(self.tail_size * 4, EXPORT_ACTIVITY_LIMIT)),
                    limit=max(self.tail_size * 4, GOVERNANCE_EVIDENCE_LIMIT),
                )
            )
        if hasattr(self, "deployment_status_panel"):
            self._update_deployment_workspace(
                self._load_deployment_rows(limit=max(self.tail_size * 4, DEPLOYMENT_READINESS_LIMIT))
            )
        if hasattr(self, "ai_status_panel"):
            self._update_ai_workspace(
                self._load_ai_events(
                    remediation_events=remediation_events,
                    scan_results=scan_results,
                    limit=max(self.tail_size * 4, AI_ACTIVITY_LIMIT),
                )
            )
        if hasattr(self, "topology_panel"):
            self.topology_panel.update_topology(topology_edge_rows(flow_visualization.get("topology"), limit=self.tail_size))
        if hasattr(self, "traffic_flows_panel"):
            self.traffic_flows_panel.update_flows(flow_rows(flow_visualization.get("flows") or [], limit=self.tail_size))
        self._allowlist_candidates = self._build_allowlist_candidates(remediation_events)
        self._expected_services = [
            item for item in self.runtime_settings.get("expected_services", []) if isinstance(item, dict)
        ]
        self.expected_services_panel.update_services(self._allowlist_candidates, self._expected_services)
        self._update_risk_workspace(
            remediation_events=remediation_events,
            scan_results=scan_results,
            risk_timeline=risk_timeline,
            allowlist_candidates=self._allowlist_candidates,
            expected_services=self._expected_services,
            selected_index=self._selected_expected_services_row(),
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

    def _load_export_rows(self, limit: int = EXPORT_ACTIVITY_LIMIT) -> List[Dict[str, str]]:
        return _export_rows_from_dir(getattr(self, "export_dir", resolve_export_dir()), limit=limit)

    def _update_exports_workspace(self, export_rows: List[Dict[str, str]]) -> None:
        if not hasattr(self, "exports_status_panel"):
            return
        export_dir = getattr(self, "export_dir", resolve_export_dir())
        self.exports_status_panel.update_status(export_rows, export_dir)
        self.export_activity_panel.update_exports(export_rows)
        selected_export = self.export_activity_panel.selected_export()
        self.export_details_panel.update_details(selected_export)
        self.export_types_panel.update_types(export_rows)
        self.export_events_panel.update_events(export_rows)
        self.export_validation_timeline_panel.update_timeline(export_rows)

    def _load_governance_rows(
        self,
        *,
        remediation_events: List[Dict[str, Any]] | None = None,
        export_rows: List[Dict[str, str]] | None = None,
        limit: int = GOVERNANCE_EVIDENCE_LIMIT,
    ) -> List[Dict[str, str]]:
        audit_events = read_jsonl(AUDIT_EVENTS_LOG, limit=limit)
        command_events = self._load_command_events(limit=limit)
        return _governance_rows_from_sources(
            audit_events=audit_events,
            command_events=command_events,
            remediation_events=remediation_events,
            export_rows=export_rows,
            limit=limit,
        )

    def _update_governance_workspace(self, governance_rows: List[Dict[str, str]]) -> None:
        if not hasattr(self, "governance_status_panel"):
            return
        self.governance_status_panel.update_status(governance_rows)
        self.governance_evidence_panel.update_governance(governance_rows)
        selected_governance = self.governance_evidence_panel.selected_governance()
        self.governance_details_panel.update_details(selected_governance)
        self.governance_categories_panel.update_categories(governance_rows)
        self.governance_recent_events_panel.update_events(governance_rows)
        self.governance_timeline_panel.update_timeline(governance_rows)

    def _load_deployment_rows(self, limit: int = DEPLOYMENT_READINESS_LIMIT) -> List[Dict[str, str]]:
        return _build_default_deployment_readiness_rows(limit=limit)

    def _update_deployment_workspace(self, deployment_rows: List[Dict[str, str]]) -> None:
        if not hasattr(self, "deployment_status_panel"):
            return
        self.deployment_status_panel.update_status(deployment_rows)
        self.deployment_readiness_panel.update_deployments(deployment_rows)
        selected_deployment = self.deployment_readiness_panel.selected_deployment()
        self.deployment_details_panel.update_details(selected_deployment)
        self.deployment_platform_types_panel.update_platforms(deployment_rows)
        self.deployment_events_panel.update_events(deployment_rows)
        self.deployment_timeline_panel.update_timeline(deployment_rows)

    def _load_ai_events(
        self,
        *,
        remediation_events: List[Dict[str, Any]] | None = None,
        scan_results: List[Dict[str, Any]] | None = None,
        limit: int = AI_ACTIVITY_LIMIT,
    ) -> List[Dict[str, Any]]:
        return _ai_events_from_sources(
            remediation_events=remediation_events,
            scan_results=scan_results,
            master_events=self._load_master_events(limit=limit),
            limit=limit,
        )

    def _update_ai_workspace(self, ai_events: List[Dict[str, Any]]) -> None:
        if not hasattr(self, "ai_status_panel"):
            return
        ai_rows = _ai_provider_model_rows(ai_events, limit=AI_ACTIVITY_LIMIT)
        self.ai_status_panel.update_status(ai_rows)
        self.ai_provider_model_panel.update_ai(ai_rows)
        selected_ai = self.ai_provider_model_panel.selected_ai()
        self.ai_details_panel.update_details(selected_ai)
        self.ai_provider_summary_panel.update_providers(ai_rows)
        self.ai_activity_panel.update_activity(ai_events)
        self.ai_timeline_panel.update_timeline(ai_events)

    def _update_risk_workspace(
        self,
        *,
        remediation_events: List[Dict[str, Any]],
        scan_results: List[Dict[str, Any]],
        risk_timeline: List[Dict[str, Any]],
        allowlist_candidates: List[Dict[str, Any]],
        expected_services: List[Dict[str, Any]],
        selected_index: int,
    ) -> None:
        if not hasattr(self, "risk_status_panel"):
            return
        sections = build_risk_workspace_sections(
            remediation_events=remediation_events,
            scan_results=scan_results,
            risk_timeline=risk_timeline,
            allowlist_candidates=allowlist_candidates,
            expected_services=expected_services,
            selected_index=selected_index,
        )
        finding_keys = {row["key"] for row in _active_risk_finding_rows(remediation_events, scan_results)}
        feed_keys = {row["key"] for row in _remediation_feed_rows(remediation_events)}
        timeline_keys = {row["key"] for row in _risk_timeline_rows(risk_timeline)}
        previous_finding_keys = getattr(self, "_risk_finding_keys", None)
        previous_feed_keys = getattr(self, "_risk_feed_keys", None)
        previous_timeline_keys = getattr(self, "_risk_timeline_keys", None)
        new_finding_keys = finding_keys - previous_finding_keys if previous_finding_keys is not None else set()
        new_feed_keys = feed_keys - previous_feed_keys if previous_feed_keys is not None else set()
        new_timeline_keys = timeline_keys - previous_timeline_keys if previous_timeline_keys is not None else set()
        self._risk_finding_keys = finding_keys
        self._risk_feed_keys = feed_keys
        self._risk_timeline_keys = timeline_keys
        self._risk_last_remediation_events = remediation_events
        self._risk_last_timeline = risk_timeline
        self._risk_last_feed_new_keys = new_feed_keys
        self._risk_last_timeline_new_keys = new_timeline_keys
        self.risk_status_panel.update_status(remediation_events, scan_results)
        self.risk_active_findings_panel.update_findings(
            remediation_events,
            scan_results,
            new_keys=new_finding_keys,
        )
        selected_finding = self.risk_active_findings_panel.selected_finding()
        self.risk_finding_details_panel.update_details(selected_finding)
        self.risk_signals_panel.update_signals(remediation_events, scan_results)
        self.risk_feed_panel.update_feed(
            remediation_events,
            new_keys=new_feed_keys,
            selected_finding=selected_finding,
        )
        self.risk_workspace_timeline_panel.update_timeline_rows(
            risk_timeline,
            new_keys=new_timeline_keys,
            selected_finding=selected_finding,
        )
        self.risk_footer_status_panel.update(_format_footer_status(sections["allowlist_status"], sections["safety_boundary"]))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if getattr(self, "ai_provider_model_panel", None) is event.data_table:
            if hasattr(self, "ai_details_panel"):
                self.ai_details_panel.update_details(self.ai_provider_model_panel.selected_ai(event.cursor_row))
            return
        if getattr(self, "deployment_readiness_panel", None) is event.data_table:
            if hasattr(self, "deployment_details_panel"):
                self.deployment_details_panel.update_details(
                    self.deployment_readiness_panel.selected_deployment(event.cursor_row)
                )
            return
        if getattr(self, "governance_evidence_panel", None) is event.data_table:
            if hasattr(self, "governance_details_panel"):
                self.governance_details_panel.update_details(
                    self.governance_evidence_panel.selected_governance(event.cursor_row)
                )
            return
        if getattr(self, "export_activity_panel", None) is event.data_table:
            if hasattr(self, "export_details_panel"):
                self.export_details_panel.update_details(
                    self.export_activity_panel.selected_export(event.cursor_row)
                )
            return
        if getattr(self, "risk_active_findings_panel", None) is not event.data_table:
            return
        if not hasattr(self, "risk_finding_details_panel"):
            return
        selected_finding = self.risk_active_findings_panel.selected_finding(event.cursor_row)
        self.risk_finding_details_panel.update_details(selected_finding)
        if hasattr(self, "risk_feed_panel"):
            self.risk_feed_panel.update_feed(
                getattr(self, "_risk_last_remediation_events", []),
                new_keys=getattr(self, "_risk_last_feed_new_keys", set()),
                selected_finding=selected_finding,
            )
        if hasattr(self, "risk_workspace_timeline_panel"):
            self.risk_workspace_timeline_panel.update_timeline_rows(
                getattr(self, "_risk_last_timeline", []),
                new_keys=getattr(self, "_risk_last_timeline_new_keys", set()),
                selected_finding=selected_finding,
            )

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
        if tab_id == "deployment":
            self._set_status("Deployment tab is read-only; Scan Now is a global orchestrator action.")
        elif tab:
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
