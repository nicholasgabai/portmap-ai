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


def _risk_finding_count(event: Dict[str, Any]) -> str:
    for key in ("count", "event_count", "seen_count", "occurrences"):
        value = event.get(key)
        if value not in {"", "-", None}:
            return _short_text(value, limit=12)
    return "-"


def _format_optional_timestamp(value: Any) -> str:
    formatted = _format_timestamp(value)
    return formatted if formatted != "-" else "-"


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
    rows = []
    for event in sorted(events, key=_risk_finding_sort_key, reverse=True)[: max(limit, 0)]:
        score_value = _numeric_risk_score(event)
        rows.append(
            {
                "severity": _risk_severity_label(score_value),
                "asset": _risk_finding_target(event),
                "service": _risk_finding_service(event),
                "finding": _risk_finding_summary(event),
                "score": _format_compact_risk_score(score_value),
                "action": _short_text(event.get("action") or event.get("status") or event.get("reason"), limit=12),
                "time": _format_time(event.get("timestamp") or event.get("generated_at")),
                "provider": _risk_finding_provider(event),
                "state": _risk_finding_state(event),
                "first_seen": _format_optional_timestamp(event.get("first_seen")),
                "last_seen": _format_optional_timestamp(event.get("last_seen")),
                "count": _risk_finding_count(event),
                "key": _risk_finding_key(event),
            }
        )
    return rows


def _finding_detail_rows(finding: Dict[str, str] | None) -> List[tuple[str, str]]:
    row = finding or {}
    return [
        ("Asset", row.get("asset", "-")),
        ("Service", row.get("service", "-")),
        ("Finding", row.get("finding", "-")),
        ("Provider", row.get("provider", "-")),
        ("Score", row.get("score", "-")),
        ("Action", row.get("action", "-")),
        ("Time", row.get("time", "-")),
        ("State", row.get("state", "-")),
        ("First Seen", row.get("first_seen", "-")),
        ("Last Seen", row.get("last_seen", "-")),
        ("Count", row.get("count", "-")),
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
        rows.append(
            {
                "time": _format_time(event.get("timestamp") or event.get("generated_at")),
                "action": _short_text(event.get("action"), limit=14),
                "score": _format_compact_risk_score(_numeric_risk_score(event)),
                "signal": _short_text(_format_score_factors(event, limit=1), limit=24),
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
        )


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
        self.clear()
        rows = _active_risk_finding_rows(remediation_events, scan_results)
        self.finding_rows = rows
        if not rows:
            self.add_row("-", "-", "-", "No active risk findings available.", "-", "-", "-")
            return
        new_keys = new_keys or set()
        for index, row in enumerate(rows):
            severity = f"NEW {row['severity']}" if row["key"] in new_keys else row["severity"]
            self.add_row(
                severity,
                row["asset"],
                row["service"],
                row["finding"],
                row["score"],
                row["action"],
                row["time"],
                key=f"{index}:{row['key']}",
            )

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
        self.clear()
        for field, value in _finding_detail_rows(finding):
            self.add_row(field, value)


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
        self.clear()
        rows = _top_risk_signal_rows(remediation_events, scan_results)
        if not rows:
            self.add_row("No risk signals available.", "-")
            return
        for row in rows:
            self.add_row(row["signal"], row["count"])


class RiskFeedTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Time")
        self.add_column("Action")
        self.add_column("Score")
        self.add_column("Signal")
        self.update_feed([])

    def update_feed(self, events: List[Dict[str, Any]], new_keys: set[str] | None = None) -> None:
        self.clear()
        rows = _remediation_feed_rows(events)
        if not rows:
            self.add_row("-", "-", "-", "No remediation preview events yet.")
            return
        new_keys = new_keys or set()
        for row in rows:
            signal = f"NEW {row['signal']}" if row["key"] in new_keys else row["signal"]
            self.add_row(row["time"], row["action"], row["score"], signal)


class RiskTimelineTable(DataTable):
    def on_mount(self) -> None:
        self.add_column("Time")
        self.add_column("Avg")
        self.add_column("Max")
        self.add_column("Events")
        self.add_column("Trend")
        self.update_timeline_rows([])

    def update_timeline_rows(self, timeline: List[Dict[str, Any]], new_keys: set[str] | None = None) -> None:
        self.clear()
        rows = _risk_timeline_rows(timeline)
        if not rows:
            self.add_row("-", "-", "-", "0", "No scored events yet.")
            return
        new_keys = new_keys or set()
        for row in rows:
            trend = "new" if row["key"] in new_keys else row["trend"]
            self.add_row(row["time"], row["avg"], row["max"], row["events"], trend)


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
    #tab-risk {
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
        self.risk_status_panel.update_status(remediation_events, scan_results)
        self.risk_active_findings_panel.update_findings(
            remediation_events,
            scan_results,
            new_keys=new_finding_keys,
        )
        self.risk_finding_details_panel.update_details(self.risk_active_findings_panel.selected_finding())
        self.risk_signals_panel.update_signals(remediation_events, scan_results)
        self.risk_feed_panel.update_feed(remediation_events, new_keys=new_feed_keys)
        self.risk_workspace_timeline_panel.update_timeline_rows(risk_timeline, new_keys=new_timeline_keys)
        self.risk_footer_status_panel.update(_format_footer_status(sections["allowlist_status"], sections["safety_boundary"]))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if getattr(self, "risk_active_findings_panel", None) is not event.data_table:
            return
        if not hasattr(self, "risk_finding_details_panel"):
            return
        self.risk_finding_details_panel.update_details(
            self.risk_active_findings_panel.selected_finding(event.cursor_row)
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
