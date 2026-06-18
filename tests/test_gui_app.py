import json
from datetime import datetime
from pathlib import Path

import pytest

pytest.importorskip("textual")

from gui import app as gui_app
from gui import visualization


def _timestamp(date, *parts):
    return f"{date}T{':'.join(parts)}Z"


def _local_display_from_iso(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return datetime.fromtimestamp(parsed.timestamp()).strftime("%Y-%m-%d %H:%M:%S")


def test_compute_metrics():
    metrics = gui_app._compute_metrics(
        [{"node_id": "n1", "status": "online", "last_seen": 10}],
        [{"action": "block"}],
    )
    assert metrics["online_nodes"] == 1
    assert metrics["counts"]["block"] == 1


def test_format_score_factors():
    text = gui_app._format_score_factors(
        {"score_factors": ["sensitive_port:3306", "public_remote_ip", "payload_present"]}
    )
    assert text == "sensitive_port:3306, public_remote_ip..."


def test_format_score_factors_explains_monitor_without_factors():
    text = gui_app._format_score_factors(
        {"action": "monitor", "reason": "score<0.75", "score_factors": []}
    )
    assert text == "below_threshold"


def test_format_command_result():
    assert gui_app._format_command_result({"result": {"extra_scan": True}}) == "extra_scan=True"
    assert gui_app._format_command_result({"error": "unknown command"}) == "unknown command"
    assert gui_app._format_command_result({}) == "-"


def test_format_risk_score():
    assert gui_app._format_risk_score(0.91234) == "0.912"
    assert gui_app._format_risk_score("-") == "-"
    assert gui_app._format_risk_score("high") == "high"


def test_format_timestamp_handles_iso_and_unavailable_values():
    assert gui_app._format_timestamp("2026-06-03T12:00:00+00:00") == "2026-06-03 12:00:00"
    assert gui_app._format_timestamp("2026-06-03T12:00:00") == "2026-06-03 12:00:00"
    assert gui_app._format_timestamp(0) == "-"
    assert gui_app._format_timestamp(None) == "-"
    assert gui_app._format_timestamp("") == "-"


def test_format_timestamp_handles_epoch_seconds_and_milliseconds():
    seconds = datetime(2026, 6, 3, 12, 0, 0).timestamp()
    expected = datetime.fromtimestamp(seconds).strftime("%Y-%m-%d %H:%M:%S")

    assert gui_app._format_timestamp(seconds) == expected
    assert gui_app._format_timestamp(int(seconds * 1000)) == expected


def test_scan_rows_from_telemetry_extracts_ports_sample():
    rows = gui_app._scan_rows_from_telemetry(
        [
            {
                "timestamp": _timestamp("2026-05-05", "12", "00", "00"),
                "event_type": "worker_telemetry",
                "node_id": "worker-1",
                "risk_score": 0.8,
                "score_factors": ["public_remote_ip"],
                "ports_sample": [
                    {
                        "program": "postgres",
                        "port": 5432,
                        "protocol": "TCP",
                        "status": "LISTEN",
                        "source_mode": "live",
                        "score": 0.91,
                        "score_factors": ["sensitive_port:5432"],
                        "ai_provider": "heuristic",
                    }
                ],
            }
        ]
    )

    assert rows == [
        {
            "timestamp": _timestamp("2026-05-05", "12", "00", "00"),
            "node_id": "worker-1",
            "program": "postgres",
            "port": 5432,
            "protocol": "TCP",
            "status": "LISTEN",
            "source_mode": "live",
            "score": 0.91,
            "score_factors": ["sensitive_port:5432"],
            "risk_explanation": "",
            "ai_provider": "heuristic",
        }
    ]


def test_expected_service_helpers():
    event = {
        "port": 3306,
        "protocol": "MySQL",
        "program": "mysqld",
    }
    service = gui_app._service_from_event(event)
    assert service == {
        "port": 3306,
        "protocol": "MySQL",
        "program": "mysqld",
        "reason": "dashboard allowlist",
    }
    settings = {"expected_services": []}
    assert gui_app._merge_expected_service(settings, service) is True
    assert gui_app._merge_expected_service(settings, service) is False
    assert gui_app._remove_expected_service(settings, service) is True
    assert settings["expected_services"] == []


def test_operator_help_text_defines_key_terms(tmp_path):
    text = gui_app._operator_help_text(
        tmp_path / "exports",
        {"plugin": "noop", "enforcement": "dry_run"},
    )
    assert "Start here:" in text
    assert "monitor: observed but not risky enough to act" in text
    assert "Signals: short explanations" in text
    assert "Scan Results: latest sampled ports" in text
    assert "Risk Overview: compact score" in text
    assert "Expected Services: move normal services" in text
    assert "Command Outcomes: whether queued commands" in text
    assert "Risk tab: detailed remediation feed" in text
    assert "Topology Edges: passive flow relationships" in text
    assert "Traffic Flows: bidirectional session summaries" in text
    assert "Firewall plugin: noop" in text
    assert "Enforcement mode: dry_run" in text
    assert "Tab shortcuts: 1 Dashboard, 2 Risk, 3 Exports, 4 Governance, 5 Deployment, 6 AI, 7 Packet" in text
    assert str(tmp_path / "exports") in text


def test_tui_tab_registry_and_shortcut_mapping_are_stable():
    tabs = gui_app.serialize_tui_tab_registry()
    labels = [tab["label"] for tab in tabs]
    shortcuts = gui_app.tui_tab_shortcut_mapping()

    assert labels == ["Dashboard", "Risk", "Exports", "Governance", "Deployment", "AI", "Packet"]
    assert shortcuts == {
        "1": "dashboard",
        "2": "risk",
        "3": "exports",
        "4": "governance",
        "5": "deployment",
        "6": "ai",
        "7": "packet",
    }
    assert tabs[0]["tab_id"] == gui_app.DEFAULT_TUI_TAB
    assert all(tab["preview_only"] is True for tab in tabs)
    assert all(tab["destructive_action"] is False for tab in tabs)


def test_dashboard_section_labels_keep_risk_details_on_risk_tab():
    labels = gui_app.dashboard_section_labels()

    assert labels[0] == "Start Here"
    assert "Risk Overview" in labels
    assert "Remediation Feed" not in labels
    assert "Risk Timeline" not in labels
    assert "Traffic Flows" in labels
    assert "Topology Edges" in labels


def test_placeholder_tabs_render_safe_labels_and_serialization():
    for tab_id in ["exports", "governance", "deployment", "ai", "packet"]:
        rendered = gui_app.render_placeholder_tab(tab_id)
        assert "This tab is a navigation placeholder." in rendered
        assert "No collectors, packet capture, network calls" in rendered

    assert "Risk and remediation readiness surface." in gui_app.render_placeholder_tab("risk")
    assert "Last Export Summary" in gui_app.render_placeholder_tab("exports")
    assert "Privacy Safeguards" in gui_app.render_placeholder_tab("governance")
    assert "Deployment wizard readiness" in gui_app.render_placeholder_tab("deployment")
    assert "Threat Prediction Models" in gui_app.render_placeholder_tab("ai")
    assert "Packet Intelligence Integration" in gui_app.render_placeholder_tab("packet")
    json.dumps(gui_app.serialize_tui_tab_registry(), sort_keys=True)


def test_risk_tab_text_is_live_read_only_not_placeholder_only():
    text = gui_app.build_risk_tab_text()

    assert "Risk Status" in text
    assert "Current:" in text
    assert "Monitor:" in text
    assert "Active Risk Findings" in text
    assert "Top Risk Signals" in text
    assert "Recent Remediation Feed" in text
    assert "Risk Timeline" in text
    assert "Footer Status" in text
    assert "Allowlist:" in text
    assert "Safety:" in text
    assert "This tab is a navigation placeholder." not in text
    assert "no enforcement" in text


def test_risk_workspace_sections_are_structured_for_layout():
    sections = gui_app.build_risk_workspace_sections()

    assert gui_app.risk_workspace_heading_labels() == (
        "Risk Status",
        "Active Risk Findings",
        "Top Risk Signals",
        "Recent Remediation Feed",
        "Risk Timeline",
        "Footer Status",
    )
    assert gui_app.risk_workspace_section_order() == (
        "risk_summary",
        "queue_summary",
        "active_findings",
        "top_signals",
        "remediation_feed",
        "risk_timeline",
        "allowlist_status",
        "safety_boundary",
    )
    assert set(sections) == set(gui_app.risk_workspace_section_order())
    assert sections["risk_summary"].startswith("Current:")
    assert sections["queue_summary"].startswith("Monitor:")
    assert sections["active_findings"].startswith("- No active risk findings available.")
    assert sections["top_signals"].startswith("- No risk signals available.")
    assert sections["remediation_feed"].startswith("- No remediation preview events yet.")
    assert sections["risk_timeline"].startswith("- No scored events yet.")
    assert sections["allowlist_status"].startswith("Observed:")
    assert sections["safety_boundary"].startswith("Read-only;")


def test_risk_workspace_uses_dashboard_style_dense_sections():
    css = gui_app.PortMapDashboard.CSS

    assert gui_app.risk_workspace_content_class() == "risk-section"
    assert gui_app.risk_workspace_layout_rows() == (
        "risk-top-row",
        "risk-active-row",
        "risk-bottom-row",
        "risk-footer-row",
    )
    assert "panel-heading" in css
    assert "risk-section" in css
    assert "risk-active-row" in css
    assert "risk-bottom-row" in css
    assert "risk-footer-row" in css
    assert "risk-panel" not in css
    assert "border:" not in css
    assert "VerticalScroll" not in Path(gui_app.__file__).read_text()
    assert "risk_allowlist_panel" not in Path(gui_app.__file__).read_text()
    assert "risk_safety_panel" not in Path(gui_app.__file__).read_text()


def test_risk_workspace_layout_supports_wide_and_narrow_rendering():
    remediation_events = [
        {
            "timestamp": "2026-06-14T12:00:00+00:00",
            "action": "prompt_operator",
            "enforcement": "dry_run",
            "score": 0.82,
            "reason": "score>=0.75 and review required",
            "score_factors": ["sensitive_port:22", "listening_socket"],
        }
    ]
    scan_results = [{"timestamp": "2026-06-14T12:05:00+00:00", "risk_score": 0.91}]
    timeline = [
        {
            "bucket_start": "2026-06-14T12:00:00+00:00",
            "event_count": 2,
            "average_score": 0.7,
            "max_score": 0.91,
            "actions": {"monitor": 1, "prompt_operator": 1, "block": 0},
        }
    ]

    wide = gui_app.render_risk_workspace_layout(
        remediation_events=remediation_events,
        scan_results=scan_results,
        risk_timeline=timeline,
        width=120,
    )
    narrow = gui_app.render_risk_workspace_layout(
        remediation_events=remediation_events,
        scan_results=scan_results,
        risk_timeline=timeline,
        width=72,
    )

    assert "Risk Status" in wide
    assert "Current:" in wide
    assert "Monitor:" in wide
    assert "Active Risk Findings" in wide
    assert "Risk Status" in narrow
    assert "Current:" in narrow
    assert "Monitor:" in narrow
    assert "Active Risk Findings" in narrow
    assert "Risk Status" in wide.splitlines()[0]
    assert "Risk Status" in narrow.splitlines()[0]
    assert "Time | Action | Score | Signal" in wide
    assert "Top Risk Signals" in wide
    assert " | Recent Remediation Feed" in wide
    assert " | Risk Timeline" in wide
    assert "Time | Avg | Max | N | Trend" in wide
    assert "Time | Avg" in narrow
    assert "Footer Status" in wide
    assert "Allowlist:" in wide
    assert "Safety:" in wide
    assert "Footer Status" in narrow


def test_active_risk_findings_formatter_handles_empty_and_populated_data():
    assert "No active risk findings available." in gui_app._format_active_risk_findings([], [])

    text = gui_app._format_active_risk_findings(
        [
            {
                "timestamp": "2026-06-14T12:00:00+00:00",
                "node_id": "worker-1",
                "action": "prompt_operator",
                "score": 0.82,
                "score_factors": ["sensitive_port:22", "listening_socket"],
            }
        ],
        [
            {
                "timestamp": "2026-06-14T12:05:00+00:00",
                "program": "ssh",
                "protocol": "tcp",
                "port": 22,
                "status": "LISTEN",
                "risk_score": 0.91,
                "score_factors": ["risky_port:22:SSH"],
            }
        ],
    )

    assert "Severity | Asset | Service | Finding | Score | Action" in text
    assert "HIGH" in text
    assert ".91" in text
    assert "22" in text
    assert "TCP" in text
    assert "worker-1" in text


def test_risk_severity_labels_are_score_only_presentation():
    assert gui_app._risk_severity_label(0.88) == "HIGH"
    assert gui_app._risk_severity_label(0.52) == "MED"
    assert gui_app._risk_severity_label(0.05) == "LOW"
    assert gui_app._risk_severity_label(0) == "INFO"
    assert gui_app._risk_severity_label(None) == "-"


def test_risk_summary_formatter_handles_populated_runtime_data():
    remediation_events = [
        {
            "timestamp": "2026-06-14T12:00:00+00:00",
            "action": "prompt_operator",
            "enforcement": "dry_run",
            "reason": "score>=0.75",
            "score": 0.81,
            "score_factors": ["sensitive_port:22", "listening_socket"],
            "ai_provider": "local_rules",
        },
        {
            "timestamp": "2026-06-14T12:05:00+00:00",
            "action": "monitor",
            "dry_run": True,
            "reason": "score<0.75",
            "risk_score": 0.2,
            "score_factors": ["unknown_service"],
            "anomaly_count": 1,
        },
    ]
    scan_results = [
        {
            "timestamp": "2026-06-14T12:06:00+00:00",
            "risk_score": 0.91,
            "score_factors": ["risky_port:22:SSH"],
            "ai_provider": "local_rules",
            "anomalies": ["new_service"],
        }
    ]

    summary = gui_app._format_risk_summary(remediation_events, scan_results)

    assert "Current:3" in summary
    assert "Latest:.91" in summary
    assert "Max:.91" in summary
    assert "Avg:.64" in summary
    assert "Anom:2" in summary
    assert "Providers:local_rules=2" in summary


def test_risk_summary_formatter_handles_empty_runtime_data():
    summary = gui_app._format_risk_summary([], [])

    assert "Current:0" in summary
    assert "Latest:-" in summary
    assert "Max:-" in summary
    assert "Avg:-" in summary
    assert "Updated:-" in summary
    assert "Providers:-" in summary


def test_dashboard_compact_risk_summary_renders_without_detailed_sections():
    text = gui_app._format_dashboard_risk_overview(
        [
            {
                "timestamp": "2026-06-14T12:00:00+00:00",
                "action": "prompt_operator",
                "score": 0.8,
            },
            {
                "timestamp": "2026-06-14T12:05:00+00:00",
                "action": "monitor",
                "risk_score": 0.2,
            },
        ],
        [{"timestamp": "2026-06-14T12:06:00+00:00", "risk_score": 0.91}],
    )

    assert "Risk Overview" in text
    assert "Latest score: 0.910" in text
    assert "Max score: 0.910" in text
    assert "Queues: monitor=1 review=1 block=0" in text
    assert "Details: press 2 for the Risk workspace." in text
    assert "Recent Remediation Feed" not in text
    assert "Risk Timeline" not in text


def test_queue_summary_counts_monitor_review_block_correctly():
    text = gui_app._format_queue_summary(
        [
            {"action": "monitor"},
            {"action": "prompt_operator"},
            {"action": "review"},
            {"action": "block"},
            {"action": "other"},
        ]
    )

    assert "Monitor:1" in text
    assert "Review:2" in text
    assert "Block:1" in text
    assert "Total:4" in text


def test_risk_signal_formatter_truncates_and_sanitizes_values():
    signal = gui_app._sanitize_risk_signal("signal\nwith\rprivate-looking-extra-details" * 3, limit=24)

    assert "\n" not in signal
    assert "\r" not in signal
    assert len(signal) <= 24
    assert signal.endswith("...")


def test_top_risk_signals_formatter_handles_empty_and_populated_data():
    assert "No risk signals available." in gui_app._format_top_risk_signals([], [])

    text = gui_app._format_top_risk_signals(
        [{"score_factors": ["sensitive_port:22", "listening_socket"]}],
        [{"score_factors": ["sensitive_port:22", "risky_port:22:SSH"]}],
    )

    assert "Signal | Count" in text
    assert "sensitive_port:22" in text
    assert "2" in text
    assert "listening_socket" in text
    assert "risky_port:22:SSH" in text


def test_remediation_feed_formatter_handles_empty_and_populated_data():
    assert "No remediation preview events yet." in gui_app._format_remediation_feed([])

    text = gui_app._format_remediation_feed(
        [
            {
                "timestamp": "2026-06-14T12:00:00+00:00",
                "action": "prompt_operator",
                "enforcement": "dry_run",
                "reason": "score>=0.75 and review required",
                "score": 0.82,
                "score_factors": ["sensitive_port:22", "listening_socket"],
            }
        ]
    )

    assert "Time | Action | Score | Signal" in text
    assert "prompt_oper..." in text
    assert ".82" in text
    assert "sensitive_port:22" in text
    assert "..." in text


def test_risk_timeline_formatter_handles_empty_and_populated_data():
    assert "No scored events yet." in gui_app._format_risk_timeline([])

    text = gui_app._format_risk_timeline(
        [
            {
                "bucket_start": "2026-06-14T12:00:00+00:00",
                "event_count": 3,
                "average_score": 0.64,
                "max_score": 0.91,
                "actions": {"monitor": 1, "prompt_operator": 1, "block": 0},
            },
            {
                "bucket_start": "2026-06-14T12:01:00+00:00",
                "event_count": 4,
                "average_score": 0.70,
                "max_score": 0.92,
                "actions": {"monitor": 2, "prompt_operator": 1, "block": 0},
            },
        ]
    )

    assert "Time | Avg | Max | N | Trend" in text
    assert "12:00 | .64" in text
    assert "12:01 | .70" in text
    assert "up" in text


def test_allowlist_status_formatter_handles_empty_and_populated_data():
    empty = gui_app._format_allowlist_status([], [])

    assert "Observed:0" in empty
    assert "Allowlisted:0" in empty
    assert "Selected:-" in empty

    text = gui_app._format_allowlist_status(
        [{"program": "ssh", "protocol": "tcp", "port": 22}],
        [{"program": "nginx", "protocol": "tcp", "port": 443}],
    )

    assert "Observed:1" in text
    assert "Allowlisted:1" in text
    assert "Selected:ssh tcp:22" in text
    assert "Status:candidate selected" in text


def test_allowlist_and_safety_footers_stay_short_for_one_screen_layout():
    allowlist = gui_app._format_allowlist_status(
        [{"program": "ssh", "protocol": "tcp", "port": 22}],
        [{"program": "nginx", "protocol": "tcp", "port": 443}],
    )
    safety = gui_app._format_safety_boundary()

    assert allowlist.splitlines()[0].startswith("Observed:")
    assert safety.splitlines()[0].startswith("Read-only;")
    assert len(allowlist.splitlines()) <= 1
    assert len(safety.splitlines()) <= 1
    assert "Read-only" in safety


def test_risk_one_screen_layout_formatter_enforces_row_limits():
    remediation_events = [
        {
            "timestamp": f"2026-06-14T12:{index:02d}:00+00:00",
            "node_id": f"worker-{index}",
            "action": "prompt_operator" if index % 2 else "monitor",
            "score": 0.5 + index / 100,
            "score_factors": [f"signal-{index}", "shared-signal"],
        }
        for index in range(9)
    ]
    scan_results = [
        {
            "timestamp": f"2026-06-14T13:{index:02d}:00+00:00",
            "program": "svc",
            "protocol": "tcp",
            "port": 8000 + index,
            "risk_score": 0.7 + index / 100,
            "score_factors": [f"scan-signal-{index}"],
        }
        for index in range(4)
    ]
    timeline = [
        {
            "bucket_start": f"2026-06-14T14:{index:02d}:00+00:00",
            "event_count": index,
            "average_score": 0.2,
            "max_score": 0.9,
            "actions": {"monitor": 1, "prompt_operator": 1, "block": 0},
        }
        for index in range(12)
    ]

    sections = gui_app.build_risk_workspace_sections(
        remediation_events=remediation_events,
        scan_results=scan_results,
        risk_timeline=timeline,
    )

    assert len(sections["active_findings"].splitlines()) == 13
    assert len(sections["remediation_feed"].splitlines()) == 10
    assert len(sections["top_signals"].splitlines()) == 10
    assert len(sections["risk_timeline"].splitlines()) == 10
    assert len(sections["allowlist_status"].splitlines()) <= 1
    assert len(sections["safety_boundary"].splitlines()) <= 1
    footer = gui_app._format_footer_status(sections["allowlist_status"], sections["safety_boundary"])
    status = gui_app._format_risk_status_strip(sections["risk_summary"], sections["queue_summary"])
    assert len(footer.splitlines()) == 1
    assert len(status.splitlines()) == 1
    assert "Allowlist:" in footer
    assert "Safety:" in footer


def test_tab_nav_and_bindings_expose_shortcuts():
    nav = gui_app.render_tab_nav("governance")
    binding_keys = [binding[0] for binding in gui_app.PortMapDashboard.BINDINGS]

    assert "[4 Governance]" in nav
    assert "1 Dashboard" in nav
    assert binding_keys[:7] == ["1", "2", "3", "4", "5", "6", "7"]
    assert "?" in binding_keys
    assert "e" in binding_keys


def test_dashboard_tab_is_default_and_switching_placeholders_does_not_crash():
    dashboard = gui_app.PortMapDashboard()

    assert dashboard.active_tab == gui_app.DEFAULT_TUI_TAB
    dashboard.action_tab_risk()
    assert dashboard.active_tab == "risk"
    dashboard.action_tab_exports()
    assert dashboard.active_tab == "exports"
    dashboard.action_tab_governance()
    assert dashboard.active_tab == "governance"
    dashboard.action_tab_packet()
    assert dashboard.active_tab == "packet"
    dashboard.action_tab_dashboard()
    assert dashboard.active_tab == gui_app.DEFAULT_TUI_TAB


def test_risk_tab_is_registered_and_selectable_with_shortcut_2():
    dashboard = gui_app.PortMapDashboard()

    assert gui_app.tui_tab_shortcut_mapping()["2"] == "risk"
    dashboard.action_tab_risk()
    assert dashboard.active_tab == "risk"


def test_resolve_firewall_status_defaults_safe():
    status = gui_app._resolve_firewall_status({})
    assert status == {"plugin": "noop", "enforcement": "dry_run"}


def test_resolve_firewall_status_detects_active_mode():
    status = gui_app._resolve_firewall_status({
        "firewall": {"plugin": "linux_iptables", "options": {"dry_run": False}}
    })
    assert status == {"plugin": "linux_iptables", "enforcement": "active"}


def test_load_nodes_no_state(monkeypatch, tmp_path):
    monkeypatch.setattr(gui_app, "ORCHESTRATOR_STATE", tmp_path / "state.json")
    monkeypatch.setattr(gui_app, "load_settings", lambda defaults=None: {})
    dashboard = gui_app.PortMapDashboard()
    assert dashboard._load_nodes() == []


def test_load_command_events(monkeypatch, tmp_path):
    path = tmp_path / "command_events.jsonl"
    path.write_text(
        "\n".join([
            json.dumps({"node_id": "n1", "command_type": "scan_now", "status": "received"}),
            "not json",
            json.dumps({"node_id": "n1", "command_type": "scan_now", "status": "applied"}),
        ])
    )
    monkeypatch.setattr(gui_app, "COMMAND_AUDIT_LOG", path)
    dashboard = gui_app.PortMapDashboard()
    events = dashboard._load_command_events(limit=3)
    assert [event["status"] for event in events] == ["received", "applied"]


def test_load_scan_results_prefers_worker_telemetry(monkeypatch, tmp_path):
    master_events = tmp_path / "master_events.log"
    master_events.write_text(
        json.dumps(
            {
                "event_type": "worker_telemetry",
                "timestamp": _timestamp("2026-05-05", "12", "00", "00"),
                "node_id": "worker-1",
                "ports_sample": [{"program": "nginx", "port": 443, "score": 0.4}],
            }
        )
    )
    monkeypatch.setattr(gui_app, "MASTER_EVENTS_LOG", master_events)

    dashboard = gui_app.PortMapDashboard()
    rows = dashboard._load_scan_results(
        [{"node_id": "worker-2", "program": "postgres", "port": 5432, "risk_score": 0.9}],
        limit=5,
    )

    assert rows[0]["node_id"] == "worker-1"
    assert rows[0]["program"] == "nginx"


def test_load_scan_results_falls_back_to_remediation_events(monkeypatch, tmp_path):
    monkeypatch.setattr(gui_app, "MASTER_EVENTS_LOG", tmp_path / "missing.log")
    dashboard = gui_app.PortMapDashboard()

    rows = dashboard._load_scan_results(
        [
            {
                "timestamp": _timestamp("2026-05-05", "12", "00", "00"),
                "node_id": "worker-2",
                "program": "postgres",
                "port": 5432,
                "protocol": "TCP",
                "risk_score": 0.9,
                "score_factors": ["sensitive_port:5432"],
            }
        ],
        limit=5,
    )

    assert rows[0]["node_id"] == "worker-2"
    assert rows[0]["score"] == 0.9
    assert rows[0]["score_factors"] == ["sensitive_port:5432"]


def test_visualization_builds_risk_timeline():
    timeline = visualization.build_risk_timeline(
        [
            {"timestamp": 10, "risk_score": 0.2, "action": "monitor"},
            {"timestamp": 20, "risk_score": 0.82, "action": "prompt_operator"},
            {"timestamp": 310, "risk_score": 0.95, "action": "block"},
            {"timestamp": _timestamp("2026-05-10", "12", "00", "00"), "risk_score": 0.51, "action": "monitor"},
        ],
        bucket_seconds=300,
    )

    assert len(timeline) == 3
    assert timeline[0]["event_count"] == 2
    assert timeline[0]["buckets"]["high"] == 1
    assert timeline[1]["buckets"]["critical"] == 1
    assert timeline[2]["buckets"]["medium"] == 1
    assert "L/M/H/C=1/0/1/0" in visualization.render_risk_timeline(timeline)


def test_visualization_builds_topology_and_flow_rows():
    report = visualization.build_flow_visualization(
        [
            {
                "timestamp": 1,
                "protocol": "TCP",
                "src_ip": "203.0.113.5",
                "src_port": 51515,
                "dst_ip": "203.0.113.10",
                "dst_port": 443,
                "payload_bytes": 120,
                "application_protocol": "https",
            }
        ]
    )

    edges = visualization.topology_edge_rows(report["topology"])
    flows = visualization.flow_rows(report["flows"])
    summary = visualization.visualization_summary(
        nodes=[{"node_id": "worker-1"}],
        risk_timeline=[],
        flows=report["flows"],
        topology=report["topology"],
    )

    assert edges[0]["src_ip"] == "203.0.113.5"
    assert edges[0]["application_protocols"] == "HTTPS"
    assert "203.0.113.5:51515 -> 203.0.113.10:443" == flows[0]["flow"]
    assert summary["flow_count"] == 1
    assert summary["raw_payload_stored"] is False
    assert summary["automatic_changes"] is False


def test_flow_visualization_uses_generated_at_when_event_timestamp_is_missing():
    generated_at = "2026-06-03T12:00:00+00:00"
    report = visualization.build_flow_visualization(
        [
            {
                "generated_at": generated_at,
                "protocol": "TCP",
                "src_ip": "203.0.113.5",
                "src_port": 51515,
                "dst_ip": "203.0.113.10",
                "dst_port": 443,
            }
        ]
    )

    rows = visualization.flow_rows(report["flows"])
    assert gui_app._format_timestamp(rows[0]["first_seen"]) == _local_display_from_iso(generated_at)
    assert gui_app._format_timestamp(rows[0]["last_seen"]) == _local_display_from_iso(generated_at)


def test_flow_visualization_does_not_render_epoch_for_missing_or_zero_timestamps():
    report = visualization.build_flow_visualization(
        [
            {
                "timestamp": 0,
                "protocol": "TCP",
                "src_ip": "203.0.113.5",
                "src_port": 51515,
                "dst_ip": "203.0.113.10",
                "dst_port": 443,
            },
            {
                "protocol": "TCP",
                "src_ip": "203.0.113.6",
                "src_port": 51516,
                "dst_ip": "203.0.113.11",
                "dst_port": 443,
            },
        ]
    )

    rendered = [
        gui_app._format_timestamp(value)
        for row in visualization.flow_rows(report["flows"])
        for value in (row["first_seen"], row["last_seen"])
    ]
    assert rendered
    assert all(value == "-" for value in rendered)
    assert not any(value.startswith(("1969-", "1970-")) for value in rendered)


def test_master_event_flow_rows_inherit_parent_timestamp():
    flow_events = gui_app._flow_events_from_master_events(
        [
            {
                "event_type": "worker_telemetry",
                "timestamp": "2026-06-03T12:00:00+00:00",
                "flows": [
                    {
                        "protocol": "TCP",
                        "src_ip": "203.0.113.5",
                        "src_port": 51515,
                        "dst_ip": "203.0.113.10",
                        "dst_port": 443,
                    }
                ],
            }
        ]
    )

    report = visualization.build_flow_visualization(flow_events)
    rows = visualization.flow_rows(report["flows"])
    assert flow_events[0]["generated_at"] == "2026-06-03T12:00:00+00:00"
    assert gui_app._format_timestamp(rows[0]["first_seen"]) == _local_display_from_iso("2026-06-03T12:00:00+00:00")
    assert gui_app._format_timestamp(rows[0]["last_seen"]) == _local_display_from_iso("2026-06-03T12:00:00+00:00")


def test_load_flow_visualization_reads_flow_events(monkeypatch, tmp_path):
    flow_log = tmp_path / "flow_events.jsonl"
    flow_log.write_text(
        json.dumps(
            {
                "timestamp": 1,
                "protocol": "TCP",
                "src_ip": "203.0.113.5",
                "src_port": 51515,
                "dst_ip": "203.0.113.10",
                "dst_port": 443,
                "payload_bytes": 120,
            }
        )
    )
    monkeypatch.setattr(gui_app, "FLOW_EVENTS_LOG", flow_log)
    monkeypatch.setattr(gui_app, "MASTER_EVENTS_LOG", tmp_path / "missing.log")

    dashboard = gui_app.PortMapDashboard()
    report = dashboard._load_flow_visualization(limit=5)

    assert report["flows"][0]["payload_bytes"] == 120
    assert report["topology"]["edges"][0]["packet_count"] == 1


def test_flow_events_from_master_events_extracts_nested_rows():
    rows = gui_app._flow_events_from_master_events(
        [
            {"event_type": "worker_telemetry", "flows": [{"src_ip": "203.0.113.1", "dst_ip": "203.0.113.2"}]},
            {"event_type": "traffic_flow", "src_ip": "203.0.113.3", "dst_ip": "203.0.113.4"},
        ]
    )

    assert [row["src_ip"] for row in rows] == ["203.0.113.1", "203.0.113.3"]


def test_load_orchestrator_health_reads_health_and_metrics(monkeypatch):
    dashboard = gui_app.PortMapDashboard()
    dashboard.orchestrator_url = "http://orchestrator"
    dashboard.orchestrator_token = "token"

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(self.payload).encode("utf-8")

    def fake_urlopen(req, timeout):
        assert req.headers["Authorization"] == "Bearer token"
        if req.full_url.endswith("/healthz"):
            return FakeResponse({"status": "ok"})
        if req.full_url.endswith("/metrics"):
            return FakeResponse({"registers": 1, "heartbeats": 2, "commands_queued": 3})
        raise AssertionError(req.full_url)

    monkeypatch.setattr(gui_app.request, "urlopen", fake_urlopen)

    health = dashboard._load_orchestrator_health()

    assert health == {
        "url": "http://orchestrator",
        "status": "ok",
        "metrics": {"registers": 1, "heartbeats": 2, "commands_queued": 3},
    }


def test_queue_command_posts_to_orchestrator(monkeypatch, tmp_path):
    monkeypatch.setattr(gui_app, "ORCHESTRATOR_STATE", tmp_path / "state.json")
    monkeypatch.setattr(gui_app, "REMEDIATION_LOG", tmp_path / "remediation.jsonl")

    monkeypatch.setattr(gui_app, "load_settings", lambda defaults=None: {})
    dashboard = gui_app.PortMapDashboard()
    dashboard.orchestrator_url = "http://orchestrator"
    dashboard.orchestrator_token = "token"

    calls = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout):
        calls["url"] = req.full_url
        calls["data"] = json.loads(req.data.decode("utf-8"))
        assert req.headers["Authorization"] == "Bearer token"
        return FakeResponse()

    monkeypatch.setattr(gui_app.request, "urlopen", fake_urlopen)

    dashboard._queue_command("node-1", {"type": "scan_now"})

    assert calls["url"].endswith("/commands")
    assert calls["data"]["node_id"] == "node-1"
