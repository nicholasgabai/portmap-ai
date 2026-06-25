import asyncio
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
    rendered = gui_app.render_placeholder_tab("unknown")
    assert "Unknown tab" in rendered
    assert "No readiness surface is registered" in rendered

    assert "Risk and remediation readiness surface." in gui_app.render_placeholder_tab("risk")
    assert "Last Export Summary" in gui_app.render_placeholder_tab("exports")
    json.dumps(gui_app.serialize_tui_tab_registry(), sort_keys=True)


def test_risk_tab_text_is_live_read_only_not_placeholder_only():
    text = gui_app.build_risk_tab_text()

    assert "Risk Status" in text
    assert "Current | Latest | Max | Avg | Updated | Provider | Monitor | Review | Block | Total | Mode" in text
    assert "Queue Status" not in text
    assert "Active Risk Findings" in text
    assert "Top Risk Signals" in text
    assert "Recent Remediation Feed" in text
    assert "Risk Timeline" in text
    assert "Allowlist:" in text
    assert "Safety:" in text
    assert "This tab is a navigation placeholder." not in text
    assert "no enforcement" in text


def test_risk_workspace_sections_are_structured_for_layout():
    sections = gui_app.build_risk_workspace_sections()

    assert gui_app.risk_workspace_heading_labels() == (
        "Risk Status",
        "Active Risk Findings",
        "Finding Details",
        "Top Risk Signals",
        "Recent Remediation Feed",
        "Risk Timeline",
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
        "risk-status-row",
        "risk-active-heading-row",
        "risk-active-table-row",
        "risk-support-tables-row",
        "risk-footer-status-row",
    )
    assert "panel-heading" in css
    assert "#risk-screen" in css
    assert "layout: grid;" in css
    assert "grid-size: 3 5;" in css
    assert "grid-columns: 2fr 5fr 3fr;" in css
    assert "grid-rows: 3 1 13fr 7fr 2;" in css
    assert "risk-section" in css
    assert "risk-active-row" not in css
    assert "risk-bottom-row" not in css
    assert "risk-top-row" not in css
    assert "risk-panel" not in css
    assert "border:" not in css
    source = Path(gui_app.__file__).read_text()
    compact_source = "".join(source.split())
    assert "VerticalScroll" not in source
    assert "withGrid(id=\"risk-screen\"):" in compact_source
    assert "risk_allowlist_panel" not in source
    assert "risk_safety_panel" not in source
    assert '_panel_heading("RiskStatus"' in compact_source
    assert '_panel_heading("QueueStatus"' not in compact_source
    assert '_panel_heading("ActiveRiskFindings"' in compact_source
    assert '_panel_heading("FindingDetails"' in compact_source
    assert '_panel_heading("TopRiskSignals"' in compact_source
    assert '_panel_heading("RecentRemediationFeed"' in compact_source
    assert '_panel_heading("RiskTimeline"' in compact_source


def test_risk_workspace_uses_dashboard_style_data_tables():
    assert issubclass(gui_app.RiskStatusTable, gui_app.DataTable)
    assert issubclass(gui_app.RiskActiveFindingsTable, gui_app.DataTable)
    assert issubclass(gui_app.FindingDetailsTable, gui_app.DataTable)
    assert issubclass(gui_app.RiskSignalsTable, gui_app.DataTable)
    assert issubclass(gui_app.RiskFeedTable, gui_app.DataTable)
    assert issubclass(gui_app.RiskTimelineTable, gui_app.DataTable)

    source = Path(gui_app.__file__).read_text()
    compact_source = "".join(source.split())
    assert "self.risk_status_panel=RiskStatusTable(" in compact_source
    assert "self.risk_active_findings_panel=RiskActiveFindingsTable(" in compact_source
    assert "self.risk_finding_details_panel=FindingDetailsTable(" in compact_source
    assert "self.risk_signals_panel=RiskSignalsTable(" in compact_source
    assert "self.risk_feed_panel=RiskFeedTable(" in compact_source
    assert "self.risk_workspace_timeline_panel=RiskTimelineTable(" in compact_source
    assert "self.risk_status_panel=Static(" not in compact_source
    assert "self.risk_queue_panel" not in compact_source
    assert "self.risk_active_findings_panel=Static(" not in compact_source
    assert "self.risk_finding_details_panel=Static(" not in compact_source


def test_exports_workspace_layout_mounts_correctly():
    assert gui_app.export_workspace_heading_labels() == (
        "Export Status",
        "Recent Exports",
        "Export Details",
        "Export Types",
        "Recent Export Events",
        "Validation Timeline",
    )
    assert gui_app.export_workspace_layout_rows() == (
        "export-status-row",
        "export-active-heading-row",
        "export-active-table-row",
        "export-support-tables-row",
    )
    assert gui_app.export_workspace_content_class() == "export-section"

    css = gui_app.PortMapDashboard.CSS
    assert "#exports-screen" in css
    assert "layout: grid;" in css
    assert "grid-size: 3 4;" in css
    assert "grid-columns: 2fr 5fr 3fr;" in css
    assert "grid-rows: 3 1 13fr 7fr;" in css
    assert "export-section" in css

    source = Path(gui_app.__file__).read_text()
    compact_source = "".join(source.split())
    assert "VerticalScroll" not in source
    assert "withGrid(id=\"exports-screen\"):" in compact_source
    assert '_panel_heading("ExportStatus"' in compact_source
    assert '_panel_heading("RecentExports"' in compact_source
    assert '_panel_heading("ExportDetails"' in compact_source
    assert '_panel_heading("ExportTypes"' in compact_source
    assert '_panel_heading("RecentExportEvents"' in compact_source
    assert '_panel_heading("ValidationTimeline"' in compact_source

    class Harness(gui_app.PortMapDashboard):
        def compose(self):
            yield from self._compose_exports_tab()

        async def on_mount(self):
            pass

    async def run_case():
        app = Harness()
        async with app.run_test():
            assert app.query_one("#exports-screen", gui_app.Grid)
            assert app.query_one(gui_app.ExportStatusTable)
            assert app.query_one(gui_app.ExportActivityTable)
            assert app.query_one(gui_app.ExportDetailsTable)
            assert app.query_one(gui_app.ExportTypesTable)
            assert app.query_one(gui_app.ExportEventsTable)
            assert app.query_one(gui_app.ExportValidationTimelineTable)

    asyncio.run(run_case())


def test_exports_workspace_uses_dashboard_style_data_tables():
    assert issubclass(gui_app.ExportStatusTable, gui_app.DataTable)
    assert issubclass(gui_app.ExportActivityTable, gui_app.DataTable)
    assert issubclass(gui_app.ExportDetailsTable, gui_app.DataTable)
    assert issubclass(gui_app.ExportTypesTable, gui_app.DataTable)
    assert issubclass(gui_app.ExportEventsTable, gui_app.DataTable)
    assert issubclass(gui_app.ExportValidationTimelineTable, gui_app.DataTable)

    source = Path(gui_app.__file__).read_text()
    compact_source = "".join(source.split())
    assert "self.exports_status_panel=ExportStatusTable(" in compact_source
    assert "self.export_activity_panel=ExportActivityTable(" in compact_source
    assert "self.export_details_panel=ExportDetailsTable(" in compact_source
    assert "self.export_types_panel=ExportTypesTable(" in compact_source
    assert "self.export_events_panel=ExportEventsTable(" in compact_source
    assert "self.export_validation_timeline_panel=ExportValidationTimelineTable(" in compact_source
    assert "self.export_activity_panel=Static(" not in compact_source
    assert "self.export_details_panel=Static(" not in compact_source


def _sample_export_rows():
    return [
        {
            "export_id": "portmap-logs-20260614-120300.zip",
            "timestamp": "2026-06-14 12:03:00",
            "export_type": "logs",
            "status": "available",
            "destination": "/tmp/exports",
            "files": "1",
            "size": "4.0 KB",
            "duration": "-",
            "started": "-",
            "completed": "2026-06-14 12:03:00",
            "validation_result": "valid",
            "key": "portmap-logs-20260614-120300.zip",
        },
        {
            "export_id": "topology-20260614-120200.zip",
            "timestamp": "2026-06-14 12:02:00",
            "export_type": "topology",
            "status": "available",
            "destination": "/tmp/exports",
            "files": "1",
            "size": "2.0 KB",
            "duration": "-",
            "started": "-",
            "completed": "2026-06-14 12:02:00",
            "validation_result": "valid",
            "key": "topology-20260614-120200.zip",
        },
        {
            "export_id": "reports-empty.zip",
            "timestamp": "2026-06-13 09:00:00",
            "export_type": "reports",
            "status": "empty",
            "destination": "/tmp/exports",
            "files": "1",
            "size": "0 B",
            "duration": "-",
            "started": "-",
            "completed": "2026-06-13 09:00:00",
            "validation_result": "empty",
            "key": "reports-empty.zip",
        },
    ]


def test_exports_status_strip_population():
    row = gui_app._export_status_table_row(_sample_export_rows(), Path("/tmp/exports"))

    assert row == {
        "last_export": "2026-06-14 12:03:00",
        "export_count": "3",
        "success_count": "2",
        "failure_count": "1",
        "destination": "/tmp/exports",
        "validation_state": "attention",
    }

    empty = gui_app._export_status_table_row([], Path("/tmp/exports"))
    assert empty["last_export"] == "-"
    assert empty["export_count"] == "0"
    assert empty["validation_state"] == "no_exports"


def test_exports_analytics_panels_population():
    rows = _sample_export_rows()

    assert gui_app._export_type_rows(rows) == [
        {"export_type": "logs", "count": "1"},
        {"export_type": "reports", "count": "1"},
        {"export_type": "topology", "count": "1"},
    ]

    events = gui_app._export_event_rows(rows, limit=2)
    assert [event["export_id"] if "export_id" in event else event["export_type"] for event in events] == [
        "topology",
        "logs",
    ]
    assert events[0]["time"] == "2026-06-14 12:02:00"
    assert events[1]["result"] == "valid"

    timeline = gui_app._export_validation_timeline_rows(rows)
    assert timeline == [
        {"time": "2026-06-14", "valid": "2", "failed": "0", "total": "2"},
        {"time": "2026-06-13", "valid": "0", "failed": "1", "total": "1"},
    ]


def test_export_rows_from_dir_reads_archive_metadata(tmp_path):
    archive = tmp_path / "portmap-logs-20260614-120300.zip"
    archive.write_bytes(b"export")

    rows = gui_app._export_rows_from_dir(tmp_path)

    assert len(rows) == 1
    assert rows[0]["export_id"] == archive.name
    assert rows[0]["export_type"] == "logs"
    assert rows[0]["status"] == "available"
    assert rows[0]["destination"] == str(tmp_path)
    assert rows[0]["files"] == "1"
    assert rows[0]["size"] == "6 B"
    assert rows[0]["validation_result"] == "valid"


def test_governance_workspace_layout_mounts_correctly():
    assert gui_app.governance_workspace_heading_labels() == (
        "Governance Status",
        "Governance Evidence",
        "Governance Details",
        "Evidence Categories",
        "Recent Governance Events",
        "Governance Timeline",
    )
    assert gui_app.governance_workspace_layout_rows() == (
        "governance-status-row",
        "governance-active-heading-row",
        "governance-active-table-row",
        "governance-support-tables-row",
    )
    assert gui_app.governance_workspace_content_class() == "governance-section"

    css = gui_app.PortMapDashboard.CSS
    assert "#governance-screen" in css
    assert "layout: grid;" in css
    assert "grid-size: 3 4;" in css
    assert "grid-columns: 2fr 5fr 3fr;" in css
    assert "grid-rows: 3 1 13fr 7fr;" in css
    assert "governance-section" in css

    source = Path(gui_app.__file__).read_text()
    compact_source = "".join(source.split())
    assert "VerticalScroll" not in source
    assert "withGrid(id=\"governance-screen\"):" in compact_source
    assert '_panel_heading("GovernanceStatus"' in compact_source
    assert '_panel_heading("GovernanceEvidence"' in compact_source
    assert '_panel_heading("GovernanceDetails"' in compact_source
    assert '_panel_heading("EvidenceCategories"' in compact_source
    assert '_panel_heading("RecentGovernanceEvents"' in compact_source
    assert '_panel_heading("GovernanceTimeline"' in compact_source

    class Harness(gui_app.PortMapDashboard):
        def compose(self):
            yield from self._compose_governance_tab()

        async def on_mount(self):
            pass

    async def run_case():
        app = Harness()
        async with app.run_test():
            assert app.query_one("#governance-screen", gui_app.Grid)
            assert app.query_one(gui_app.GovernanceStatusTable)
            assert app.query_one(gui_app.GovernanceEvidenceTable)
            assert app.query_one(gui_app.GovernanceDetailsTable)
            assert app.query_one(gui_app.GovernanceCategoriesTable)
            assert app.query_one(gui_app.GovernanceRecentEventsTable)
            assert app.query_one(gui_app.GovernanceTimelineTable)

    asyncio.run(run_case())


def test_governance_workspace_uses_dashboard_style_data_tables():
    assert issubclass(gui_app.GovernanceStatusTable, gui_app.DataTable)
    assert issubclass(gui_app.GovernanceEvidenceTable, gui_app.DataTable)
    assert issubclass(gui_app.GovernanceDetailsTable, gui_app.DataTable)
    assert issubclass(gui_app.GovernanceCategoriesTable, gui_app.DataTable)
    assert issubclass(gui_app.GovernanceRecentEventsTable, gui_app.DataTable)
    assert issubclass(gui_app.GovernanceTimelineTable, gui_app.DataTable)

    source = Path(gui_app.__file__).read_text()
    compact_source = "".join(source.split())
    assert "self.governance_status_panel=GovernanceStatusTable(" in compact_source
    assert "self.governance_evidence_panel=GovernanceEvidenceTable(" in compact_source
    assert "self.governance_details_panel=GovernanceDetailsTable(" in compact_source
    assert "self.governance_categories_panel=GovernanceCategoriesTable(" in compact_source
    assert "self.governance_recent_events_panel=GovernanceRecentEventsTable(" in compact_source
    assert "self.governance_timeline_panel=GovernanceTimelineTable(" in compact_source
    assert "self.governance_evidence_panel=Static(" not in compact_source
    assert "self.governance_details_panel=Static(" not in compact_source


def test_deployment_workspace_layout_mounts_correctly():
    assert gui_app.deployment_workspace_heading_labels() == (
        "Deployment Readiness Catalog",
        "Deployment Targets / Readiness Records",
        "Deployment Details",
        "Platform Types",
        "Recent Deployment Events",
        "Deployment Timeline",
    )
    assert gui_app.deployment_workspace_layout_rows() == (
        "deployment-status-row",
        "deployment-active-heading-row",
        "deployment-active-table-row",
        "deployment-support-tables-row",
    )
    assert gui_app.deployment_workspace_content_class() == "deployment-section"

    css = gui_app.PortMapDashboard.CSS
    assert "#deployment-screen" in css
    assert "layout: grid;" in css
    assert "grid-size: 3 4;" in css
    assert "grid-columns: 2fr 5fr 3fr;" in css
    assert "grid-rows: 3 1 13fr 7fr;" in css
    assert "deployment-section" in css

    source = Path(gui_app.__file__).read_text()
    compact_source = "".join(source.split())
    assert "VerticalScroll" not in source
    assert "withGrid(id=\"deployment-screen\"):" in compact_source
    assert '_panel_heading("DeploymentReadinessCatalog"' in compact_source
    assert "Metadata-onlyreadinesscatalog.Notaliveinstall/testresult." in compact_source
    assert '_panel_heading("DeploymentTargets/ReadinessRecords"' in compact_source
    assert "notproofoflocalvalidation" in compact_source
    assert '_panel_heading("DeploymentDetails"' in compact_source
    assert '_panel_heading("PlatformTypes"' in compact_source
    assert '_panel_heading("RecentDeploymentEvents"' in compact_source
    assert '_panel_heading("DeploymentTimeline"' in compact_source

    class Harness(gui_app.PortMapDashboard):
        def compose(self):
            yield from self._compose_deployment_tab()

        async def on_mount(self):
            pass

    async def run_case():
        app = Harness()
        async with app.run_test():
            assert app.query_one("#deployment-screen", gui_app.Grid)
            assert app.query_one(gui_app.DeploymentStatusTable)
            assert app.query_one(gui_app.DeploymentReadinessTable)
            assert app.query_one(gui_app.DeploymentDetailsTable)
            assert app.query_one(gui_app.DeploymentPlatformTypesTable)
            assert app.query_one(gui_app.DeploymentEventsTable)
            assert app.query_one(gui_app.DeploymentTimelineTable)

    asyncio.run(run_case())


def test_deployment_workspace_uses_dashboard_style_data_tables():
    assert issubclass(gui_app.DeploymentStatusTable, gui_app.DataTable)
    assert issubclass(gui_app.DeploymentReadinessTable, gui_app.DataTable)
    assert issubclass(gui_app.DeploymentDetailsTable, gui_app.DataTable)
    assert issubclass(gui_app.DeploymentPlatformTypesTable, gui_app.DataTable)
    assert issubclass(gui_app.DeploymentEventsTable, gui_app.DataTable)
    assert issubclass(gui_app.DeploymentTimelineTable, gui_app.DataTable)

    source = Path(gui_app.__file__).read_text()
    compact_source = "".join(source.split())
    assert "self.deployment_status_panel=DeploymentStatusTable(" in compact_source
    assert "self.deployment_readiness_panel=DeploymentReadinessTable(" in compact_source
    assert "self.deployment_details_panel=DeploymentDetailsTable(" in compact_source
    assert "self.deployment_platform_types_panel=DeploymentPlatformTypesTable(" in compact_source
    assert "self.deployment_events_panel=DeploymentEventsTable(" in compact_source
    assert "self.deployment_timeline_panel=DeploymentTimelineTable(" in compact_source
    assert "self.deployment_readiness_panel=Static(" not in compact_source
    assert "self.deployment_details_panel=Static(" not in compact_source


def _sample_deployment_rows():
    return [
        {
            "platform": "windows",
            "method": "powershell_preview",
            "status": "ready",
            "readiness": "ready",
            "warnings": "0",
            "blockers": "0",
            "updated": "2026-06-14 12:03:00",
            "required_steps": "operator_review",
            "warning_details": "-",
            "blocker_details": "-",
            "safety_mode": "preview",
            "notes": "metadata only",
            "scope": "metadata_only",
            "local_platform": "macos",
            "tested_locally": "unknown",
            "execution": "not performed",
            "preview_only": "True",
            "destructive_action": "False",
            "key": "windows|powershell_preview",
        },
        {
            "platform": "linux",
            "method": "deb_preview",
            "status": "warning",
            "readiness": "degraded",
            "warnings": "2",
            "blockers": "0",
            "updated": "2026-06-14 12:02:00",
            "required_steps": "operator_review, future_admin_if_operator_approved",
            "warning_details": "future admin context, signing missing",
            "blocker_details": "-",
            "safety_mode": "preview",
            "notes": "review package metadata",
            "scope": "metadata_only",
            "local_platform": "macos",
            "tested_locally": "unknown",
            "execution": "not performed",
            "preview_only": "True",
            "destructive_action": "False",
            "key": "linux|deb_preview",
        },
        {
            "platform": "container",
            "method": "compose_preview",
            "status": "blocker",
            "readiness": "blocked",
            "warnings": "1",
            "blockers": "1",
            "updated": "2026-06-13 09:00:00",
            "required_steps": "operator_review",
            "warning_details": "runtime review",
            "blocker_details": "runtime unavailable",
            "safety_mode": "preview",
            "notes": "no containers started",
            "scope": "metadata_only",
            "local_platform": "macos",
            "tested_locally": "unknown",
            "execution": "not performed",
            "preview_only": "True",
            "destructive_action": "False",
            "key": "container|compose_preview",
        },
    ]


def test_deployment_status_and_analytics_population():
    rows = _sample_deployment_rows()
    status = gui_app._deployment_status_table_row(rows)

    assert status == {
        "platforms": "3",
        "ready": "1",
        "warnings": "3",
        "blockers": "1",
        "last_updated": "2026-06-14 12:03:00",
        "mode": "read_only",
    }
    assert gui_app._deployment_platform_type_rows(rows) == [
        {"platform": "windows", "count": "1"},
        {"platform": "macos", "count": "0"},
        {"platform": "linux", "count": "1"},
        {"platform": "container", "count": "1"},
        {"platform": "updater", "count": "0"},
    ]

    events = gui_app._deployment_recent_event_rows(rows, limit=2)
    assert [event["method"] for event in events] == ["deb_preview", "powershell_preview"]
    assert gui_app._deployment_timeline_rows(rows) == [
        {"time": "2026-06-14", "ready": "1", "warnings": "2", "blockers": "0", "total": "2"},
        {"time": "2026-06-13", "ready": "0", "warnings": "1", "blockers": "1", "total": "1"},
    ]


def test_deployment_details_rows_use_selected_readiness_with_placeholders():
    rows = _sample_deployment_rows()
    details = dict(gui_app._deployment_detail_rows(rows[1]))

    assert details["Platform"] == "linux"
    assert details["Method"] == "deb_preview"
    assert details["Status"] == "warning"
    assert details["Readiness"] == "degraded"
    assert details["Scope"] == "metadata_only"
    assert details["Local Platform"] == "macos"
    assert details["Tested Locally"] == "unknown"
    assert details["Execution"] == "not performed"
    assert details["Required Steps"] == "operator_review, future_admin_if_operator_approved"
    assert details["Warnings"] == "future admin context, signing missing"
    assert details["Blockers"] == "-"
    assert details["Safety Mode"] == "preview"
    assert details["Notes"] == "review package metadata"

    placeholders = dict(gui_app._deployment_detail_rows(None))
    assert all(value == "-" for value in placeholders.values())


def test_default_deployment_rows_use_existing_preview_only_readiness_sources():
    rows = gui_app._build_default_deployment_readiness_rows(
        generated_at="2026-06-14T12:00:00+00:00",
        limit=24,
    )
    platforms = {row["platform"] for row in rows}

    assert {"windows", "macos", "linux", "container", "updater"}.issubset(platforms)
    assert rows
    assert all(row["safety_mode"] in {"dry_run", "preview", "read_only"} for row in rows)
    assert all(row["destructive_action"] == "False" for row in rows)
    assert all(row["scope"] == "metadata_only" for row in rows)
    assert all(row["tested_locally"] == "unknown" for row in rows)
    assert all(row["execution"] == "not performed" for row in rows)
    assert all(row["key"] for row in rows)


def test_deployment_workspace_semantics_do_not_imply_local_install_or_execution():
    rows = _sample_deployment_rows()
    details = dict(gui_app._deployment_detail_rows(rows[0]))

    assert details["Scope"] == "metadata_only"
    assert details["Tested Locally"] == "unknown"
    assert details["Execution"] == "not performed"

    source = Path(gui_app.__file__).read_text()
    assert "Deployment tab is read-only; Scan Now is a global orchestrator action." in source
    assert "Not a live install/test result." in source


def test_deployment_tables_handle_empty_readiness_data_without_crashing():
    class Harness(gui_app.App):
        def compose(self):
            self.status = gui_app.DeploymentStatusTable()
            self.readiness = gui_app.DeploymentReadinessTable()
            self.details = gui_app.DeploymentDetailsTable()
            self.platforms = gui_app.DeploymentPlatformTypesTable()
            self.events = gui_app.DeploymentEventsTable()
            self.timeline = gui_app.DeploymentTimelineTable()
            yield self.status
            yield self.readiness
            yield self.details
            yield self.platforms
            yield self.events
            yield self.timeline

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            app.status.update_status([])
            app.readiness.update_deployments([])
            app.details.update_details(app.readiness.selected_deployment())
            app.platforms.update_platforms([])
            app.events.update_events([])
            app.timeline.update_timeline([])
            await pilot.pause()
            assert app.readiness.row_count == 1
            assert app.readiness.selected_deployment() is None
            assert dict(app.details.get_row_at(index) for index in range(app.details.row_count))["Platform"] == "-"

    asyncio.run(run_case())


def test_ai_workspace_layout_mounts_correctly():
    assert gui_app.ai_workspace_heading_labels() == (
        "AI Summary",
        "AI Provider / Model",
        "AI Details",
        "Provider Summary",
        "Recent AI Activity",
        "AI Timeline",
    )
    assert gui_app.ai_workspace_layout_rows() == (
        "ai-status-row",
        "ai-active-heading-row",
        "ai-active-table-row",
        "ai-support-tables-row",
    )
    assert gui_app.ai_workspace_content_class() == "ai-section"

    css = gui_app.PortMapDashboard.CSS
    assert "#ai-screen" in css
    assert "layout: grid;" in css
    assert "grid-size: 3 4;" in css
    assert "grid-columns: 2fr 5fr 3fr;" in css
    assert "grid-rows: 3 1 13fr 7fr;" in css
    assert "ai-section" in css

    source = Path(gui_app.__file__).read_text()
    compact_source = "".join(source.split())
    assert "VerticalScroll" not in source
    assert "withGrid(id=\"ai-screen\"):" in compact_source
    assert '_panel_heading("AISummary"' in compact_source
    assert "noinferenceormodelloading" in compact_source
    assert '_panel_heading("AIProvider/Model"' in compact_source
    assert '_panel_heading("AIDetails"' in compact_source
    assert '_panel_heading("ProviderSummary"' in compact_source
    assert '_panel_heading("RecentAIActivity"' in compact_source
    assert '_panel_heading("AITimeline"' in compact_source

    class Harness(gui_app.PortMapDashboard):
        def compose(self):
            yield from self._compose_ai_tab()

        async def on_mount(self):
            pass

    async def run_case():
        app = Harness()
        async with app.run_test():
            assert app.query_one("#ai-screen", gui_app.Grid)
            assert app.query_one(gui_app.AIStatusTable)
            assert app.query_one(gui_app.AIProviderModelTable)
            assert app.query_one(gui_app.AIDetailsTable)
            assert app.query_one(gui_app.AIProviderSummaryTable)
            assert app.query_one(gui_app.AIActivityTable)
            assert app.query_one(gui_app.AITimelineTable)

    asyncio.run(run_case())


def test_ai_workspace_uses_dashboard_style_data_tables():
    assert issubclass(gui_app.AIStatusTable, gui_app.DataTable)
    assert issubclass(gui_app.AIProviderModelTable, gui_app.DataTable)
    assert issubclass(gui_app.AIDetailsTable, gui_app.DataTable)
    assert issubclass(gui_app.AIProviderSummaryTable, gui_app.DataTable)
    assert issubclass(gui_app.AIActivityTable, gui_app.DataTable)
    assert issubclass(gui_app.AITimelineTable, gui_app.DataTable)

    source = Path(gui_app.__file__).read_text()
    compact_source = "".join(source.split())
    assert "self.ai_status_panel=AIStatusTable(" in compact_source
    assert "self.ai_provider_model_panel=AIProviderModelTable(" in compact_source
    assert "self.ai_details_panel=AIDetailsTable(" in compact_source
    assert "self.ai_provider_summary_panel=AIProviderSummaryTable(" in compact_source
    assert "self.ai_activity_panel=AIActivityTable(" in compact_source
    assert "self.ai_timeline_panel=AITimelineTable(" in compact_source
    assert "self.ai_provider_model_panel=Static(" not in compact_source
    assert "self.ai_details_panel=Static(" not in compact_source


def _sample_ai_events():
    return gui_app._ai_events_from_sources(
        remediation_events=[
            {
                "timestamp": "2026-06-14T12:03:00+00:00",
                "ai_provider": "heuristic",
                "model": "risk-v1",
                "action": "prompt_operator",
                "status": "preview",
                "program": "nginx",
                "service_name": "https",
                "protocol": "tls",
                "port": 443,
                "score_factors": ["sensitive_port:443"],
            },
            {
                "timestamp": "2026-06-14T12:01:00+00:00",
                "ai_provider": "heuristic",
                "model": "risk-v1",
                "action": "monitor",
                "status": "preview",
                "program": "sshd",
                "service_name": "ssh",
                "protocol": "tcp",
                "port": 22,
            },
        ],
        scan_results=[
            {
                "timestamp": "2026-06-14T12:02:00+00:00",
                "ai_provider": "local_rules",
                "model_name": "port-score",
                "status": "LISTEN",
                "program": "postgres",
                "service_name": "postgresql",
                "protocol": "tcp",
                "port": 5432,
            }
        ],
        master_events=[
            {
                "timestamp": "2026-06-13T09:00:00+00:00",
                "event_type": "ai_decision",
                "provider": "heuristic",
                "model_name": "risk-v2",
                "decision": "review",
            }
        ],
    )


def test_ai_provider_model_rows_and_analytics_population():
    events = _sample_ai_events()
    rows = gui_app._ai_provider_model_rows(events)
    status = gui_app._ai_status_table_row(rows)

    assert status == {
        "providers": "2",
        "models": "3",
        "decisions": "4",
        "last_updated": "2026-06-14 12:03:00",
        "mode": "read_only",
    }
    assert rows[0]["provider"] == "heuristic"
    assert rows[0]["model"] == "risk-v1"
    assert rows[0]["decisions"] == "2"
    assert rows[0]["candidate_models"].startswith("nginx ")
    assert rows[0]["confidence"] != "-"
    assert rows[0]["evidence_count"] == "6"
    assert rows[0]["top_classification"] == "nginx"
    assert "https_service" in rows[0]["alternative_candidates"]
    assert "port:443" in rows[0]["evidence_signals"]
    assert "process_match" in rows[0]["calibration"]
    assert rows[0]["mode"] == "read_only"
    assert rows[0]["execution"] == "not performed"
    assert gui_app._ai_provider_summary_rows(rows) == [
        {"provider": "heuristic", "models": "2", "decisions": "3"},
        {"provider": "local_rules", "models": "1", "decisions": "1"},
    ]
    assert gui_app._ai_timeline_rows(events) == [
        {"time": "2026-06-14", "providers": "2", "decisions": "3", "events": "3"},
        {"time": "2026-06-13", "providers": "1", "decisions": "1", "events": "1"},
    ]
    assert [row["activity"] for row in gui_app._ai_recent_activity_rows(events, limit=2)] == [
        "LISTEN",
        "prompt_operator",
    ]


def test_ai_details_rows_use_selected_provider_model_with_placeholders():
    rows = gui_app._ai_provider_model_rows(_sample_ai_events())
    details = dict(gui_app._ai_detail_rows(rows[0]))

    assert details["Provider"] == "heuristic"
    assert details["Model"] == "risk-v1"
    assert details["Top Classification"] == "nginx"
    assert details["Confidence"] != "-"
    assert "https_service" in details["Alternative Candidates"]
    assert details["Evidence Count"] == "6"
    assert "port:443" in details["Evidence Signals"]
    assert "nginx:" in details["Candidate Reasoning"]
    assert "process:nginx" in details["Supporting Evidence"]
    assert "fingerprint" in details["Missing Evidence"]
    assert "Classified as nginx" in details["Explanation Summary"]
    assert details["Evidence Quality"] == "moderate"
    assert "moderate-low" in details["Confidence Rationale"]
    assert "Alternative candidates survived" in details["Ambiguity Reason"]
    assert "service fingerprint" in details["Missing Evidence Summary"]
    assert "expected-service allowlist" in details["Operator Next Steps"]
    assert details["Learning Profile ID"].startswith("learning-profile-")
    assert details["Learning Profile Name"] == "nginx"
    assert details["Learning Profile Observations"] == "1"
    assert details["Learning Profile Stability"] != "-"
    assert details["Historical Observations"] == "1"
    assert details["Profile Age"] == "0m"
    assert details["First Observed"] == "2026-06-14T12:03:00+00:00"
    assert details["Last Observed"] == "2026-06-14T12:03:00+00:00"
    assert details["Stability Score"] != "-"
    assert details["Stability Label"] == "unstable"
    assert details["Drift Score"] == "0.00"
    assert details["Drift Label"] == "none"
    assert details["Confidence Trend"] == "stable"
    assert details["Confidence Delta"] == "0.00"
    assert details["Confidence Average"] != "-"
    assert details["Confidence Min"] != "-"
    assert details["Confidence Max"] != "-"
    assert details["First Confidence"] != "-"
    assert details["Latest Confidence"] != "-"
    assert details["Recommendation Count"] != "-"
    assert details["Primary Recommendation"] == "verify_service_identity"
    assert "verify_service_identity" in details["Recommendation List"]
    assert int(details["Graph Nodes"]) >= 5
    assert int(details["Graph Edges"]) >= 4
    assert int(details["Graph Relationships"]) >= 4
    assert int(details["Inferred Relationships"]) > 0
    assert details["Strongest Relationship"].startswith("graph-rel-")
    assert details["Strongest Relationship Type"] != "-"
    assert details["Strongest Relationship Score"] != "-"
    assert int(details["Related Entities"]) > 0
    assert int(details["Graph Clusters"]) > 0
    assert details["Strongest Cluster"].startswith("graph-cluster-")
    assert details["Strongest Cluster Type"] != "-"
    assert details["Strongest Cluster Score"] != "-"
    assert details["Primary Cluster"].startswith("graph-cluster-")
    assert details["Primary Cluster Type"] != "-"
    assert details["Primary Cluster Risk"] in {"low", "medium", "high", "critical"}
    assert details["Primary Cluster Confidence"] != "-"
    assert details["Primary Cluster Reason"] != "-"
    assert details["Primary Cluster Trend"] in {"emerging", "growing", "shrinking", "stable", "dormant", "unknown"}
    assert details["Primary Cluster Age"] != "-"
    assert details["Primary Cluster Evolution Score"] != "-"
    assert details["Primary Cluster New Relationships"] != "-"
    assert details["Primary Cluster Lost Relationships"] != "-"
    assert details["Primary Cluster New Signals"] != "-"
    assert details["Primary Cluster Lost Signals"] != "-"
    assert details["Primary Cluster Evolution Summary"] != "-"
    assert details["Primary Cluster Trend Summary"] != "-"
    assert details["Graph Insight Count"] != "-"
    assert details["Strongest Graph Insight"].startswith("graph-insight-")
    assert details["Strongest Graph Insight Type"] != "-"
    assert details["Strongest Graph Insight Score"] != "-"
    assert details["Graph Insight Summary"] != "-"
    assert details["Graph Operator Next Steps"] != "-"
    assert details["Risk Evolution Direction"] in {
        "increasing",
        "decreasing",
        "stable",
        "fluctuating",
        "insufficient_history",
    }
    assert details["Risk Evolution Velocity"] in {"slow", "moderate", "rapid", "unknown"}
    assert details["Risk Evolution Confidence"] != "-"
    assert details["Risk Change Reasons"] != "-"
    assert details["Risk Evolution Summary"] != "-"
    assert details["Risk Operator Next Steps"] != "-"
    assert details["Related Asset"] == "-"
    assert details["Related Service"] == "https"
    assert details["Related Profile"].startswith("learning-profile-")
    assert details["Status"] == "preview"
    assert details["Decisions"] == "2"
    assert details["Updated"] == "2026-06-14 12:03:00"
    assert details["Mode"] == "read_only"
    assert details["Execution"] == "not performed"

    placeholders = dict(gui_app._ai_detail_rows(None))
    assert all(value == "-" for value in placeholders.values())


def test_wrapped_detail_rows_wrap_and_bound_long_metadata_values():
    long_value = "candidate-" + ("metadata " * 40) + "tail"
    rows = gui_app._wrapped_detail_rows([("Alternative Candidates", long_value)], width=32, max_lines=3)

    assert len(rows) == 3
    assert rows[0][0] == "Alternative Candidates"
    assert rows[1][0] == ""
    assert rows[2][0] == ""
    assert rows[2][1].endswith("...")
    assert rows[0][2] == "Alternative Candidates"
    assert rows[1][2] == "Alternative Candidates#1"


def test_wrapped_detail_rows_break_long_tokens_without_wrapping_short_values():
    long_token = "learning-profile-" + ("abcdef" * 12)
    rows = gui_app._wrapped_detail_rows(
        [
            ("Status", "preview"),
            ("Learning Profile ID", long_token),
        ],
        width=24,
        max_lines=4,
    )

    assert rows[0] == ("Status", "preview", "Status")
    assert rows[1][0] == "Learning Profile ID"
    assert rows[2][0] == ""
    assert all(len(row[1]) <= 24 for row in rows)


def test_ai_details_table_wraps_long_metadata_and_preserves_cursor_selection():
    class Harness(gui_app.App):
        def compose(self):
            self.details = gui_app.AIDetailsTable()
            yield self.details

    long_value = "nginx 0.42, " + ("shared_tls_metadata " * 4) + "apache 0.31, caddy 0.18"
    ai_row = {
        "provider": "heuristic",
        "model": "risk-v1",
        "alternative_candidates": long_value,
        "candidate_reasoning": "nginx: " + ("process and service metadata " * 5),
        "supporting_evidence": "nginx: process:nginx, service:https, port:443, protocol:tls",
        "missing_evidence": "nginx: fingerprint, historical confirmation, expected service review",
        "operator_next_steps": "Review service name, process owner, expected-service allowlist, and historical observations.",
        "learning_profile_id": "learning-profile-" + ("abcdef" * 8),
    }

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            details = app.query_one(gui_app.AIDetailsTable)
            details.update_details(ai_row)
            await pilot.pause()
            rendered = [details.get_row_at(index) for index in range(details.row_count)]
            assert any(row[0] == "Alternative Candidates" for row in rendered)
            assert any(row[0] == "" and "apache" in row[1] for row in rendered)
            assert any(row[0] == "Learning Profile ID" for row in rendered)

            continuation_index = next(index for index, row in enumerate(rendered) if row[0] == "")
            details.move_cursor(row=continuation_index, column=0)
            details.update_details(ai_row)
            await pilot.pause()
            assert details.cursor_row == continuation_index
            assert details.get_row_at(details.cursor_row)[0] == ""

    asyncio.run(run_case())


def test_ai_details_table_preserves_scroll_and_highlighted_wrapped_row_on_refresh():
    class Harness(gui_app.App):
        def compose(self):
            self.details = gui_app.AIDetailsTable()
            self.details.styles.height = 6
            yield self.details

    ai_row = {
        "provider": "heuristic",
        "model": "risk-v1",
        "alternative_candidates": "nginx 0.42, " + ("shared_tls_metadata " * 6) + "apache 0.31, caddy 0.18",
        "candidate_reasoning": "nginx: " + ("process and service metadata " * 6),
        "operator_next_steps": "Review service name, process owner, expected-service allowlist, and historical observations.",
        "learning_profile_id": "learning-profile-" + ("abcdef" * 8),
    }

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            details = app.query_one(gui_app.AIDetailsTable)
            details.update_details(ai_row)
            await pilot.pause()
            rendered = [details.get_row_at(index) for index in range(details.row_count)]
            continuation_index = next(index for index, row in enumerate(rendered) if row[0] == "")
            details.move_cursor(row=continuation_index, column=0)
            details.scroll_to(y=max(continuation_index - 1, 0), animate=False)
            await pilot.pause()
            previous_scroll = details.scroll_y
            previous_first_visible = gui_app._table_row_key_at(details, previous_scroll)
            previous_selected = gui_app._table_row_key_at(details, details.cursor_row)

            details.update_details(ai_row)
            await pilot.pause()
            await pilot.pause()

            assert details.cursor_row == continuation_index
            assert details.get_row_at(details.cursor_row)[0] == ""
            assert gui_app._table_row_key_at(details, details.cursor_row) == previous_selected
            assert gui_app._table_row_key_at(details, details.scroll_y) == previous_first_visible
            assert details.scroll_y == previous_scroll
            assert details.scroll_y > 0
            assert details.scroll_y <= details.cursor_row <= details.scroll_y + max(int(details.size.height), 1)

    asyncio.run(run_case())


def test_ai_details_table_falls_back_to_nearest_row_when_wrapped_key_disappears():
    class Harness(gui_app.App):
        def compose(self):
            self.details = gui_app.AIDetailsTable()
            self.details.styles.height = 6
            yield self.details

    initial = {
        "provider": "heuristic",
        "model": "risk-v1",
        "alternative_candidates": "nginx 0.42, " + ("shared_tls_metadata " * 6) + "apache 0.31, caddy 0.18",
        "operator_next_steps": "Review service name, process owner, expected-service allowlist, and historical observations.",
    }
    updated = {
        "provider": "heuristic",
        "model": "risk-v1",
        "alternative_candidates": "nginx 0.42",
        "operator_next_steps": "Review service name.",
    }

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            details = app.query_one(gui_app.AIDetailsTable)
            details.update_details(initial)
            await pilot.pause()
            rendered = [details.get_row_at(index) for index in range(details.row_count)]
            old_index = next(index for index, row in enumerate(rendered) if row[0] == "")
            details.move_cursor(row=old_index, column=0)
            details.scroll_to(y=old_index, animate=False)
            await pilot.pause()
            previous_scroll = details.scroll_y

            details.update_details(updated)
            await pilot.pause()

            assert details.cursor_row == min(old_index, details.row_count - 1)
            assert details.scroll_y == min(previous_scroll, details.max_scroll_y)
            assert details.cursor_row > 0

    asyncio.run(run_case())


def test_ai_details_table_prevents_horizontal_overflow_for_long_values():
    class Harness(gui_app.App):
        def compose(self):
            self.details = gui_app.AIDetailsTable()
            self.details.styles.width = 52
            self.details.styles.height = 8
            yield self.details

    ai_row = {
        "provider": "heuristic",
        "model": "risk-v1",
        "candidate_reasoning": "nginx:" + ("process_service_fingerprint_without_spaces" * 4),
        "supporting_evidence": "nginx:" + ("service-process-fingerprint-support-token" * 4),
        "missing_evidence": "nginx:" + ("missing-fingerprint-confirmation-token" * 4),
        "recommendation_list": "review_profile_drift:" + ("metadata-drift-with-long-token" * 5),
        "strongest_relationship": "graph-rel-shared_application_candidate-" + ("abcdef1234567890" * 4),
        "strongest_cluster": "graph-cluster-application-" + ("abcdef1234567890" * 4),
        "primary_cluster_reason": "critical_risk_from_profile_drift:" + ("cluster-analysis-token" * 5),
        "primary_cluster_evolution_summary": "application_cluster:growing;" + ("relationship-signal-delta-token" * 4),
        "primary_cluster_trend_summary": "trend:growing;" + ("temporal-evolution-token" * 5),
        "graph_insight_summary": "emerging_risk_cluster:1.00;" + ("insight-summary-token" * 5),
        "graph_operator_next_steps": "Review related cluster recent signals expected behavior " + ("operator-step-token" * 5),
        "risk_change_reasons": "risk_score_increase:0.42;" + ("risk-change-reason-token" * 5),
        "risk_evolution_summary": "direction:increasing;velocity:rapid;" + ("risk-evolution-summary-token" * 5),
        "risk_operator_next_steps": "Review new signals relationships and cluster changes " + ("risk-next-step-token" * 5),
        "learning_profile_id": "learning-profile-" + ("abcdef1234567890" * 4),
    }

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            details = app.query_one(gui_app.AIDetailsTable)
            details.update_details(ai_row)
            await pilot.pause()
            target_width = gui_app._detail_value_wrap_width(details, gui_app._ai_detail_rows(ai_row))
            rendered = [details.get_row_at(index) for index in range(details.row_count)]
            continuation_index = next(index for index, row in enumerate(rendered) if row[0] == "")
            details.move_cursor(row=continuation_index, column=0)
            details.scroll_to(y=max(continuation_index - 1, 0), animate=False)
            await pilot.pause()
            previous_scroll = details.scroll_y
            previous_selected = gui_app._table_row_key_at(details, details.cursor_row)

            assert target_width < gui_app.DETAIL_WRAP_WIDTH
            assert details.columns.get("value").width == target_width
            assert details.allow_horizontal_scroll is False
            assert all(len(row[1]) <= target_width for row in rendered)
            assert any(row[0] == "Candidate Reasoning" for row in rendered)
            assert any(row[0] == "Supporting Evidence" for row in rendered)
            assert any(row[0] == "Missing Evidence" for row in rendered)
            assert any(row[0] == "Recommendation List" for row in rendered)
            assert any(row[0] == "Strongest Relationship" for row in rendered)
            assert any(row[0] == "Strongest Cluster" for row in rendered)
            assert any(row[0] == "Primary Cluster Reason" for row in rendered)
            assert any(row[0] == "Primary Cluster Evolution Summary" for row in rendered)
            assert any(row[0] == "Primary Cluster Trend Summary" for row in rendered)
            assert any(row[0] == "Graph Insight Summary" for row in rendered)
            assert any(row[0] == "Graph Operator Next Steps" for row in rendered)
            assert any(row[0] == "Risk Change Reasons" for row in rendered)
            assert any(row[0] == "Risk Evolution Summary" for row in rendered)
            assert any(row[0] == "Risk Operator Next Steps" for row in rendered)
            assert any(row[0] == "Learning Profile ID" for row in rendered)
            assert any(row[0] == "" for row in rendered)

            details.update_details(ai_row)
            await pilot.pause()
            refreshed = [details.get_row_at(index) for index in range(details.row_count)]
            assert details.allow_horizontal_scroll is False
            assert all(len(row[1]) <= target_width for row in refreshed)
            assert gui_app._table_row_key_at(details, details.cursor_row) == previous_selected
            assert details.scroll_y == previous_scroll

    asyncio.run(run_case())


def test_ai_tables_handle_empty_metadata_without_crashing():
    class Harness(gui_app.App):
        def compose(self):
            self.status = gui_app.AIStatusTable()
            self.providers = gui_app.AIProviderModelTable()
            self.details = gui_app.AIDetailsTable()
            self.summary = gui_app.AIProviderSummaryTable()
            self.activity = gui_app.AIActivityTable()
            self.timeline = gui_app.AITimelineTable()
            yield self.status
            yield self.providers
            yield self.details
            yield self.summary
            yield self.activity
            yield self.timeline

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            app.status.update_status([])
            app.providers.update_ai([])
            app.details.update_details(app.providers.selected_ai())
            app.summary.update_providers([])
            app.activity.update_activity([])
            app.timeline.update_timeline([])
            await pilot.pause()
            assert app.providers.row_count == 1
            assert app.providers.selected_ai() is None
            assert dict(app.details.get_row_at(index) for index in range(app.details.row_count))["Provider"] == "-"

    asyncio.run(run_case())


def test_ai_table_and_timeline_populate_from_existing_ai_data():
    class Harness(gui_app.App):
        def compose(self):
            self.providers = gui_app.AIProviderModelTable()
            self.timeline = gui_app.AITimelineTable()
            yield self.providers
            yield self.timeline

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            events = _sample_ai_events()
            rows = gui_app._ai_provider_model_rows(events)
            app.providers.update_ai(rows)
            app.timeline.update_timeline(events)
            await pilot.pause()
            assert app.providers.row_count == 3
            assert app.providers.get_row_at(0)[0] == "heuristic"
            assert app.providers.get_row_at(0)[1] == "risk-v1"
            assert "nginx" in app.providers.get_row_at(0)[2]
            assert app.providers.get_row_at(0)[3] != "-"
            assert app.providers.get_row_at(0)[4] == "6"
            assert app.timeline.row_count == 2
            assert app.timeline.get_row_at(0)[0] == "2026-06-14"

    asyncio.run(run_case())


def test_packet_workspace_layout_mounts_correctly():
    assert gui_app.packet_workspace_heading_labels() == (
        "Packet Summary",
        "Packet Activity",
        "Packet Details",
        "Packet Summary",
        "Recent Packet Activity",
        "Packet Timeline",
    )
    assert gui_app.packet_workspace_layout_rows() == (
        "packet-status-row",
        "packet-active-heading-row",
        "packet-active-table-row",
        "packet-support-tables-row",
    )
    assert gui_app.packet_workspace_content_class() == "packet-section"

    css = gui_app.PortMapDashboard.CSS
    assert "#packet-screen" in css
    assert "layout: grid;" in css
    assert "grid-size: 3 4;" in css
    assert "grid-columns: 2fr 5fr 3fr;" in css
    assert "grid-rows: 3 1 13fr 7fr;" in css
    assert "packet-section" in css

    source = Path(gui_app.__file__).read_text()
    compact_source = "".join(source.split())
    assert "VerticalScroll" not in source
    assert "withGrid(id=\"packet-screen\"):" in compact_source
    assert '_panel_heading("PacketSummary"' in compact_source
    assert "nocaptureorinspection" in compact_source
    assert '_panel_heading("PacketActivity"' in compact_source
    assert "nopacketcapture,decoding,orpayloadhandling" in compact_source
    assert '_panel_heading("PacketDetails"' in compact_source
    assert '_panel_heading("RecentPacketActivity"' in compact_source
    assert '_panel_heading("PacketTimeline"' in compact_source

    class Harness(gui_app.PortMapDashboard):
        def compose(self):
            yield from self._compose_packet_tab()

        async def on_mount(self):
            pass

    async def run_case():
        app = Harness()
        async with app.run_test():
            assert app.query_one("#packet-screen", gui_app.Grid)
            assert app.query_one(gui_app.PacketStatusTable)
            assert app.query_one(gui_app.PacketActivityTable)
            assert app.query_one(gui_app.PacketDetailsTable)
            assert app.query_one(gui_app.PacketSummaryTable)
            assert app.query_one(gui_app.PacketRecentActivityTable)
            assert app.query_one(gui_app.PacketTimelineTable)

    asyncio.run(run_case())


def test_packet_workspace_uses_dashboard_style_data_tables():
    assert issubclass(gui_app.PacketStatusTable, gui_app.DataTable)
    assert issubclass(gui_app.PacketActivityTable, gui_app.DataTable)
    assert issubclass(gui_app.PacketDetailsTable, gui_app.DataTable)
    assert issubclass(gui_app.PacketSummaryTable, gui_app.DataTable)
    assert issubclass(gui_app.PacketRecentActivityTable, gui_app.DataTable)
    assert issubclass(gui_app.PacketTimelineTable, gui_app.DataTable)

    source = Path(gui_app.__file__).read_text()
    compact_source = "".join(source.split())
    assert "self.packet_status_panel=PacketStatusTable(" in compact_source
    assert "self.packet_activity_panel=PacketActivityTable(" in compact_source
    assert "self.packet_details_panel=PacketDetailsTable(" in compact_source
    assert "self.packet_summary_panel=PacketSummaryTable(" in compact_source
    assert "self.packet_recent_activity_panel=PacketRecentActivityTable(" in compact_source
    assert "self.packet_timeline_panel=PacketTimelineTable(" in compact_source
    assert "self.packet_activity_panel=Static(" not in compact_source
    assert "self.packet_details_panel=Static(" not in compact_source


def _sample_packet_flows():
    return [
        {
            "flow_id": "flow-1",
            "initiator": {"ip": "203.0.113.5", "port": 51515},
            "responder": {"ip": "203.0.113.10", "port": 443},
            "first_seen": "2026-06-14T12:00:00+00:00",
            "last_seen": "2026-06-14T12:03:00+00:00",
            "packet_count": 3,
            "payload_bytes": 420,
            "transports": ["TCP"],
            "application_protocols": ["TLS"],
            "findings": [],
        },
        {
            "flow_id": "flow-2",
            "initiator": {"ip": "203.0.113.20", "port": 53000},
            "responder": {"ip": "203.0.113.53", "port": 53},
            "first_seen": "2026-06-14T12:01:00+00:00",
            "last_seen": "2026-06-14T12:02:00+00:00",
            "packet_count": 2,
            "payload_bytes": 120,
            "transports": ["UDP"],
            "application_protocols": ["DNS"],
            "findings": ["dns_metadata"],
        },
        {
            "flow_id": "flow-3",
            "initiator": {"ip": "203.0.113.30", "port": 50000},
            "responder": {"ip": "203.0.113.1", "port": 22},
            "first_seen": "2026-06-13T09:00:00+00:00",
            "last_seen": "2026-06-13T09:01:00+00:00",
            "packet_count": 1,
            "payload_bytes": 80,
            "transports": ["TCP"],
            "application_protocols": ["SSH"],
            "findings": [],
        },
    ]


def test_packet_activity_rows_and_analytics_population():
    rows = gui_app._packet_activity_rows(_sample_packet_flows())
    status = gui_app._packet_status_table_row(rows)

    assert status == {
        "packets": "6",
        "flows": "3",
        "protocols": "2",
        "updated": "2026-06-14 12:03:00",
        "mode": "read_only",
    }
    assert rows[0]["flow"] == "203.0.113.5:51515 -> 203.0.113.10:443"
    assert rows[0]["transport"] == "TCP"
    assert rows[0]["packets"] == "3"
    assert rows[0]["mode"] == "read_only"
    assert rows[0]["execution"] == "not performed"
    assert gui_app._packet_summary_rows(rows) == [
        {"protocol": "TCP", "flows": "2", "packets": "4", "bytes": "500"},
        {"protocol": "UDP", "flows": "1", "packets": "2", "bytes": "120"},
    ]
    assert gui_app._packet_timeline_rows(rows) == [
        {"time": "2026-06-14", "flows": "2", "packets": "5", "bytes": "540"},
        {"time": "2026-06-13", "flows": "1", "packets": "1", "bytes": "80"},
    ]
    assert [row["status"] for row in gui_app._packet_recent_activity_rows(rows, limit=2)] == [
        "dns_metadata",
        "observed",
    ]


def test_packet_details_rows_use_selected_activity_with_placeholders():
    rows = gui_app._packet_activity_rows(_sample_packet_flows())
    details = dict(gui_app._packet_detail_rows(rows[0]))

    assert details["Flow"] == "203.0.113.5:51515 -> 203.0.113.10:443"
    assert details["Transport"] == "TCP"
    assert details["Packets"] == "3"
    assert details["Bytes"] == "420"
    assert details["First Seen"] == "2026-06-14 12:00:00"
    assert details["Last Seen"] == "2026-06-14 12:03:00"
    assert details["Source"] == "flow_metadata"
    assert details["Mode"] == "read_only"
    assert details["Execution"] == "not performed"

    placeholders = dict(gui_app._packet_detail_rows(None))
    assert all(value == "-" for value in placeholders.values())


def test_packet_tables_handle_empty_metadata_without_crashing():
    class Harness(gui_app.App):
        def compose(self):
            self.status = gui_app.PacketStatusTable()
            self.activity = gui_app.PacketActivityTable()
            self.details = gui_app.PacketDetailsTable()
            self.summary = gui_app.PacketSummaryTable()
            self.recent = gui_app.PacketRecentActivityTable()
            self.timeline = gui_app.PacketTimelineTable()
            yield self.status
            yield self.activity
            yield self.details
            yield self.summary
            yield self.recent
            yield self.timeline

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            app.status.update_status([])
            app.activity.update_packets([])
            app.details.update_details(app.activity.selected_packet())
            app.summary.update_summary([])
            app.recent.update_activity([])
            app.timeline.update_timeline([])
            await pilot.pause()
            assert app.activity.row_count == 1
            assert app.activity.selected_packet() is None
            assert dict(app.details.get_row_at(index) for index in range(app.details.row_count))["Flow"] == "-"

    asyncio.run(run_case())


def test_packet_table_and_timeline_populate_from_existing_flow_data():
    class Harness(gui_app.App):
        def compose(self):
            self.activity = gui_app.PacketActivityTable()
            self.timeline = gui_app.PacketTimelineTable()
            yield self.activity
            yield self.timeline

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            rows = gui_app._packet_activity_rows(_sample_packet_flows())
            app.activity.update_packets(rows)
            app.timeline.update_timeline(rows)
            await pilot.pause()
            assert app.activity.row_count == 3
            assert app.activity.get_row_at(0)[1] == "203.0.113.5:51515 -> 203.0.113.10:443"
            assert app.timeline.row_count == 2
            assert app.timeline.get_row_at(0)[0] == "2026-06-14"

    asyncio.run(run_case())


def _sample_governance_rows():
    return gui_app._governance_rows_from_sources(
        audit_events=[
            {
                "created_at": "2026-06-14T12:03:00+00:00",
                "event_type": "export_created",
                "event_category": "export",
                "event_state": "recorded",
                "actor_reference": "operator",
                "action_reference": "export_logs",
                "target_reference": "portmap-logs.zip",
                "source_mode": "live",
                "evidence_references": ["archive"],
            },
            {
                "created_at": "2026-06-14T12:01:00+00:00",
                "event_type": "policy_review",
                "event_category": "policy_review",
                "event_state": "degraded",
                "actor_reference": "reviewer",
                "target_reference": "policy-1",
                "source_mode": "fixture",
            },
        ],
        command_events=[
            {
                "timestamp": "2026-06-14T12:02:00+00:00",
                "node_id": "worker-1",
                "command_type": "scan_now",
                "status": "applied",
            }
        ],
        remediation_events=[
            {
                "timestamp": "2026-06-14T12:00:00+00:00",
                "node_id": "worker-2",
                "action": "prompt_operator",
                "status": "preview",
                "port": 22,
            }
        ],
        export_rows=[
            {
                "export_id": "portmap-logs-20260614-120400.zip",
                "timestamp": "2026-06-14 12:04:00",
                "export_type": "logs",
                "validation_result": "valid",
            }
        ],
    )


def test_governance_status_and_analytics_population():
    rows = _sample_governance_rows()
    status = gui_app._governance_status_table_row(rows)

    assert status == {
        "latest": "2026-06-14 12:04:00",
        "evidence_count": "5",
        "preview_count": "5",
        "exception_count": "1",
        "category_count": "4",
        "readiness": "attention",
    }
    assert gui_app._governance_category_rows(rows) == [
        {"category": "export", "count": "2"},
        {"category": "operator_action", "count": "1"},
        {"category": "policy_review", "count": "1"},
        {"category": "remediation_preview", "count": "1"},
    ]
    recent = gui_app._governance_recent_event_rows(rows, limit=2)
    assert [row["event_type"] for row in recent] == ["export_created", "export_available"]
    assert gui_app._governance_timeline_rows(rows) == [
        {"time": "2026-06-14", "events": "5", "exceptions": "1", "preview": "5"}
    ]


def test_governance_details_rows_use_selected_evidence_with_placeholders():
    rows = _sample_governance_rows()
    details = dict(gui_app._governance_detail_rows(rows[0]))

    assert details["Category"] == "export"
    assert details["Event Type"] == "export_available"
    assert details["State"] == "valid"
    assert details["Actor"] == "local_export_dir"
    assert details["Target"] == "portmap-logs-20260614-120..."
    assert details["Source"] == "local_file"
    assert details["Evidence Count"] == "1"
    assert details["Preview Only"] == "True"
    assert details["Destructive Action"] == "False"

    placeholders = dict(gui_app._governance_detail_rows(None))
    assert all(value == "-" for value in placeholders.values())


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
    assert "Current | Latest | Max | Avg | Updated | Provider | Monitor | Review | Block | Total | Mode" in wide
    assert "Queue Status" not in wide
    assert "Active Risk Findings" in wide
    assert "Finding Details" in wide
    assert "Risk Status" in narrow
    assert "Current | Latest | Max | Avg | Updated | Provider | Monitor | Review | Block | Total | Mode" in narrow
    assert "Queue Status" not in narrow
    assert "Active Risk Findings" in narrow
    assert "Finding Details" in narrow
    assert "Risk Status" in wide.splitlines()[0]
    assert "Risk Status" in narrow.splitlines()[0]
    assert "Time | Action | Score | Signal" in wide
    assert "Top Risk Signals" in wide
    assert " | Recent Remediation Feed" in wide
    assert " | Risk Timeline" in wide
    assert "Time | Avg | Max | Events | Trend" in wide
    assert "Time | Avg" in narrow
    assert "Allowlist:" in wide
    assert "Safety:" in wide
    assert "Footer Status" not in wide
    assert "Footer Status" not in narrow


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

    assert "Severity | Asset | Service | Finding | Score | Action | Time" in text
    assert "HIGH" in text
    assert ".91" in text
    assert "22" in text
    assert "TCP" in text
    assert "worker-1" in text


def test_finding_details_rows_use_selected_finding_with_placeholders():
    rows = gui_app._active_risk_finding_rows(
        [
            {
                "timestamp": "2026-06-14T12:00:00+00:00",
                "node_id": "worker-1",
                "action": "prompt_operator",
                "score": 0.82,
                "score_factors": ["sensitive_port:22"],
                "ai_provider": "local_rules",
                "port": 22,
                "protocol": "tcp",
                "service_name": "ssh",
                "status": "LISTEN",
                "first_seen": "2026-06-14T11:00:00+00:00",
                "last_seen": "2026-06-14T12:00:00+00:00",
                "count": 3,
            }
        ],
        [],
    )

    details = dict(gui_app._finding_detail_rows(rows[0]))

    assert details["Asset"] == "worker-1"
    assert details["Node"] == "worker-1"
    assert details["Port"] == "22"
    assert details["Protocol"] == "TCP"
    assert details["Service Name"] == "ssh"
    assert details["Finding"] == "sensitive_port:22"
    assert details["Provider"] == "local_rules"
    assert details["Top Classification"] == "ssh"
    assert details["Classification Confidence"] != "-"
    assert "remote_access" in details["Alternative Candidates"]
    assert "port:22" in details["Evidence Signals"]
    assert "ssh:" in details["Candidate Reasoning"]
    assert "service:ssh" in details["Supporting Evidence"]
    assert "fingerprint" in details["Missing Evidence"]
    assert "Classified as ssh" in details["Explanation Summary"]
    assert details["Evidence Quality"] == "moderate"
    assert "moderate" in details["Confidence Rationale"]
    assert "Alternative candidates survived" in details["Ambiguity Reason"]
    assert "service fingerprint" in details["Missing Evidence Summary"]
    assert "expected-service allowlist" in details["Operator Next Steps"]
    assert details["Learning Profile ID"].startswith("learning-profile-")
    assert details["Learning Profile Name"] == "ssh"
    assert details["Learning Profile Observations"] == "3"
    assert details["Learning Profile Stability"] != "-"
    assert details["Historical Observations"] == "3"
    assert details["Profile Age"] == "1h"
    assert details["First Observed"] == "2026-06-14T11:00:00+00:00"
    assert details["Last Observed"] == "2026-06-14T12:00:00+00:00"
    assert details["Stability Score"] != "-"
    assert details["Stability Label"] == "stable"
    assert details["Drift Score"] == "0.00"
    assert details["Drift Label"] == "none"
    assert details["Confidence Trend"] == "stable"
    assert details["Confidence Delta"] == "0.00"
    assert details["Confidence Average"] == details["Classification Confidence"]
    assert details["Confidence Min"] == details["Classification Confidence"]
    assert details["Confidence Max"] == details["Classification Confidence"]
    assert details["First Confidence"] == details["Classification Confidence"]
    assert details["Latest Confidence"] == details["Classification Confidence"]
    assert details["Recommendation Count"] != "-"
    assert details["Primary Recommendation"] == "classification_stable"
    assert "classification_stable" in details["Recommendation List"]
    assert int(details["Graph Nodes"]) >= 6
    assert int(details["Graph Edges"]) >= 5
    assert int(details["Graph Relationships"]) >= 5
    assert int(details["Inferred Relationships"]) > 0
    assert details["Strongest Relationship"].startswith("graph-rel-")
    assert details["Strongest Relationship Type"] != "-"
    assert details["Strongest Relationship Score"] != "-"
    assert int(details["Related Entities"]) > 0
    assert int(details["Graph Clusters"]) > 0
    assert details["Strongest Cluster"].startswith("graph-cluster-")
    assert details["Strongest Cluster Type"] != "-"
    assert details["Strongest Cluster Score"] != "-"
    assert details["Primary Cluster"].startswith("graph-cluster-")
    assert details["Primary Cluster Type"] != "-"
    assert details["Primary Cluster Risk"] in {"low", "medium", "high", "critical"}
    assert details["Primary Cluster Confidence"] != "-"
    assert details["Primary Cluster Reason"] != "-"
    assert details["Primary Cluster Trend"] in {"emerging", "growing", "shrinking", "stable", "dormant", "unknown"}
    assert details["Primary Cluster Age"] != "-"
    assert details["Primary Cluster Evolution Score"] != "-"
    assert details["Primary Cluster New Relationships"] != "-"
    assert details["Primary Cluster Lost Relationships"] != "-"
    assert details["Primary Cluster New Signals"] != "-"
    assert details["Primary Cluster Lost Signals"] != "-"
    assert details["Primary Cluster Evolution Summary"] != "-"
    assert details["Primary Cluster Trend Summary"] != "-"
    assert details["Graph Insight Count"] != "-"
    assert details["Strongest Graph Insight"].startswith("graph-insight-")
    assert details["Strongest Graph Insight Type"] != "-"
    assert details["Strongest Graph Insight Score"] != "-"
    assert details["Graph Insight Summary"] != "-"
    assert details["Graph Operator Next Steps"] != "-"
    assert details["Current Risk Score"] != "-"
    assert details["Risk Evolution Direction"] in {
        "increasing",
        "decreasing",
        "stable",
        "fluctuating",
        "insufficient_history",
    }
    assert details["Risk Evolution Velocity"] in {"slow", "moderate", "rapid", "unknown"}
    assert details["Risk Evolution Confidence"] != "-"
    assert details["Risk Change Reasons"] != "-"
    assert details["Risk Evolution Summary"] != "-"
    assert details["Risk Operator Next Steps"] != "-"
    assert details["Related Asset"] == "worker-1"
    assert details["Related Service"] == "ssh"
    assert details["Related Profile"].startswith("learning-profile-")
    assert "service_match" in rows[0]["calibration"]
    assert details["Score"] == ".82"
    assert details["Action"] == "prompt_op..."
    assert details["State"] == "LISTEN"
    assert details["First Seen"] == "2026-06-14 11:00:00"
    assert details["Last Seen"] == "2026-06-14 12:00:00"
    assert details["Occurrence Count"] == "3"
    assert details["Signal Count"] == "1"
    assert details["Top Signal"] == "sensitive_port:22"
    assert details["Related Signals"] == "sensitive_port:22"
    assert details["Strongest Signal"] == "sensitive_port:22"
    assert details["Signal Categories"] == "sensitive_port"
    assert details["Risk Source"] == "remediation"
    assert details["Current Status"] == "LISTEN"

    placeholders = dict(gui_app._finding_detail_rows(None))
    assert all(value == "-" for value in placeholders.values())


def test_risk_details_table_wraps_long_metadata_and_preserves_cursor_selection():
    class Harness(gui_app.App):
        def compose(self):
            self.details = gui_app.FindingDetailsTable()
            yield self.details

    finding = {
        "asset": "worker-1",
        "service": "TCP/443",
        "alternative_candidates": "nginx 0.42, " + ("shared_tls_metadata " * 4) + "apache 0.31, caddy 0.18",
        "candidate_reasoning": "nginx: " + ("process and service metadata " * 5),
        "supporting_evidence": "nginx: process:nginx, service:https, port:443, protocol:tls",
        "missing_evidence": "nginx: fingerprint, historical confirmation, expected service review",
        "operator_next_steps": "Review service name, process owner, expected-service allowlist, and historical observations.",
        "learning_profile_id": "learning-profile-" + ("123456" * 8),
    }

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            details = app.query_one(gui_app.FindingDetailsTable)
            details.update_details(finding)
            await pilot.pause()
            rendered = [details.get_row_at(index) for index in range(details.row_count)]
            assert any(row[0] == "Alternative Candidates" for row in rendered)
            assert any(row[0] == "" and "apache" in row[1] for row in rendered)
            assert any(row[0] == "Operator Next Steps" for row in rendered)
            assert any(row[0] == "Learning Profile ID" for row in rendered)

            continuation_index = next(index for index, row in enumerate(rendered) if row[0] == "")
            details.move_cursor(row=continuation_index, column=0)
            details.update_details(finding)
            await pilot.pause()
            assert details.cursor_row == continuation_index
            assert details.get_row_at(details.cursor_row)[0] == ""

    asyncio.run(run_case())


def test_risk_details_table_preserves_scroll_and_highlighted_wrapped_row_on_refresh():
    class Harness(gui_app.App):
        def compose(self):
            self.details = gui_app.FindingDetailsTable()
            self.details.styles.height = 6
            yield self.details

    finding = {
        "asset": "worker-1",
        "service": "TCP/443",
        "alternative_candidates": "nginx 0.42, " + ("shared_tls_metadata " * 6) + "apache 0.31, caddy 0.18",
        "candidate_reasoning": "nginx: " + ("process and service metadata " * 6),
        "operator_next_steps": "Review service name, process owner, expected-service allowlist, and historical observations.",
        "learning_profile_id": "learning-profile-" + ("123456" * 8),
    }

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            details = app.query_one(gui_app.FindingDetailsTable)
            details.update_details(finding)
            await pilot.pause()
            rendered = [details.get_row_at(index) for index in range(details.row_count)]
            continuation_index = next(index for index, row in enumerate(rendered) if row[0] == "")
            details.move_cursor(row=continuation_index, column=0)
            details.scroll_to(y=max(continuation_index - 1, 0), animate=False)
            await pilot.pause()
            previous_scroll = details.scroll_y
            previous_first_visible = gui_app._table_row_key_at(details, previous_scroll)
            previous_selected = gui_app._table_row_key_at(details, details.cursor_row)

            details.update_details(finding)
            await pilot.pause()
            await pilot.pause()

            assert details.cursor_row == continuation_index
            assert details.get_row_at(details.cursor_row)[0] == ""
            assert gui_app._table_row_key_at(details, details.cursor_row) == previous_selected
            assert gui_app._table_row_key_at(details, details.scroll_y) == previous_first_visible
            assert details.scroll_y == previous_scroll
            assert details.scroll_y > 0
            assert details.scroll_y <= details.cursor_row <= details.scroll_y + max(int(details.size.height), 1)

    asyncio.run(run_case())


def test_risk_details_table_falls_back_to_nearest_row_when_wrapped_key_disappears():
    class Harness(gui_app.App):
        def compose(self):
            self.details = gui_app.FindingDetailsTable()
            self.details.styles.height = 6
            yield self.details

    initial = {
        "asset": "worker-1",
        "service": "TCP/443",
        "alternative_candidates": "nginx 0.42, " + ("shared_tls_metadata " * 6) + "apache 0.31, caddy 0.18",
        "operator_next_steps": "Review service name, process owner, expected-service allowlist, and historical observations.",
    }
    updated = {
        "asset": "worker-1",
        "service": "TCP/443",
        "alternative_candidates": "nginx 0.42",
        "operator_next_steps": "Review service name.",
    }

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            details = app.query_one(gui_app.FindingDetailsTable)
            details.update_details(initial)
            await pilot.pause()
            rendered = [details.get_row_at(index) for index in range(details.row_count)]
            old_index = next(index for index, row in enumerate(rendered) if row[0] == "")
            details.move_cursor(row=old_index, column=0)
            details.scroll_to(y=old_index, animate=False)
            await pilot.pause()
            previous_scroll = details.scroll_y

            details.update_details(updated)
            await pilot.pause()

            assert details.cursor_row == min(old_index, details.row_count - 1)
            assert details.scroll_y == min(previous_scroll, details.max_scroll_y)
            assert details.cursor_row > 0

    asyncio.run(run_case())


def test_risk_details_table_prevents_horizontal_overflow_for_long_values():
    class Harness(gui_app.App):
        def compose(self):
            self.details = gui_app.FindingDetailsTable()
            self.details.styles.width = 52
            self.details.styles.height = 8
            yield self.details

    finding = {
        "asset": "worker-1",
        "service": "TCP/443",
        "candidate_reasoning": "nginx:" + ("process_service_fingerprint_without_spaces" * 4),
        "supporting_evidence": "nginx:" + ("service-process-fingerprint-support-token" * 4),
        "missing_evidence": "nginx:" + ("missing-fingerprint-confirmation-token" * 4),
        "recommendation_list": "review_profile_drift:" + ("metadata-drift-with-long-token" * 5),
        "strongest_relationship": "graph-rel-shared_learning_profile-" + ("1234567890abcdef" * 4),
        "strongest_cluster": "graph-cluster-profile-" + ("1234567890abcdef" * 4),
        "primary_cluster_reason": "high_risk_from_service_score:" + ("cluster-analysis-token" * 5),
        "primary_cluster_evolution_summary": "profile_cluster:shrinking;" + ("relationship-signal-delta-token" * 4),
        "primary_cluster_trend_summary": "trend:shrinking;" + ("temporal-evolution-token" * 5),
        "graph_insight_summary": "low_confidence_high_risk:0.82;" + ("insight-summary-token" * 5),
        "graph_operator_next_steps": "Gather more metadata before acting on elevated risk context " + ("operator-step-token" * 5),
        "risk_change_reasons": "relationships_removed:4;" + ("risk-change-reason-token" * 5),
        "risk_evolution_summary": "direction:decreasing;velocity:moderate;" + ("risk-evolution-summary-token" * 5),
        "risk_operator_next_steps": "Continue observation and confirm expected behavior " + ("risk-next-step-token" * 5),
        "learning_profile_id": "learning-profile-" + ("1234567890abcdef" * 4),
    }

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            details = app.query_one(gui_app.FindingDetailsTable)
            details.update_details(finding)
            await pilot.pause()
            target_width = gui_app._detail_value_wrap_width(details, gui_app._finding_detail_rows(finding))
            rendered = [details.get_row_at(index) for index in range(details.row_count)]
            continuation_index = next(index for index, row in enumerate(rendered) if row[0] == "")
            details.move_cursor(row=continuation_index, column=0)
            details.scroll_to(y=max(continuation_index - 1, 0), animate=False)
            await pilot.pause()
            previous_scroll = details.scroll_y
            previous_selected = gui_app._table_row_key_at(details, details.cursor_row)

            assert target_width < gui_app.DETAIL_WRAP_WIDTH
            assert details.columns.get("value").width == target_width
            assert details.allow_horizontal_scroll is False
            assert all(len(row[1]) <= target_width for row in rendered)
            assert any(row[0] == "Candidate Reasoning" for row in rendered)
            assert any(row[0] == "Supporting Evidence" for row in rendered)
            assert any(row[0] == "Missing Evidence" for row in rendered)
            assert any(row[0] == "Recommendation List" for row in rendered)
            assert any(row[0] == "Strongest Relationship" for row in rendered)
            assert any(row[0] == "Strongest Cluster" for row in rendered)
            assert any(row[0] == "Primary Cluster Reason" for row in rendered)
            assert any(row[0] == "Primary Cluster Evolution Summary" for row in rendered)
            assert any(row[0] == "Primary Cluster Trend Summary" for row in rendered)
            assert any(row[0] == "Graph Insight Summary" for row in rendered)
            assert any(row[0] == "Graph Operator Next Steps" for row in rendered)
            assert any(row[0] == "Risk Change Reasons" for row in rendered)
            assert any(row[0] == "Risk Evolution Summary" for row in rendered)
            assert any(row[0] == "Risk Operator Next Steps" for row in rendered)
            assert any(row[0] == "Learning Profile ID" for row in rendered)
            assert any(row[0] == "" for row in rendered)

            details.update_details(finding)
            await pilot.pause()
            refreshed = [details.get_row_at(index) for index in range(details.row_count)]
            assert details.allow_horizontal_scroll is False
            assert all(len(row[1]) <= target_width for row in refreshed)
            assert gui_app._table_row_key_at(details, details.cursor_row) == previous_selected
            assert details.scroll_y == previous_scroll

    asyncio.run(run_case())


def test_risk_finding_correlation_marks_related_feed_and_timeline_rows():
    events = [
        {
            "timestamp": "2026-06-14T12:02:00+00:00",
            "node_id": "worker-1",
            "action": "prompt_operator",
            "score": 0.82,
            "port": 22,
            "protocol": "tcp",
            "service_name": "ssh",
            "score_factors": ["sensitive_port:22", "listening_socket"],
        },
        {
            "timestamp": "2026-06-14T12:07:00+00:00",
            "node_id": "worker-2",
            "action": "monitor",
            "score": 0.2,
            "port": 8080,
            "protocol": "tcp",
            "score_factors": ["expected_service"],
        },
    ]
    selected = gui_app._active_risk_finding_rows(events, [], limit=1)[0]
    feed_rows = gui_app._remediation_feed_rows(events, limit=2)
    timeline_rows = gui_app._risk_timeline_rows(
        [
            {
                "bucket_start": "2026-06-14T12:00:00+00:00",
                "event_count": 1,
                "average_score": 0.82,
                "max_score": 0.82,
            },
            {
                "bucket_start": "2026-06-14T12:10:00+00:00",
                "event_count": 1,
                "average_score": 0.2,
                "max_score": 0.2,
            },
        ]
    )

    assert gui_app._row_matches_selected_finding(selected, feed_rows[1])
    assert not gui_app._row_matches_selected_finding(selected, feed_rows[0])
    assert gui_app._row_matches_selected_finding(selected, timeline_rows[0])
    assert not gui_app._row_matches_selected_finding(selected, timeline_rows[1])


def test_risk_active_findings_selection_survives_refresh_when_row_still_exists():
    class Harness(gui_app.App):
        def compose(self):
            self.table = gui_app.RiskActiveFindingsTable()
            yield self.table

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            table = app.query_one(gui_app.RiskActiveFindingsTable)
            table.update_findings(
                [
                    {"timestamp": "2026-06-14T12:03:00+00:00", "node_id": "worker-3", "score": 0.95},
                    {"timestamp": "2026-06-14T12:02:00+00:00", "node_id": "worker-2", "score": 0.85},
                    {"timestamp": "2026-06-14T12:01:00+00:00", "node_id": "worker-1", "score": 0.70},
                ],
                [],
            )
            table.move_cursor(row=1, column=0)
            await pilot.pause()
            assert table.selected_finding()["asset"] == "worker-2"

            table.update_findings(
                [
                    {"timestamp": "2026-06-14T12:04:00+00:00", "node_id": "worker-4", "score": 0.99},
                    {"timestamp": "2026-06-14T12:03:00+00:00", "node_id": "worker-3", "score": 0.95},
                    {"timestamp": "2026-06-14T12:02:00+00:00", "node_id": "worker-2", "score": 0.85},
                    {"timestamp": "2026-06-14T12:01:00+00:00", "node_id": "worker-1", "score": 0.70},
                ],
                [],
            )
            await pilot.pause()
            assert table.selected_finding()["asset"] == "worker-2"
            assert table.cursor_row == 2

    asyncio.run(run_case())


def test_risk_active_findings_selection_falls_back_when_selected_row_removed():
    class Harness(gui_app.App):
        def compose(self):
            self.table = gui_app.RiskActiveFindingsTable()
            yield self.table

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            table = app.query_one(gui_app.RiskActiveFindingsTable)
            table.update_findings(
                [
                    {"timestamp": "2026-06-14T12:03:00+00:00", "node_id": "worker-3", "score": 0.95},
                    {"timestamp": "2026-06-14T12:02:00+00:00", "node_id": "worker-2", "score": 0.85},
                    {"timestamp": "2026-06-14T12:01:00+00:00", "node_id": "worker-1", "score": 0.70},
                ],
                [],
            )
            table.move_cursor(row=2, column=0)
            await pilot.pause()
            assert table.selected_finding()["asset"] == "worker-1"

            table.update_findings(
                [
                    {"timestamp": "2026-06-14T12:03:00+00:00", "node_id": "worker-3", "score": 0.95},
                    {"timestamp": "2026-06-14T12:02:00+00:00", "node_id": "worker-2", "score": 0.85},
                ],
                [],
            )
            await pilot.pause()
            assert table.cursor_row == 1
            assert table.selected_finding()["asset"] == "worker-2"

    asyncio.run(run_case())


def test_dashboard_node_table_selection_survives_refresh_when_row_still_exists():
    class Harness(gui_app.App):
        def compose(self):
            self.table = gui_app.NodeTable()
            yield self.table

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            table = app.query_one(gui_app.NodeTable)
            table.update_nodes(
                [
                    {"node_id": "node-a", "role": "worker", "status": "online", "last_seen": 1},
                    {"node_id": "node-b", "role": "worker", "status": "online", "last_seen": 2},
                ]
            )
            table.move_cursor(row=1, column=0)
            await pilot.pause()
            assert table.get_row_at(table.cursor_row)[0] == "node-b"

            table.update_nodes(
                [
                    {"node_id": "node-x", "role": "worker", "status": "online", "last_seen": 3},
                    {"node_id": "node-a", "role": "worker", "status": "online", "last_seen": 1},
                    {"node_id": "node-b", "role": "worker", "status": "online", "last_seen": 4},
                ]
            )
            await pilot.pause()
            assert table.cursor_row == 2
            assert table.get_row_at(table.cursor_row)[0] == "node-b"

    asyncio.run(run_case())


def test_export_activity_selection_survives_refresh_when_row_still_exists():
    class Harness(gui_app.App):
        def compose(self):
            self.table = gui_app.ExportActivityTable()
            yield self.table

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            table = app.query_one(gui_app.ExportActivityTable)
            table.update_exports(_sample_export_rows())
            table.move_cursor(row=1, column=0)
            await pilot.pause()
            assert table.selected_export()["export_id"] == "topology-20260614-120200.zip"

            table.update_exports(
                [
                    {
                        "export_id": "snapshots-20260614-120400.zip",
                        "timestamp": "2026-06-14 12:04:00",
                        "export_type": "snapshots",
                        "status": "available",
                        "destination": "/tmp/exports",
                        "files": "1",
                        "size": "8.0 KB",
                        "duration": "-",
                        "started": "-",
                        "completed": "2026-06-14 12:04:00",
                        "validation_result": "valid",
                        "key": "snapshots-20260614-120400.zip",
                    },
                    *_sample_export_rows(),
                ]
            )
            await pilot.pause()
            assert table.cursor_row == 2
            assert table.selected_export()["export_id"] == "topology-20260614-120200.zip"

    asyncio.run(run_case())


def test_export_activity_selection_falls_back_when_selected_row_removed():
    class Harness(gui_app.App):
        def compose(self):
            self.table = gui_app.ExportActivityTable()
            yield self.table

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            table = app.query_one(gui_app.ExportActivityTable)
            table.update_exports(_sample_export_rows())
            table.move_cursor(row=2, column=0)
            await pilot.pause()
            assert table.selected_export()["export_id"] == "reports-empty.zip"

            table.update_exports(_sample_export_rows()[:2])
            await pilot.pause()
            assert table.cursor_row == 1
            assert table.selected_export()["export_id"] == "topology-20260614-120200.zip"

    asyncio.run(run_case())


def test_export_details_update_when_selection_changes():
    class Harness(gui_app.App):
        def compose(self):
            self.activity = gui_app.ExportActivityTable()
            self.details = gui_app.ExportDetailsTable()
            yield self.activity
            yield self.details

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            activity = app.query_one(gui_app.ExportActivityTable)
            details = app.query_one(gui_app.ExportDetailsTable)
            activity.update_exports(_sample_export_rows())
            details.update_details(activity.selected_export())
            await pilot.pause()
            assert dict(details.get_row_at(index) for index in range(details.row_count))["Export ID"] == (
                "portmap-logs-20260614-120300.zip"
            )

            activity.move_cursor(row=1, column=0)
            details.update_details(activity.selected_export())
            await pilot.pause()
            assert dict(details.get_row_at(index) for index in range(details.row_count))["Export ID"] == (
                "topology-20260614-120200.zip"
            )

    asyncio.run(run_case())


def test_governance_evidence_selection_survives_refresh_when_row_still_exists():
    class Harness(gui_app.App):
        def compose(self):
            self.table = gui_app.GovernanceEvidenceTable()
            yield self.table

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            table = app.query_one(gui_app.GovernanceEvidenceTable)
            rows = _sample_governance_rows()
            table.update_governance(rows)
            table.move_cursor(row=1, column=0)
            await pilot.pause()
            assert table.selected_governance()["event_type"] == "export_created"

            table.update_governance(
                [
                    {
                        "time": "2026-06-14 12:05:00",
                        "category": "security_review",
                        "event_type": "review_recorded",
                        "state": "recorded",
                        "actor": "reviewer",
                        "action": "security_review",
                        "target": "review-1",
                        "source": "fixture",
                        "evidence": "1",
                        "preview_only": "True",
                        "destructive_action": "False",
                        "key": "security|2026-06-14 12:05:00|review-1",
                    },
                    *rows,
                ]
            )
            await pilot.pause()
            assert table.cursor_row == 2
            assert table.selected_governance()["event_type"] == "export_created"

    asyncio.run(run_case())


def test_governance_evidence_selection_falls_back_when_selected_row_removed():
    class Harness(gui_app.App):
        def compose(self):
            self.table = gui_app.GovernanceEvidenceTable()
            yield self.table

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            table = app.query_one(gui_app.GovernanceEvidenceTable)
            rows = _sample_governance_rows()
            table.update_governance(rows)
            table.move_cursor(row=2, column=0)
            await pilot.pause()
            assert table.selected_governance()["event_type"] == "scan_now"

            table.update_governance([rows[0], rows[1]])
            await pilot.pause()
            assert table.cursor_row == 1
            assert table.selected_governance()["event_type"] == "export_created"

    asyncio.run(run_case())


def test_governance_details_update_when_selection_changes():
    class Harness(gui_app.App):
        def compose(self):
            self.evidence = gui_app.GovernanceEvidenceTable()
            self.details = gui_app.GovernanceDetailsTable()
            yield self.evidence
            yield self.details

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            evidence = app.query_one(gui_app.GovernanceEvidenceTable)
            details = app.query_one(gui_app.GovernanceDetailsTable)
            evidence.update_governance(_sample_governance_rows())
            details.update_details(evidence.selected_governance())
            await pilot.pause()
            assert dict(details.get_row_at(index) for index in range(details.row_count))["Event Type"] == (
                "export_available"
            )

            evidence.move_cursor(row=1, column=0)
            details.update_details(evidence.selected_governance())
            await pilot.pause()
            assert dict(details.get_row_at(index) for index in range(details.row_count))["Event Type"] == (
                "export_created"
            )

    asyncio.run(run_case())


def test_deployment_readiness_selection_survives_refresh_when_row_still_exists():
    class Harness(gui_app.App):
        def compose(self):
            self.table = gui_app.DeploymentReadinessTable()
            yield self.table

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            table = app.query_one(gui_app.DeploymentReadinessTable)
            rows = _sample_deployment_rows()
            table.update_deployments(rows)
            table.move_cursor(row=1, column=0)
            await pilot.pause()
            assert table.selected_deployment()["method"] == "deb_preview"

            table.update_deployments(
                [
                    {
                        "platform": "updater",
                        "method": "secure_update_preview",
                        "status": "ready",
                        "readiness": "ready",
                        "warnings": "0",
                        "blockers": "0",
                        "updated": "2026-06-14 12:05:00",
                        "required_steps": "operator_review",
                        "warning_details": "-",
                        "blocker_details": "-",
                        "safety_mode": "preview",
                        "notes": "metadata only",
                        "preview_only": "True",
                        "destructive_action": "False",
                        "key": "updater|secure_update_preview",
                    },
                    *rows,
                ]
            )
            await pilot.pause()
            assert table.cursor_row == 2
            assert table.selected_deployment()["method"] == "deb_preview"

    asyncio.run(run_case())


def test_deployment_readiness_selection_falls_back_when_selected_row_removed():
    class Harness(gui_app.App):
        def compose(self):
            self.table = gui_app.DeploymentReadinessTable()
            yield self.table

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            table = app.query_one(gui_app.DeploymentReadinessTable)
            rows = _sample_deployment_rows()
            table.update_deployments(rows)
            table.move_cursor(row=2, column=0)
            await pilot.pause()
            assert table.selected_deployment()["method"] == "compose_preview"

            table.update_deployments([rows[0], rows[1]])
            await pilot.pause()
            assert table.cursor_row == 1
            assert table.selected_deployment()["method"] == "deb_preview"

    asyncio.run(run_case())


def test_deployment_details_update_when_selection_changes():
    class Harness(gui_app.App):
        def compose(self):
            self.readiness = gui_app.DeploymentReadinessTable()
            self.details = gui_app.DeploymentDetailsTable()
            yield self.readiness
            yield self.details

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            readiness = app.query_one(gui_app.DeploymentReadinessTable)
            details = app.query_one(gui_app.DeploymentDetailsTable)
            readiness.update_deployments(_sample_deployment_rows())
            details.update_details(readiness.selected_deployment())
            await pilot.pause()
            assert dict(details.get_row_at(index) for index in range(details.row_count))["Method"] == (
                "powershell_preview"
            )

            readiness.move_cursor(row=1, column=0)
            details.update_details(readiness.selected_deployment())
            await pilot.pause()
            assert dict(details.get_row_at(index) for index in range(details.row_count))["Method"] == "deb_preview"

    asyncio.run(run_case())


def test_ai_provider_model_selection_survives_refresh_when_row_still_exists():
    class Harness(gui_app.App):
        def compose(self):
            self.table = gui_app.AIProviderModelTable()
            yield self.table

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            table = app.query_one(gui_app.AIProviderModelTable)
            rows = gui_app._ai_provider_model_rows(_sample_ai_events())
            table.update_ai(rows)
            table.move_cursor(row=1, column=0)
            await pilot.pause()
            assert table.selected_ai()["provider"] == "local_rules"

            table.update_ai(
                [
                    {
                        "provider": "heuristic",
                        "model": "risk-v0",
                        "status": "observed",
                        "decisions": "1",
                        "updated": "2026-06-14 12:05:00",
                        "source": "master_event",
                        "latest_activity": "metadata",
                        "mode": "read_only",
                        "execution": "not performed",
                        "key": "heuristic|risk-v0",
                    },
                    *rows,
                ]
            )
            await pilot.pause()
            assert table.cursor_row == 2
            assert table.selected_ai()["provider"] == "local_rules"

    asyncio.run(run_case())


def test_ai_provider_model_selection_falls_back_when_selected_row_removed():
    class Harness(gui_app.App):
        def compose(self):
            self.table = gui_app.AIProviderModelTable()
            yield self.table

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            table = app.query_one(gui_app.AIProviderModelTable)
            rows = gui_app._ai_provider_model_rows(_sample_ai_events())
            table.update_ai(rows)
            table.move_cursor(row=2, column=0)
            await pilot.pause()
            assert table.selected_ai()["model"] == "risk-v2"

            table.update_ai([rows[0], rows[1]])
            await pilot.pause()
            assert table.cursor_row == 1
            assert table.selected_ai()["provider"] == "local_rules"

    asyncio.run(run_case())


def test_ai_details_update_when_selection_changes():
    class Harness(gui_app.App):
        def compose(self):
            self.providers = gui_app.AIProviderModelTable()
            self.details = gui_app.AIDetailsTable()
            yield self.providers
            yield self.details

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            providers = app.query_one(gui_app.AIProviderModelTable)
            details = app.query_one(gui_app.AIDetailsTable)
            providers.update_ai(gui_app._ai_provider_model_rows(_sample_ai_events()))
            details.update_details(providers.selected_ai())
            await pilot.pause()
            assert dict(details.get_row_at(index) for index in range(details.row_count))["Model"] == "risk-v1"

            providers.move_cursor(row=1, column=0)
            details.update_details(providers.selected_ai())
            await pilot.pause()
            assert dict(details.get_row_at(index) for index in range(details.row_count))["Model"] == "port-score"

    asyncio.run(run_case())


def test_packet_activity_selection_survives_refresh_when_row_still_exists():
    class Harness(gui_app.App):
        def compose(self):
            self.table = gui_app.PacketActivityTable()
            yield self.table

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            table = app.query_one(gui_app.PacketActivityTable)
            rows = gui_app._packet_activity_rows(_sample_packet_flows())
            table.update_packets(rows)
            table.move_cursor(row=1, column=0)
            await pilot.pause()
            assert table.selected_packet()["transport"] == "UDP"

            table.update_packets(
                [
                    {
                        "time": "2026-06-14 12:05:00",
                        "flow": "203.0.113.40:50000 -> 203.0.113.41:443",
                        "transport": "TCP",
                        "packets": "1",
                        "bytes": "60",
                        "status": "observed",
                        "first_seen": "2026-06-14 12:05:00",
                        "last_seen": "2026-06-14 12:05:00",
                        "source": "flow_metadata",
                        "mode": "read_only",
                        "execution": "not performed",
                        "key": "flow-4",
                    },
                    *rows,
                ]
            )
            await pilot.pause()
            assert table.cursor_row == 2
            assert table.selected_packet()["transport"] == "UDP"

    asyncio.run(run_case())


def test_packet_activity_selection_falls_back_when_selected_row_removed():
    class Harness(gui_app.App):
        def compose(self):
            self.table = gui_app.PacketActivityTable()
            yield self.table

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            table = app.query_one(gui_app.PacketActivityTable)
            rows = gui_app._packet_activity_rows(_sample_packet_flows())
            table.update_packets(rows)
            table.move_cursor(row=2, column=0)
            await pilot.pause()
            assert table.selected_packet()["flow"] == "203.0.113.30:50000 -> 203.0.113.1:22"

            table.update_packets([rows[0], rows[1]])
            await pilot.pause()
            assert table.cursor_row == 1
            assert table.selected_packet()["transport"] == "UDP"

    asyncio.run(run_case())


def test_packet_details_update_when_selection_changes():
    class Harness(gui_app.App):
        def compose(self):
            self.activity = gui_app.PacketActivityTable()
            self.details = gui_app.PacketDetailsTable()
            yield self.activity
            yield self.details

    async def run_case():
        app = Harness()
        async with app.run_test() as pilot:
            activity = app.query_one(gui_app.PacketActivityTable)
            details = app.query_one(gui_app.PacketDetailsTable)
            activity.update_packets(gui_app._packet_activity_rows(_sample_packet_flows()))
            details.update_details(activity.selected_packet())
            await pilot.pause()
            assert dict(details.get_row_at(index) for index in range(details.row_count))["Transport"] == "TCP"

            activity.move_cursor(row=1, column=0)
            details.update_details(activity.selected_packet())
            await pilot.pause()
            assert dict(details.get_row_at(index) for index in range(details.row_count))["Transport"] == "UDP"

    asyncio.run(run_case())


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

    assert "Time | Avg | Max | Events | Trend" in text
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

    assert gui_app.RISK_ACTIVE_FINDING_LIMIT == 24
    assert len(sections["active_findings"].splitlines()) == 14
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


def test_risk_refresh_change_awareness_uses_existing_snapshot_keys():
    first = [
        {
            "timestamp": "2026-06-14T12:00:00+00:00",
            "node_id": "worker-1",
            "action": "monitor",
            "score": 0.5,
            "score_factors": ["listening_socket"],
        }
    ]
    second = [
        *first,
        {
            "timestamp": "2026-06-14T12:01:00+00:00",
            "node_id": "worker-2",
            "action": "prompt_operator",
            "score": 0.9,
            "score_factors": ["sensitive_port:22"],
        },
    ]

    first_keys = {row["key"] for row in gui_app._active_risk_finding_rows(first, [])}
    second_rows = gui_app._active_risk_finding_rows(second, [])
    second_keys = {row["key"] for row in second_rows}

    assert len(second_keys - first_keys) == 1
    assert all(row["key"] for row in second_rows)


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
