"""Reusable local web dashboard foundation."""

from gui.web.dashboard import build_dashboard_model, write_dashboard_html
from gui.web.distributed_views import (
    build_distributed_operator_sections,
    build_distributed_operator_view,
    distributed_operator_api_response,
    render_distributed_operator_sections,
)
from gui.web.providers import (
    DashboardProvider,
    StaticDashboardProvider,
    StorageDashboardProvider,
    collection_response,
    diagnostic_summary_response,
    review_summary_response,
    runtime_state_response,
    snapshot_summary_response,
    topology_summary_response,
)
from gui.web.render import render_dashboard_html, render_metric_panel, render_status_card
from gui.web.sample_data import sample_dashboard_api_data
from gui.web.views import build_dashboard_sections, build_dashboard_view, render_dashboard_sections, render_dashboard_view

__all__ = [
    "DashboardProvider",
    "StaticDashboardProvider",
    "StorageDashboardProvider",
    "build_dashboard_model",
    "build_dashboard_sections",
    "build_dashboard_view",
    "build_distributed_operator_sections",
    "build_distributed_operator_view",
    "collection_response",
    "diagnostic_summary_response",
    "distributed_operator_api_response",
    "render_dashboard_html",
    "render_metric_panel",
    "render_distributed_operator_sections",
    "render_dashboard_sections",
    "render_dashboard_view",
    "review_summary_response",
    "runtime_state_response",
    "render_status_card",
    "sample_dashboard_api_data",
    "snapshot_summary_response",
    "topology_summary_response",
    "write_dashboard_html",
]
