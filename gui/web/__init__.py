"""Reusable local web dashboard foundation."""

from gui.web.dashboard import build_dashboard_model, write_dashboard_html
from gui.web.render import render_dashboard_html, render_metric_panel, render_status_card
from gui.web.sample_data import sample_dashboard_api_data

__all__ = [
    "build_dashboard_model",
    "render_dashboard_html",
    "render_metric_panel",
    "render_status_card",
    "sample_dashboard_api_data",
    "write_dashboard_html",
]
