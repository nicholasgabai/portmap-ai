import re

from gui.web import (
    build_dashboard_model,
    render_dashboard_html,
    render_metric_panel,
    render_status_card,
    sample_dashboard_api_data,
    write_dashboard_html,
)


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
]


def test_dashboard_model_creation_from_sample_data():
    model = build_dashboard_model(sample_dashboard_api_data())

    assert model["health_status"] == "ok"
    assert model["metrics"]["asset_count"] == 2
    assert model["metrics"]["event_count"] == 3
    assert model["metrics"]["snapshot_count"] == 1
    assert model["metrics"]["node_count"] == 1
    assert model["metrics"]["topology_node_count"] == 2
    assert model["metrics"]["topology_edge_count"] == 1
    assert model["metrics"]["operator_review_count"] == 2
    assert model["read_only"] is True
    assert model["automatic_changes"] is False


def test_empty_state_rendering():
    model = build_dashboard_model()
    html = render_dashboard_html(model)

    assert model["metrics"]["asset_count"] == 0
    assert model["metrics"]["event_count"] == 0
    assert model["metrics"]["snapshot_count"] == 0
    assert "PortMap-AI Local Dashboard" in html
    assert "raw_payload_stored=false" in html
    assert "automatic_changes=false" in html


def test_metric_panel_and_status_card_rendering_escape_content():
    panel = render_metric_panel("<Assets>", "<2>", "Observed <local> assets")
    status = render_status_card({"health_status": "<ok>", "generated_at": "sample"})

    assert "&lt;Assets&gt;" in panel
    assert "&lt;2&gt;" in panel
    assert "&lt;local&gt;" in panel
    assert "&lt;ok&gt;" in status


def test_provider_object_input():
    class Provider:
        def __init__(self, data):
            self.data = data

        def get(self, path):
            key = path.strip("/")
            return 200, self.data[key]

    model = build_dashboard_model(Provider(sample_dashboard_api_data()))

    assert model["metrics"]["asset_count"] == 2
    assert model["metrics"]["operator_review_count"] == 2


def test_local_html_output(tmp_path):
    target = tmp_path / "preview" / "dashboard.html"
    model = build_dashboard_model(sample_dashboard_api_data())

    result = write_dashboard_html(target, model)

    assert result == target
    assert target.exists()
    assert "PortMap-AI Local Dashboard" in target.read_text(encoding="utf-8")


def test_sanitized_sample_data_and_output_have_no_private_identifiers():
    data = sample_dashboard_api_data()
    html = render_dashboard_html(build_dashboard_model(data))
    combined = repr(data) + html

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(combined)
