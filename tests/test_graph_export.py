import json

from core_engine.visualization import (
    build_topology_graph,
    deterministic_topology_json,
    export_graph_cytoscape,
    export_graph_cytoscape_json,
    export_graph_json,
    export_graph_mermaid,
)


FIXED_TIME = "2026-01-01T00:00:00+00:00"


def _flow():
    return {
        "flow_reference": "flow-redacted-001",
        "flow_direction": "outbound",
        "local_endpoint_class": "workstation",
        "remote_endpoint_class": "server",
        "local_port": 52444,
        "remote_port": 443,
        "protocol": "tcp",
        "service_hint": "https",
        "source_mode": "fixture",
        "observation_count": 4,
    }


def test_export_graph_json_is_deterministic_and_safe():
    graph = build_topology_graph(flows=[_flow()], generated_at=FIXED_TIME)
    exported = export_graph_json(graph)

    assert exported == deterministic_topology_json(graph)
    assert json.loads(exported)["summary"]["edge_count"] == 1
    assert "payload_content" not in exported
    assert "hostname" not in exported
    assert '"source_mode":"fixture"' in exported
    assert '"raw_dns_history_stored":false' in exported


def test_export_graph_mermaid_uses_sanitized_labels():
    graph = build_topology_graph(flows=[_flow()], generated_at=FIXED_TIME)
    mermaid = export_graph_mermaid(graph)

    assert mermaid.startswith("flowchart LR")
    assert "metadata-only" in mermaid
    assert "workstation" in mermaid
    assert "https" in mermaid
    assert "payload" not in mermaid.lower()


def test_export_graph_cytoscape_records_are_safe():
    graph = build_topology_graph(flows=[_flow()], generated_at=FIXED_TIME)
    cytoscape = export_graph_cytoscape(graph)
    cytoscape_json = export_graph_cytoscape_json(graph)

    assert cytoscape["format"] == "cytoscape"
    assert len(cytoscape["elements"]["nodes"]) == 2
    assert len(cytoscape["elements"]["edges"]) == 1
    assert cytoscape["safety"]["metadata_only"] is True
    assert cytoscape["safety"]["enforcement_enabled"] is False
    assert json.loads(cytoscape_json)["elements"]["edges"][0]["data"]["source_mode"] == "fixture"
