from core_engine.visibility_history import build_visibility_snapshot, compare_visibility_snapshots


def _assets(extra=None):
    rows = [
        {"host": "192.0.2.10", "ip_version": 4, "status": "reachable", "target_source": "sample", "methods": ["tcp"]},
        {"host": "192.0.2.20", "ip_version": 4, "status": "reachable", "target_source": "sample", "methods": ["tcp"]},
    ]
    if extra:
        rows.extend(extra)
    return rows


def _services(extra=None):
    rows = [
        {"target": "192.0.2.10", "port": 10022, "state": "open", "service": "SSH", "version": "", "confidence": 0.55},
        {"target": "192.0.2.20", "port": 15432, "state": "open", "service": "PostgreSQL", "version": "", "confidence": 0.55},
    ]
    if extra:
        rows.extend(extra)
    return rows


def _flows(extra=None):
    rows = [
        {
            "flow_id": "flow-a",
            "initiator": {"ip": "192.0.2.10", "port": 51515},
            "responder": {"ip": "203.0.113.50", "port": 8443},
            "payload_bytes": 512,
            "application_protocols": ["HTTPS"],
        }
    ]
    if extra:
        rows.extend(extra)
    return {"flows": rows}


def test_visibility_snapshot_tracks_assets_services_identity_and_topology():
    snapshot = build_visibility_snapshot(
        assets=_assets(),
        services=_services(),
        flows=_flows(),
        label="sample-baseline",
        observed_at="sample-observation",
    )

    assert snapshot["ok"] is True
    assert snapshot["automatic_changes"] is False
    assert snapshot["administrator_controlled"] is True
    assert snapshot["raw_payload_stored"] is False
    assert snapshot["asset_count"] == 3
    assert snapshot["service_count"] == 2
    assert snapshot["topology"]["edges"][0]["src"] == "192.0.2.10"
    known_asset = next(item for item in snapshot["assets"] if item["host"] == "192.0.2.10")
    assert known_asset["asset_id"].startswith("asset-")
    assert known_asset["identity"]["confidence_label"] in {"medium", "high"}
    assert known_asset["identity"]["raw_identifier_stored"] is False
    assert known_asset["service_ports"] == [10022]


def test_visibility_compare_reports_service_asset_and_topology_deltas():
    baseline = build_visibility_snapshot(
        assets=_assets(),
        services=_services(),
        flows=_flows(),
        label="baseline",
    )
    current = build_visibility_snapshot(
        assets=_assets(extra=[{"host": "198.51.100.30", "ip_version": 4, "status": "reachable", "target_source": "sample"}]),
        services=_services(extra=[
            {"target": "192.0.2.10", "port": 8443, "state": "open", "service": "HTTPS", "version": "sample", "confidence": 0.92},
            {"target": "192.0.2.20", "port": 15432, "state": "open", "service": "PostgreSQL", "version": "sample-updated", "confidence": 0.80},
            {"target": "198.51.100.30", "port": 6379, "state": "open", "service": "Redis", "version": "", "confidence": 0.55},
        ]),
        flows=_flows(extra=[
            {
                "flow_id": "flow-b",
                "initiator": {"ip": "198.51.100.30", "port": 51516},
                "responder": {"ip": "192.0.2.20", "port": 8080},
                "payload_bytes": 2048,
                "application_protocols": ["HTTP"],
            }
        ]),
        label="current",
    )

    report = compare_visibility_snapshots(baseline, current)

    delta_types = {delta["type"] for delta in report["deltas"]}
    assert report["automatic_changes"] is False
    assert report["administrator_controlled"] is True
    assert report["raw_payload_stored"] is False
    assert delta_types >= {"asset_added", "service_added", "service_changed", "topology_relationship_added"}
    assert report["summary"]["by_type"]["service_added"] == 2
    assert report["response_workflows"]
    assert all(workflow["dry_run"] for workflow in report["response_workflows"])
    assert all(workflow["approval_required"] for workflow in report["response_workflows"])
