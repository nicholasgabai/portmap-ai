import json

from cli import main as cli_main


def test_scan_outputs_json(monkeypatch, capsys):
    monkeypatch.setattr(
        cli_main,
        "basic_scan",
        lambda kind="inet": [{"port": 443, "program": "svc", "kind": kind}],
    )

    result = cli_main.main(["scan", "--kind", "tcp", "--output", "json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == [{"kind": "tcp", "port": 443, "program": "svc"}]


def test_scan_udp_target_outputs_json(monkeypatch, capsys):
    seen = {}

    def fake_scan_udp_target(target, ports=None, timeout=1.0, retries=1, aggressive=False):
        seen.update({
            "target": target,
            "ports": ports,
            "timeout": timeout,
            "retries": retries,
            "aggressive": aggressive,
        })
        return [{"protocol": "UDP", "port": 53, "udp_state": "open"}]

    monkeypatch.setattr(cli_main, "scan_udp_target", fake_scan_udp_target)

    result = cli_main.main([
        "scan",
        "--udp-target",
        "127.0.0.1",
        "--udp-ports",
        "53,123-124",
        "--udp-timeout",
        "0.25",
        "--udp-retries",
        "0",
        "--udp-aggressive",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "target": "127.0.0.1",
        "ports": [53, 123, 124],
        "timeout": 0.25,
        "retries": 0,
        "aggressive": True,
    }
    assert json.loads(capsys.readouterr().out) == [{"port": 53, "protocol": "UDP", "udp_state": "open"}]


def test_scan_target_outputs_dual_stack_json(monkeypatch, capsys):
    seen = {}

    def fake_scan_dual_stack_targets(targets, ports, ip_version="auto", timeout=1.0, aggressive=False):
        seen.update({
            "targets": targets,
            "ports": ports,
            "ip_version": ip_version,
            "timeout": timeout,
            "aggressive": aggressive,
        })
        return [{"protocol": "TCP", "port": 443, "ip_version": 6, "tcp_state": "open"}]

    monkeypatch.setattr(cli_main, "scan_dual_stack_targets", fake_scan_dual_stack_targets)

    result = cli_main.main([
        "scan",
        "--target",
        "::1",
        "--ports",
        "80,443",
        "--ip-version",
        "6",
        "--timeout",
        "0.5",
        "--aggressive",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "targets": "::1",
        "ports": [80, 443],
        "ip_version": "6",
        "timeout": 0.5,
        "aggressive": True,
    }
    assert json.loads(capsys.readouterr().out) == [
        {"ip_version": 6, "port": 443, "protocol": "TCP", "tcp_state": "open"}
    ]


def test_capture_outputs_json(monkeypatch, capsys, tmp_path):
    seen = {}
    pcap_path = tmp_path / "capture.pcap"

    def fake_capture_live(interface=None, duration=5.0, max_packets=100, capture_filter=None, pcap_path=None, dissect=False, dpi=False, flows=False):
        seen.update({
            "interface": interface,
            "duration": duration,
            "max_packets": max_packets,
            "capture_filter": capture_filter,
            "pcap_path": pcap_path,
            "dissect": dissect,
            "dpi": dpi,
            "flows": flows,
        })
        return {"ok": True, "packet_count": 1, "packets": [{"protocol": "TCP"}]}

    monkeypatch.setattr(cli_main, "capture_live", fake_capture_live)

    result = cli_main.main([
        "capture",
        "--interface",
        "en0",
        "--duration",
        "0.5",
        "--max-packets",
        "2",
        "--filter",
        "tcp",
        "--pcap",
        str(pcap_path),
        "--dissect",
        "--dpi",
        "--flows",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "interface": "en0",
        "duration": 0.5,
        "max_packets": 2,
        "capture_filter": "tcp",
        "pcap_path": str(pcap_path),
        "dissect": True,
        "dpi": True,
        "flows": True,
    }
    assert json.loads(capsys.readouterr().out) == {"ok": True, "packet_count": 1, "packets": [{"protocol": "TCP"}]}


def test_dpi_observation_outputs_json(monkeypatch, capsys):
    seen = {}

    def fake_analyze_observation(observation, include_payload_preview=False):
        seen.update({"observation": observation, "include_payload_preview": include_payload_preview})
        return {"protocol": "HTTP", "risk_score": 0.55, "findings": [{"type": "credential_material"}]}

    monkeypatch.setattr(cli_main, "analyze_observation", fake_analyze_observation)

    result = cli_main.main([
        "dpi",
        "--observation-json",
        '{"protocol":"HTTP","payload_text":"GET / HTTP/1.1"}',
        "--include-payload-preview",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "observation": {"protocol": "HTTP", "payload_text": "GET / HTTP/1.1"},
        "include_payload_preview": True,
    }
    assert json.loads(capsys.readouterr().out)["risk_score"] == 0.55


def test_flows_outputs_json(monkeypatch, capsys):
    seen = {}

    def fake_build_flow_report(events, window_seconds=60.0):
        seen.update({"events": events, "window_seconds": window_seconds})
        return {"ok": True, "flow_count": 1, "flows": [{"flow_id": "abc"}]}

    monkeypatch.setattr(cli_main, "build_flow_report", fake_build_flow_report)

    result = cli_main.main([
        "flows",
        "--events-json",
        '[{"timestamp":1,"protocol":"TCP","src_ip":"203.0.113.1","dst_ip":"203.0.113.2","src_port":1111,"dst_port":443}]',
        "--window",
        "30",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "events": [{"timestamp": 1, "protocol": "TCP", "src_ip": "203.0.113.1", "dst_ip": "203.0.113.2", "src_port": 1111, "dst_port": 443}],
        "window_seconds": 30.0,
    }
    assert json.loads(capsys.readouterr().out) == {"flow_count": 1, "flows": [{"flow_id": "abc"}], "ok": True}


def test_flows_rejects_non_list_events(capsys):
    result = cli_main.main(["flows", "--events-json", '{"src_ip":"203.0.113.1"}'])

    assert result == 1
    assert "must decode to a list" in capsys.readouterr().err


def test_cluster_plan_outputs_json(monkeypatch, capsys):
    seen = {}

    def fake_plan_distributed_scan(targets, ports, **kwargs):
        seen.update({"targets": targets, "ports": ports, **kwargs})
        return {
            "ok": True,
            "mode": "dry_run",
            "summary": {"task_count": 1, "assigned_tasks": 1},
            "job": {"job_id": "job-1", "tasks": []},
            "automatic_changes": False,
        }

    monkeypatch.setattr(cli_main, "plan_distributed_scan", fake_plan_distributed_scan)

    result = cli_main.main([
        "cluster",
        "plan",
        "--target",
        "127.0.0.1",
        "--ports",
        "80,443",
        "--worker",
        "worker-a@203.0.113.2",
        "--workers-json",
        '{"workers":[{"node_id":"worker-b","status":"ready"}]}',
        "--target-chunk-size",
        "2",
        "--port-chunk-size",
        "1",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen["targets"] == "127.0.0.1"
    assert seen["ports"] == [80, 443]
    assert seen["workers"] == [
        {"node_id": "worker-b", "status": "ready"},
        {"node_id": "worker-a", "address": "203.0.113.2", "status": "available", "role": "worker"},
    ]
    assert seen["target_chunk_size"] == 2
    assert seen["port_chunk_size"] == 1
    assert json.loads(capsys.readouterr().out)["mode"] == "dry_run"


def test_cluster_plan_rejects_bad_workers_json(capsys):
    result = cli_main.main([
        "cluster",
        "plan",
        "--target",
        "127.0.0.1",
        "--workers-json",
        '{"workers":{}}',
    ])

    assert result == 1
    assert "workers-json" in capsys.readouterr().err


def test_visibility_outputs_json(monkeypatch, capsys):
    seen = {}

    def fake_build_visibility_report(**kwargs):
        seen.update(kwargs)
        return {
            "ok": True,
            "summary": {"finding_count": 1},
            "findings": [{"type": "management_service_open"}],
            "automatic_changes": False,
        }

    monkeypatch.setattr(cli_main, "build_visibility_report", fake_build_visibility_report)

    result = cli_main.main([
        "visibility",
        "--assets-json",
        '{"assets":[{"host":"203.0.113.10","status":"reachable"}]}',
        "--services-json",
        '[{"target":"203.0.113.10","port":22,"state":"open","service":"SSH"}]',
        "--flows-json",
        '{"flows":[{"flow_id":"flow-1"}]}',
        "--policy-json",
        '{"management_ports":[22]}',
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "assets": [{"host": "203.0.113.10", "status": "reachable"}],
        "services": [{"target": "203.0.113.10", "port": 22, "state": "open", "service": "SSH"}],
        "flows": {"flows": [{"flow_id": "flow-1"}]},
        "policy": {"management_ports": [22]},
    }
    assert json.loads(capsys.readouterr().out)["summary"]["finding_count"] == 1


def test_visibility_rejects_bad_flow_json(capsys):
    result = cli_main.main(["visibility", "--flows-json", '"not-a-flow-list"'])

    assert result == 1
    assert "must decode to a flow report object or list" in capsys.readouterr().err


def test_workspace_outputs_user_access_json(capsys):
    result = cli_main.main([
        "workspace",
        "--tenant-json",
        '{"tenant_id":"tenant.local","name":"Local Tenant"}',
        "--org-json",
        '{"organizations":[{"org_id":"org.ops","tenant_id":"tenant.local","name":"Ops"}]}',
        "--team-json",
        '{"teams":[{"team_id":"team.netops","tenant_id":"tenant.local","org_id":"org.ops","name":"NetOps","roles":["analyst"],"members":["alice"]}]}',
        "--user",
        "alice",
    ])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tenant_isolated"] is True
    assert payload["user_access"]["roles"] == ["analyst"]


def test_license_outputs_usage_summary(capsys):
    result = cli_main.main([
        "license",
        "--license-json",
        '{"license_id":"lic-1","tenant_id":"tenant.local","tier":"team","features":["cloud_sync"],"quotas":{"workspaces":2}}',
        "--usage-json",
        '{"tenant_id":"tenant.local","counters":{"workspaces":3}}',
        "--feature",
        "cloud_sync",
        "--quota",
        "workspaces",
    ])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["feature_gate"]["enabled"] is True
    assert payload["quota_check"]["exceeded"] is True


def test_cloud_sync_exports_manifest(capsys):
    result = cli_main.main([
        "cloud-sync",
        "--tenant-id",
        "tenant.local",
        "--workspace-id",
        "workspace.local",
        "--key",
        "local-sync-key",
        "--payload-json",
        '{"setting":"value"}',
    ])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cloud_sync_optional"] is True
    assert "value" not in payload["encrypted_payload"]


def test_advisory_outputs_review_packet(capsys):
    result = cli_main.main([
        "advisory",
        "--recommendation-json",
        '{"recommendations":[{"recommendation_id":"rec-1","title":"Review workspace","summary":"Review workspace settings.","category":"configuration_review","target":"workspace.local","actions":["review settings"]}]}',
    ])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["administrator_controlled"] is True
    assert payload["records"][0]["state"] == "pending_review"


def test_behavior_outputs_json_without_learning(monkeypatch, capsys, tmp_path):
    baseline_path = tmp_path / "baseline.json"
    seen = {}

    def fake_analyze_events(events, baseline, learn=False):
        seen.update({"events": events, "baseline": baseline, "learn": learn})
        return {"ok": True, "analysis_count": 1, "analyses": [{"device_id": "worker-1", "score": 0.1}]}

    monkeypatch.setattr(cli_main, "load_baseline", lambda path=None: {"devices": {"worker-1": {}}})
    monkeypatch.setattr(cli_main, "analyze_events", fake_analyze_events)

    result = cli_main.main([
        "behavior",
        "--events-json",
        '[{"device_id":"worker-1","metadata":{"dst_port":443}}]',
        "--baseline",
        str(baseline_path),
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "events": [{"device_id": "worker-1", "metadata": {"dst_port": 443}}],
        "baseline": {"devices": {"worker-1": {}}},
        "learn": False,
    }
    assert json.loads(capsys.readouterr().out)["analysis_count"] == 1


def test_behavior_learn_saves_baseline(monkeypatch, capsys, tmp_path):
    baseline_path = tmp_path / "baseline.json"
    saved = {}

    monkeypatch.setattr(cli_main, "load_baseline", lambda path=None: {"devices": {}})
    monkeypatch.setattr(
        cli_main,
        "analyze_events",
        lambda events, baseline, learn=False: {
            "ok": True,
            "analysis_count": 1,
            "analyses": [],
            "baseline": {"devices": {"worker-1": {"event_count": 1}}},
            "baseline_updated": learn,
        },
    )

    def fake_save_baseline(baseline, path=None):
        saved.update({"baseline": baseline, "path": path})
        return baseline_path

    monkeypatch.setattr(cli_main, "save_baseline", fake_save_baseline)

    result = cli_main.main([
        "behavior",
        "--events-json",
        '[{"device_id":"worker-1"}]',
        "--baseline",
        str(baseline_path),
        "--learn",
        "--output",
        "json",
    ])

    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert saved == {
        "baseline": {"devices": {"worker-1": {"event_count": 1}}},
        "path": str(baseline_path),
    }
    assert payload["baseline_path"] == str(baseline_path)


def test_behavior_rejects_non_list_events(capsys):
    result = cli_main.main(["behavior", "--events-json", '{"device_id":"worker-1"}'])

    assert result == 1
    assert "must decode to a list" in capsys.readouterr().err


def test_payload_outputs_json(monkeypatch, capsys):
    seen = {}

    def fake_classify_payload_events(events, include_payload_preview=False):
        seen.update({"events": events, "include_payload_preview": include_payload_preview})
        return {"ok": True, "classification_count": 1, "classifications": [{"label": "text"}]}

    monkeypatch.setattr(cli_main, "classify_payload_events", fake_classify_payload_events)

    result = cli_main.main([
        "payload",
        "--events-json",
        '{"protocol":"HTTP","payload_text":"GET / HTTP/1.1"}',
        "--include-payload-preview",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "events": [{"protocol": "HTTP", "payload_text": "GET / HTTP/1.1"}],
        "include_payload_preview": True,
    }
    assert json.loads(capsys.readouterr().out) == {
        "classifications": [{"label": "text"}],
        "classification_count": 1,
        "ok": True,
    }


def test_payload_rejects_non_list_or_object_events(capsys):
    result = cli_main.main(["payload", "--events-json", '"bad"'])

    assert result == 1
    assert "object or list" in capsys.readouterr().err


def test_correlate_outputs_json(monkeypatch, capsys):
    seen = {}

    def fake_correlate_events(events, window_seconds=300.0):
        seen.update({"events": events, "window_seconds": window_seconds})
        return {"ok": True, "incident_count": 1, "incidents": [{"type": "repeated_anomaly"}]}

    monkeypatch.setattr(cli_main, "correlate_events", fake_correlate_events)

    result = cli_main.main([
        "correlate",
        "--events-json",
        '[{"device_id":"worker-1","score":0.6}]',
        "--window",
        "120",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "events": [{"device_id": "worker-1", "score": 0.6}],
        "window_seconds": 120.0,
    }
    assert json.loads(capsys.readouterr().out) == {
        "incidents": [{"type": "repeated_anomaly"}],
        "incident_count": 1,
        "ok": True,
    }


def test_correlate_rejects_non_list_events(capsys):
    result = cli_main.main(["correlate", "--events-json", '{"device_id":"worker-1"}'])

    assert result == 1
    assert "must decode to a list" in capsys.readouterr().err


def test_recommend_outputs_json(monkeypatch, capsys):
    seen = {}

    def fake_generate_recommendations(incidents, review_threshold=0.6, approval_threshold=0.8):
        seen.update({
            "incidents": incidents,
            "review_threshold": review_threshold,
            "approval_threshold": approval_threshold,
        })
        return {"ok": True, "recommendation_count": 1, "recommendations": [{"action": "investigate"}]}

    monkeypatch.setattr(cli_main, "generate_recommendations", fake_generate_recommendations)

    result = cli_main.main([
        "recommend",
        "--incidents-json",
        '{"incidents":[{"incident_id":"inc-1","score":0.9}]}',
        "--review-threshold",
        "0.4",
        "--approval-threshold",
        "0.9",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "incidents": [{"incident_id": "inc-1", "score": 0.9}],
        "review_threshold": 0.4,
        "approval_threshold": 0.9,
    }
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "recommendation_count": 1,
        "recommendations": [{"action": "investigate"}],
    }


def test_recommend_rejects_non_list_incidents(capsys):
    result = cli_main.main(["recommend", "--incidents-json", '{"incident_id":"inc-1"}'])

    assert result == 1
    assert "must decode to a list" in capsys.readouterr().err


def test_cve_matches_service_json_against_inline_cves(capsys):
    service_json = json.dumps([
        {"target": "127.0.0.1", "port": 80, "state": "open", "service": "HTTP", "version": "Apache/2.4.49"}
    ])
    cve_json = json.dumps([
        {
            "id": "CVE-2021-41773",
            "summary": "Apache HTTP Server 2.4.49 path traversal vulnerability.",
            "severity": "high",
            "cvss_score": 7.5,
            "cpes": ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
        }
    ])

    result = cli_main.main(["cve", "--service-json", service_json, "--cve-json", cve_json, "--output", "json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["automatic_changes"] is False
    assert payload["match_count"] == 1
    assert payload["matches"][0]["cve_id"] == "CVE-2021-41773"


def test_cve_update_fetches_and_saves_cache(monkeypatch, capsys, tmp_path):
    cache_path = tmp_path / "cves.json"
    seen = {}

    def fake_fetch_nvd_cves(keyword=None, cve_id=None, api_key=None, limit=50):
        seen.update({"keyword": keyword, "cve_id": cve_id, "api_key": api_key, "limit": limit})
        return {
            "ok": True,
            "query": {"keyword": keyword, "cve_id": cve_id, "limit": limit},
            "record_count": 1,
            "records": [{"id": "CVE-2024-0001", "severity": "medium"}],
        }

    monkeypatch.setattr(cli_main, "fetch_nvd_cves", fake_fetch_nvd_cves)

    result = cli_main.main([
        "cve",
        "--update",
        "--query",
        "openssh",
        "--api-key",
        "key",
        "--limit",
        "1",
        "--cache",
        str(cache_path),
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {"keyword": "openssh", "cve_id": None, "api_key": "key", "limit": 1}
    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == "update"
    assert payload["stored_count"] == 1
    assert payload["automatic_changes"] is False
    assert cache_path.exists()


def test_vuln_outputs_prioritized_json(capsys):
    services = json.dumps([
        {
            "target": "203.0.113.10",
            "port": 80,
            "state": "open",
            "service": "HTTP",
            "version": "Apache/2.4.49",
            "classification": "public_interface",
        }
    ])
    matches = json.dumps({
        "matches": [
            {
                "target": "203.0.113.10",
                "port": 80,
                "service": "HTTP",
                "version": "Apache/2.4.49",
                "cve_id": "CVE-2021-41773",
                "severity": "high",
                "cvss_score": 7.5,
                "risk_score": 0.88,
                "confidence": 0.95,
                "known_exploited": True,
                "summary": "Apache HTTP Server 2.4.49 remote code execution vulnerability.",
            }
        ]
    })

    result = cli_main.main(["vuln", "--service-json", services, "--cve-matches-json", matches, "--output", "json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["automatic_changes"] is False
    assert payload["vulnerability_count"] == 1
    assert payload["vulnerabilities"][0]["priority"] == "critical"


def test_vuln_matches_raw_cves_when_no_match_report_is_supplied(capsys):
    services = json.dumps([
        {"target": "203.0.113.5", "port": 22, "state": "open", "service": "SSH", "version": "OpenSSH_9.1"}
    ])
    cves = json.dumps([
        {
            "id": "CVE-2024-0001",
            "summary": "OpenSSH 9.1 remote code execution vulnerability.",
            "severity": "critical",
            "cvss_score": 9.8,
            "cpes": ["cpe:2.3:a:openbsd:openssh:9.1:*:*:*:*:*:*:*"],
        }
    ])

    result = cli_main.main(["vuln", "--service-json", services, "--cve-json", cves, "--output", "json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cve_match_count"] == 1
    assert payload["vulnerabilities"][0]["cve_id"] == "CVE-2024-0001"


def test_rbac_outputs_permission_decision(capsys):
    result = cli_main.main(["rbac", "--roles", "analyst", "--permission", "generate:recommendations", "--output", "json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["granted"] is True
    assert "read:nodes" in payload["effective_permissions"]


def test_rbac_outputs_role_report(capsys):
    result = cli_main.main(["rbac", "--output", "json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert "admin" in payload["roles"]


def test_alert_formats_slack_payload(capsys):
    event = json.dumps({
        "severity": "critical",
        "title": "Critical Apache vulnerability",
        "summary": "Apache HTTP Server requires review.",
        "target": "203.0.113.10",
    })

    result = cli_main.main(["alert", "--event-json", event, "--format", "slack", "--output", "json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["delivery"]["status"] == "dry_run"
    assert payload["payload"]["text"].startswith("[CRITICAL]")


def test_alert_rejects_email_without_recipients(capsys):
    result = cli_main.main(["alert", "--event-json", '{"title":"x"}', "--format", "email", "--output", "json"])

    assert result == 1
    assert "Alert integration error" in capsys.readouterr().err


def test_tls_observation_outputs_json(monkeypatch, capsys):
    seen = {}

    def fake_analyze_tls_observation(observation):
        seen.update(observation)
        return {"target": observation["target"], "risk_score": 0.25, "warnings": []}

    monkeypatch.setattr(cli_main, "analyze_tls_observation", fake_analyze_tls_observation)

    result = cli_main.main([
        "tls",
        "--observation-json",
        '{"target":"api.local","tls_version":"TLSv1.3"}',
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {"target": "api.local", "tls_version": "TLSv1.3"}
    assert json.loads(capsys.readouterr().out) == [{"risk_score": 0.25, "target": "api.local", "warnings": []}]


def test_tls_target_outputs_json(monkeypatch, capsys):
    seen = {}

    def fake_inspect_tls_targets(
        targets,
        ports=None,
        server_name=None,
        ip_version="auto",
        timeout=3.0,
        max_targets=32,
        max_ports=32,
        aggressive=False,
    ):
        seen.update({
            "targets": targets,
            "ports": ports,
            "server_name": server_name,
            "ip_version": ip_version,
            "timeout": timeout,
            "max_targets": max_targets,
            "max_ports": max_ports,
            "aggressive": aggressive,
        })
        return [{"target": "127.0.0.1", "port": 8443, "tls_version": {"version": "TLSv1.3"}}]

    monkeypatch.setattr(cli_main, "inspect_tls_targets", fake_inspect_tls_targets)

    result = cli_main.main([
        "tls",
        "--target",
        "127.0.0.1",
        "--ports",
        "443,8443",
        "--server-name",
        "localhost",
        "--ip-version",
        "4",
        "--timeout",
        "0.5",
        "--max-targets",
        "4",
        "--max-ports",
        "8",
        "--aggressive",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "aggressive": True,
        "ip_version": "4",
        "max_ports": 8,
        "max_targets": 4,
        "ports": [443, 8443],
        "server_name": "localhost",
        "targets": "127.0.0.1",
        "timeout": 0.5,
    }
    assert json.loads(capsys.readouterr().out) == [
        {"port": 8443, "target": "127.0.0.1", "tls_version": {"version": "TLSv1.3"}}
    ]


def test_scan_rejects_tcp_and_udp_targets_together(capsys):
    result = cli_main.main(["scan", "--target", "127.0.0.1", "--udp-target", "127.0.0.1"])

    assert result == 1
    assert "use either --target or --udp-target" in capsys.readouterr().err


def test_scan_udp_target_reports_validation_errors(monkeypatch, capsys):
    monkeypatch.setattr(
        cli_main,
        "scan_udp_target",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad target")),
    )

    result = cli_main.main(["scan", "--udp-target", "bad", "--output", "json"])

    assert result == 1
    assert "UDP scan error: bad target" in capsys.readouterr().err


def test_stack_builds_run_stack_command(monkeypatch):
    calls = {}

    def fake_stack_main(args):
        calls["args"] = args
        return 0

    monkeypatch.setattr(cli_main.stack_launcher, "main", fake_stack_main)

    result = cli_main.main([
        "stack",
        "--orchestrator-config",
        "orch.json",
        "--master-config",
        "master.json",
        "--worker-config",
        "worker.json",
        "--no-dashboard",
        "--verbose",
        "--restart-limit",
        "1",
        "--worker-args",
        "--continuous",
        "--log-level",
        "DEBUG",
    ])

    assert result == 0
    assert "--orchestrator-config" in calls["args"]
    assert "orch.json" in calls["args"]
    assert "--no-dashboard" in calls["args"]
    assert "--verbose" in calls["args"]
    assert "--restart-limit" in calls["args"]
    assert "1" in calls["args"]
    assert calls["args"][-3:] == ["--continuous", "--log-level", "DEBUG"]


def test_health_uses_configured_endpoint(monkeypatch, capsys):
    seen = {}

    def fake_get_json(url, token, endpoint):
        seen.update({"url": url, "token": token, "endpoint": endpoint})
        return {"status": "ok"}

    monkeypatch.setattr(cli_main, "_get_json", fake_get_json)

    result = cli_main.main(["health", "--url", "http://example.local", "--token", "abc"])

    assert result == 0
    assert seen == {"url": "http://example.local", "token": "abc", "endpoint": "/healthz"}
    assert json.loads(capsys.readouterr().out) == {"status": "ok"}


def test_logs_exports_archive(monkeypatch, tmp_path, capsys):
    archive = tmp_path / "bundle.zip"
    seen = {}

    def fake_export_logs(output_dir=None, include_state=True):
        seen.update({"output_dir": output_dir, "include_state": include_state})
        return archive

    monkeypatch.setattr(cli_main, "export_logs", fake_export_logs)

    result = cli_main.main(["logs", "--output-dir", str(tmp_path), "--no-state"])

    assert result == 0
    assert seen == {"output_dir": str(tmp_path), "include_state": False}
    assert str(archive) in capsys.readouterr().out


def test_logs_filters_audit_events(monkeypatch, capsys):
    monkeypatch.setattr(
        cli_main,
        "filter_audit_events",
        lambda node_id=None, event_type=None, limit=None: [
            {"node_id": node_id, "event_type": event_type, "limit": limit}
        ],
    )

    result = cli_main.main([
        "logs",
        "--filter-node",
        "worker-1",
        "--filter-event-type",
        "command_event",
        "--tail",
        "5",
    ])

    assert result == 0
    assert json.loads(capsys.readouterr().out) == [
        {"event_type": "command_event", "limit": 5, "node_id": "worker-1"}
    ]


def test_tui_sets_environment_and_runs(monkeypatch):
    ran = {}

    def fake_run():
        ran["value"] = True

    import gui.app

    monkeypatch.setattr(gui.app, "run", fake_run)

    result = cli_main.main(["tui", "--url", "http://127.0.0.1:9100", "--token", "token"])

    assert result == 0
    assert ran["value"] is True


def test_setup_outputs_runtime_json(monkeypatch, capsys):
    monkeypatch.setattr(
        cli_main,
        "initialize_runtime",
        lambda force=False: {
            "paths": {
                "app_root": "/tmp/app",
                "data_dir": "/tmp/app/data",
                "log_dir": "/tmp/app/logs",
                "settings_file": "/tmp/app/data/settings.json",
                "export_dir": "/tmp/app/exports",
            },
            "settings_file_created": True,
            "settings": {"remediation_mode": "prompt"},
            "next_steps": ["portmap doctor"],
        },
    )

    result = cli_main.main(["setup", "--output", "json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["settings_file_created"] is True
    assert payload["next_steps"] == ["portmap doctor"]


def test_doctor_reports_diagnostics(monkeypatch, capsys):
    monkeypatch.setattr(
        cli_main,
        "packaging_diagnostics",
        lambda: {
            "platform": {
                "system": "Linux",
                "machine": "aarch64",
                "level": "supported",
                "notes": "Linux ARM supported",
            },
            "runtime_paths": {"app_root": "/tmp/app"},
            "service_manager": "systemd",
            "checks": [{"name": "python_version", "ok": True, "detail": "3.11.5"}],
            "ok": True,
        },
    )

    result = cli_main.main(["doctor"])

    assert result == 0
    output = capsys.readouterr().out
    assert "Linux aarch64 (supported)" in output
    assert "systemd" in output
    assert "ok: python_version" in output


def test_network_outputs_posture_json(monkeypatch, capsys):
    monkeypatch.setattr(
        cli_main,
        "assess_network_posture",
        lambda: {
            "advisory_only": True,
            "automatic_changes": False,
            "gateway": {"gateway_ip": "203.0.113.1"},
            "exposed_services": [],
            "recommendations": [],
        },
    )

    result = cli_main.main(["network", "--output", "json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["advisory_only"] is True
    assert payload["automatic_changes"] is False


def test_discover_outputs_asset_inventory_json(monkeypatch, capsys):
    seen = {}

    def fake_inventory_network_assets(
        ranges,
        include_local_networks=False,
        methods=None,
        tcp_ports=None,
        ip_version="auto",
        timeout=1.0,
        max_targets=256,
        aggressive=False,
    ):
        seen.update({
            "ranges": ranges,
            "include_local_networks": include_local_networks,
            "methods": methods,
            "tcp_ports": tcp_ports,
            "ip_version": ip_version,
            "timeout": timeout,
            "max_targets": max_targets,
            "aggressive": aggressive,
        })
        return [{"host": "203.0.113.10", "status": "reachable"}]

    monkeypatch.setattr(cli_main, "inventory_network_assets", fake_inventory_network_assets)
    monkeypatch.setattr(
        cli_main,
        "asset_telemetry_events",
        lambda assets, node_id=None: [{"type": "asset_inventory", "node_id": node_id, "asset": assets[0]}],
    )

    result = cli_main.main([
        "discover",
        "--range",
        "203.0.113.0/30",
        "--method",
        "arp",
        "--method",
        "tcp",
        "--tcp-ports",
        "22,443",
        "--ip-version",
        "4",
        "--timeout",
        "0.2",
        "--max-targets",
        "32",
        "--node-id",
        "worker-1",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "aggressive": False,
        "include_local_networks": False,
        "ip_version": "4",
        "max_targets": 32,
        "methods": ["arp", "tcp"],
        "ranges": ["203.0.113.0/30"],
        "tcp_ports": [22, 443],
        "timeout": 0.2,
    }
    payload = json.loads(capsys.readouterr().out)
    assert payload["assets"] == [{"host": "203.0.113.10", "status": "reachable"}]
    assert payload["telemetry"][0]["node_id"] == "worker-1"


def test_discover_defaults_to_local_networks_when_no_range(monkeypatch, capsys):
    seen = {}

    def fake_inventory_network_assets(ranges, include_local_networks=False, **kwargs):
        seen.update({"ranges": ranges, "include_local_networks": include_local_networks})
        return []

    monkeypatch.setattr(cli_main, "inventory_network_assets", fake_inventory_network_assets)
    monkeypatch.setattr(cli_main, "asset_telemetry_events", lambda assets, node_id=None: [])

    result = cli_main.main(["discover", "--output", "json"])

    assert result == 0
    assert seen == {"ranges": None, "include_local_networks": True}
    assert json.loads(capsys.readouterr().out) == {"assets": [], "telemetry": []}


def test_discover_reports_validation_errors(monkeypatch, capsys):
    monkeypatch.setattr(
        cli_main,
        "inventory_network_assets",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad range")),
    )

    result = cli_main.main(["discover", "--range", "bad"])

    assert result == 1
    assert "Discovery error: bad range" in capsys.readouterr().err


def test_services_outputs_json(monkeypatch, capsys):
    seen = {}

    def fake_enumerate_services(
        targets,
        ports=None,
        ip_version="auto",
        timeout=2.0,
        max_targets=64,
        max_ports=128,
        aggressive=False,
    ):
        seen.update({
            "targets": targets,
            "ports": ports,
            "ip_version": ip_version,
            "timeout": timeout,
            "max_targets": max_targets,
            "max_ports": max_ports,
            "aggressive": aggressive,
        })
        return [{"target": "127.0.0.1", "port": 80, "service": "HTTP"}]

    monkeypatch.setattr(cli_main, "enumerate_services", fake_enumerate_services)

    result = cli_main.main([
        "services",
        "--target",
        "127.0.0.1",
        "--ports",
        "80,443",
        "--ip-version",
        "4",
        "--timeout",
        "0.5",
        "--max-targets",
        "8",
        "--max-ports",
        "4",
        "--aggressive",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "aggressive": True,
        "ip_version": "4",
        "max_ports": 4,
        "max_targets": 8,
        "ports": [80, 443],
        "targets": "127.0.0.1",
        "timeout": 0.5,
    }
    assert json.loads(capsys.readouterr().out) == [{"port": 80, "service": "HTTP", "target": "127.0.0.1"}]


def test_services_reports_validation_errors(monkeypatch, capsys):
    monkeypatch.setattr(
        cli_main,
        "enumerate_services",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad target")),
    )

    result = cli_main.main(["services", "--target", "bad"])

    assert result == 1
    assert "Service enumeration error: bad target" in capsys.readouterr().err


def test_os_outputs_json_from_target(monkeypatch, capsys):
    seen = {}

    def fake_fingerprint_targets(
        targets,
        ports=None,
        ip_version="auto",
        timeout=2.0,
        max_targets=64,
        max_ports=128,
        aggressive=False,
        ttl=None,
        tcp_window=None,
        tcp_options=None,
    ):
        seen.update({
            "targets": targets,
            "ports": ports,
            "ip_version": ip_version,
            "timeout": timeout,
            "max_targets": max_targets,
            "max_ports": max_ports,
            "aggressive": aggressive,
            "ttl": ttl,
            "tcp_window": tcp_window,
            "tcp_options": tcp_options,
        })
        return [{"target": "127.0.0.1", "probable_os": "Linux", "confidence": 0.7}]

    monkeypatch.setattr(cli_main, "fingerprint_targets", fake_fingerprint_targets)

    result = cli_main.main([
        "os",
        "--target",
        "127.0.0.1",
        "--ports",
        "22,80",
        "--ip-version",
        "4",
        "--timeout",
        "0.5",
        "--max-targets",
        "8",
        "--max-ports",
        "4",
        "--aggressive",
        "--ttl",
        "64",
        "--tcp-window",
        "29200",
        "--tcp-options",
        "mss,sack",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "aggressive": True,
        "ip_version": "4",
        "max_ports": 4,
        "max_targets": 8,
        "ports": [22, 80],
        "targets": "127.0.0.1",
        "tcp_options": "mss,sack",
        "tcp_window": 29200,
        "timeout": 0.5,
        "ttl": 64,
    }
    assert json.loads(capsys.readouterr().out) == [
        {"confidence": 0.7, "probable_os": "Linux", "target": "127.0.0.1"}
    ]


def test_os_outputs_json_from_passive_observation(monkeypatch, capsys):
    seen = {}

    def fake_fingerprint_observation(observation):
        seen.update(observation)
        return {"target": observation["target"], "probable_os": "Windows"}

    monkeypatch.setattr(cli_main, "fingerprint_observation", fake_fingerprint_observation)

    result = cli_main.main([
        "os",
        "--observation-json",
        '{"target":"host1","ttl":128}',
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {"target": "host1", "ttl": 128}
    assert json.loads(capsys.readouterr().out) == [{"probable_os": "Windows", "target": "host1"}]


def test_os_requires_target_or_observation(capsys):
    result = cli_main.main(["os"])

    assert result == 1
    assert "--target is required" in capsys.readouterr().err


def test_fast_scan_outputs_json(monkeypatch, capsys):
    seen = {}

    def fake_fast_scan_targets(
        targets,
        ports,
        ip_version="auto",
        timeout=1.0,
        concurrency=64,
        rate_per_second=128.0,
        max_targets=256,
        max_ports=1024,
        aggressive=False,
    ):
        seen.update({
            "targets": targets,
            "ports": ports,
            "ip_version": ip_version,
            "timeout": timeout,
            "concurrency": concurrency,
            "rate_per_second": rate_per_second,
            "max_targets": max_targets,
            "max_ports": max_ports,
            "aggressive": aggressive,
        })
        return [{"target": "127.0.0.1", "port": 80, "tcp_state": "closed"}]

    monkeypatch.setattr(cli_main, "fast_scan_targets", fake_fast_scan_targets)

    result = cli_main.main([
        "fast-scan",
        "--target",
        "127.0.0.1",
        "--ports",
        "80,443",
        "--ip-version",
        "4",
        "--timeout",
        "0.25",
        "--concurrency",
        "8",
        "--rate",
        "16",
        "--max-targets",
        "4",
        "--max-ports",
        "8",
        "--aggressive",
        "--output",
        "json",
    ])

    assert result == 0
    assert seen == {
        "aggressive": True,
        "concurrency": 8,
        "ip_version": "4",
        "max_ports": 8,
        "max_targets": 4,
        "ports": [80, 443],
        "rate_per_second": 16.0,
        "targets": "127.0.0.1",
        "timeout": 0.25,
    }
    assert json.loads(capsys.readouterr().out) == [
        {"port": 80, "target": "127.0.0.1", "tcp_state": "closed"}
    ]


def test_fast_scan_reports_validation_errors(monkeypatch, capsys):
    monkeypatch.setattr(
        cli_main,
        "fast_scan_targets",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("too much")),
    )

    result = cli_main.main(["fast-scan", "--target", "127.0.0.1"])

    assert result == 1
    assert "Fast scan error: too much" in capsys.readouterr().err
