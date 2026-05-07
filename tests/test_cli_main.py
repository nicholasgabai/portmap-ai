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
            "gateway": {"gateway_ip": "192.168.1.1"},
            "exposed_services": [],
            "recommendations": [],
        },
    )

    result = cli_main.main(["network", "--output", "json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["advisory_only"] is True
    assert payload["automatic_changes"] is False
