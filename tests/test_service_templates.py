import json
import re

from core_engine.installers.service_templates import (
    build_service_template_correlation_record,
    build_service_template_dashboard_summary,
    build_service_template_event,
    build_service_template_finding,
    build_service_template_storage_record,
    build_service_template_timeline_entry,
    generate_service_templates,
    generate_systemd_unit,
    generate_windows_service_template,
    summarize_service_template_result,
    validate_service_definition,
)


PRIVATE_IDENTIFIER_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


def _definition(**overrides):
    data = {
        "service_id": "service.sample.agent",
        "name": "portmap-sample-agent",
        "display_name": "PortMap Sample Agent",
        "description": "Runs the sample local PortMap agent workflow.",
        "command": ["<runtime>", "-m", "portmap_agent", "--config", "<config-file>"],
        "working_directory": "<working-directory>",
        "environment_file": "<environment-file>",
        "user": "<service-user>",
        "metadata": {"owner": "operator-placeholder"},
    }
    data.update(overrides)
    return data


def test_service_definition_validation_accepts_placeholders():
    result = validate_service_definition(_definition())

    assert result["ok"] is True
    assert result["classification"] == "valid"
    assert result["summary"]["severity"] == "info"
    assert result["raw_payload_stored"] is False
    assert result["automatic_changes"] is False
    assert result["install_executed"] is False
    assert result["service_enabled"] is False
    assert result["service_started"] is False
    assert result["administrator_controlled"] is True


def test_invalid_service_definition_is_structured():
    result = validate_service_definition(_definition(command=[]))

    assert result["ok"] is False
    assert result["classification"] == "invalid"
    assert "command" in result["errors"][0]
    assert result["integration_hooks"]["policy_review_ready"] is True


def test_systemd_template_generation_is_deterministic():
    first = generate_systemd_unit(_definition())
    second = generate_systemd_unit(_definition())

    assert first["ok"] is True
    assert first["template_text"] == second["template_text"]
    assert "[Unit]" in first["template_text"]
    assert "ExecStart=<runtime> -m portmap_agent --config <config-file>" in first["template_text"]
    assert "WorkingDirectory=<working-directory>" in first["template_text"]
    assert "EnvironmentFile=<environment-file>" in first["template_text"]
    assert "systemctl enable" not in first["template_text"]
    assert "systemctl start" not in first["template_text"]
    assert first["automatic_changes"] is False


def test_windows_template_generation_is_deterministic():
    first = generate_windows_service_template(_definition())
    second = generate_windows_service_template(_definition())

    assert first["ok"] is True
    assert first["template_text"] == second["template_text"]
    assert "sc.exe create" in first["template_text"]
    assert "start= demand" in first["template_text"]
    assert "No service installation" in first["template_text"]
    assert "service_started" not in first["template_text"]


def test_combined_service_templates_and_unsupported_platform():
    result = generate_service_templates(_definition(), platforms=["systemd", "windows"])
    unsupported = generate_service_templates(_definition(), platforms=["systemd", "sample-os"])

    assert result["ok"] is True
    assert result["classification"] == "valid"
    assert set(result["templates"]) == {"systemd", "windows"}
    assert result["summary"]["template_count"] == 2
    assert unsupported["ok"] is False
    assert unsupported["classification"] == "unsupported"
    assert "unsupported platform sample-os" in unsupported["errors"]


def test_operator_provided_paths_are_allowed_with_review_warnings():
    result = validate_service_definition(
        _definition(
            working_directory="operator-provided-dir",
            environment_file="operator-provided-env",
        )
    )

    assert result["ok"] is True
    assert result["summary"]["warning_count"] == 2
    assert any("working_directory" in warning for warning in result["warnings"])
    assert any("environment_file" in warning for warning in result["warnings"])


def test_service_template_operational_records():
    result = generate_service_templates(_definition())

    summary = summarize_service_template_result(result)
    event = build_service_template_event(result)
    finding = build_service_template_finding(result)
    storage = build_service_template_storage_record(result)
    timeline = build_service_template_timeline_entry(result)
    dashboard = build_service_template_dashboard_summary(result)
    correlation = build_service_template_correlation_record(result)

    assert summary["classification"] == "valid"
    assert event["event_type"] == "system_notice"
    assert event["metadata"]["diagnostic_type"] == "service_lifecycle_template"
    assert finding["category"] == "service_lifecycle_template"
    assert storage["payload"]["template_summaries"]["systemd"]["line_count"] > 0
    assert timeline["category"] == "service_lifecycle_template"
    assert dashboard["panel"] == "service_lifecycle_template"
    assert dashboard["install_executed"] is False
    assert correlation["score"] == 0.0
    assert all(row["raw_payload_stored"] is False for row in [event, finding, storage, timeline, dashboard, correlation])


def test_invalid_template_result_becomes_policy_review_event():
    result = generate_service_templates(_definition(command=[]))
    event = build_service_template_event(result)
    finding = build_service_template_finding(result)
    correlation = build_service_template_correlation_record(result)

    assert event["event_type"] == "policy_review_required"
    assert finding["recommended_review"] is True
    assert correlation["score"] > 0


def test_service_template_outputs_do_not_contain_private_identifiers():
    result = generate_service_templates(_definition())
    records = [
        result,
        build_service_template_event(result),
        build_service_template_storage_record(result),
        build_service_template_dashboard_summary(result),
    ]
    payload = json.dumps(records, sort_keys=True)

    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(payload)
