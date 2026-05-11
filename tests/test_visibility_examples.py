import json
import re
from pathlib import Path

from cli import main as cli_main
from core_engine.visibility import build_visibility_report


EXAMPLE_DIR = Path("docs/examples")
EXAMPLE_FILES = {
    "assets": EXAMPLE_DIR / "assets_sample.json",
    "services": EXAMPLE_DIR / "services_sample.json",
    "flows": EXAMPLE_DIR / "flows_sample.json",
    "policy": EXAMPLE_DIR / "policy_sample.json",
}

FORBIDDEN_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"127\."),
    re.compile(r"::1"),
    re.compile(r"ng99", re.IGNORECASE),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}"),
    re.compile(r"\b[a-z0-9-]+\.(com|net|org|io|local|lan)\b", re.IGNORECASE),
]


def _load(name):
    with open(EXAMPLE_FILES[name], "r", encoding="utf-8") as handle:
        return json.load(handle)


def test_visibility_example_json_files_load_and_have_expected_shape():
    assets = _load("assets")
    services = _load("services")
    flows = _load("flows")
    policy = _load("policy")

    assert isinstance(assets["assets"], list)
    assert len(assets["assets"]) >= 3
    assert all(row["asset_type"] == "network_asset" for row in assets["assets"])
    assert isinstance(services["services"], list)
    assert len(services["services"]) >= 4
    assert all(isinstance(row["port"], int) for row in services["services"])
    assert isinstance(flows["flows"], list)
    assert {app for row in flows["flows"] for app in row["application_protocols"]} >= {"HTTP", "HTTPS"}
    assert flows["raw_payload_stored"] is False
    assert policy["require_approval"] is True
    assert policy["dry_run"] is True
    assert policy["administrator_controlled"] is True
    assert policy["automatic_changes"] is False


def test_visibility_examples_generate_advisory_findings():
    assets = _load("assets")["assets"]
    services = _load("services")["services"]
    flows = _load("flows")
    policy = _load("policy")

    report = build_visibility_report(
        assets=assets,
        services=services,
        flows=flows,
        policy=policy,
    )

    finding_types = {finding["type"] for finding in report["findings"]}
    assert report["automatic_changes"] is False
    assert report["administrator_controlled"] is True
    assert report["raw_payload_stored"] is False
    assert finding_types >= {
        "asset_unknown",
        "management_service_open",
        "database_service_open",
        "unknown_open_service",
        "flow_security_findings",
        "high_payload_volume",
    }
    assert report["response_workflows"]
    assert all(workflow["dry_run"] for workflow in report["response_workflows"])
    assert all(workflow["approval_required"] for workflow in report["response_workflows"])


def test_visibility_cli_accepts_sanitized_example_file_paths(capsys):
    result = cli_main.main([
        "visibility",
        "--assets-json",
        str(EXAMPLE_FILES["assets"]),
        "--services-json",
        str(EXAMPLE_FILES["services"]),
        "--flows-json",
        str(EXAMPLE_FILES["flows"]),
        "--policy-json",
        str(EXAMPLE_FILES["policy"]),
        "--output",
        "json",
    ])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["summary"]["asset_count"] >= 3
    assert payload["summary"]["service_count"] >= 4
    assert payload["summary"]["flow_count"] >= 2
    assert payload["automatic_changes"] is False


def test_visibility_examples_do_not_contain_local_or_private_identifiers():
    for path in EXAMPLE_FILES.values():
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_PATTERNS:
            assert not pattern.search(text), f"{path} matched forbidden pattern {pattern.pattern}"
