import json
import re

from cli import main as cli_main


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


def test_runtime_status_outputs_json(capsys):
    result = cli_main.main(["runtime", "status", "--output", "json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["profile_summary"]["profile_id"] == "runtime-default"
    assert payload["session_summary"]["mode"] == "dry-run"
    assert payload["automatic_changes"] is False


def test_runtime_status_outputs_table(capsys):
    result = cli_main.main(["runtime", "status", "--output", "table"])

    assert result == 0
    assert "Runtime Status" in capsys.readouterr().out


def test_runtime_run_dry_run_outputs_pipeline_summary(capsys):
    result = cli_main.main(
        [
            "runtime",
            "run",
            "--assets-json",
            '[{"asset_id":"asset-alpha","label":"Asset Alpha"}]',
            "--services-json",
            '[{"service_id":"service-alpha","asset_id":"asset-alpha","service":"https","port":443}]',
            "--output",
            "json",
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["runtime_command"] == "run"
    assert payload["dry_run"] is True
    assert payload["write_local"] is False
    assert payload["pipeline_result"]["summary"]["storage_write_count"] == 0
    assert payload["pipeline_result"]["summary"]["event_count"] == 2


def test_runtime_run_write_local_requires_db_path(capsys):
    result = cli_main.main(["runtime", "run", "--write-local", "--output", "json"])

    assert result == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "error"
    assert "--db-path is required" in payload["error"]


def test_runtime_run_write_local_uses_explicit_db_path(capsys, tmp_path):
    result = cli_main.main(
        [
            "runtime",
            "run",
            "--assets-json",
            '[{"asset_id":"asset-alpha","label":"Asset Alpha"}]',
            "--services-json",
            '[{"service_id":"service-alpha","asset_id":"asset-alpha","service":"https","port":443}]',
            "--write-local",
            "--db-path",
            str(tmp_path / "runtime.db"),
            "--output",
            "json",
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["dry_run"] is False
    assert payload["write_local"] is True
    assert payload["pipeline_result"]["summary"]["storage_write_count"] > 0


def test_runtime_recover_outputs_recommendations(capsys):
    checkpoint = {
        "record_type": "runtime_checkpoint",
        "record_version": 1,
        "checkpoint_id": "checkpoint-sample",
        "status": "incomplete",
        "created_at": "2026-01-01T00:00:00+00:00",
        "session_summary": {"session_id": "session-sample", "status": "running"},
        "profile_summary": {},
        "pipeline_result": {},
        "runtime_summary": {},
        "storage_summary": {},
        "review_summary": {"review_count": 1, "by_status": {"open": 1}, "approval_required_count": 1},
        "export_summary": {},
        "metadata": {},
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }

    result = cli_main.main(["runtime", "recover", "--checkpoint-json", json.dumps(checkpoint), "--output", "json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["runtime_command"] == "recover"
    assert payload["status"] == "needs_review"
    assert payload["recommendation_count"] >= 1


def test_runtime_reviews_summarizes_review_records(capsys):
    review = {
        "review_id": "review-sample",
        "policy_id": "policy-sample",
        "source_ref": "finding:finding-sample",
        "category": "policy_review_required",
        "severity": "high",
        "title": "Sample Review",
        "summary": "Sample review summary.",
        "status": "open",
        "approval_required": True,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }

    result = cli_main.main(["runtime", "reviews", "--reviews-json", json.dumps([review]), "--output", "json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["review_count"] == 1
    assert payload["summary"]["approval_required_count"] == 1
    assert payload["items"][0]["review_id"] == "review-sample"


def test_runtime_export_builds_bundle(capsys):
    result = cli_main.main(
        [
            "runtime",
            "export",
            "--findings-json",
            '[{"finding_id":"finding-sample","finding_type":"sample","severity":"medium"}]',
            "--runtime-summary-json",
            '{"status":"ok","session_id":"session-sample"}',
            "--output",
            "json",
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["runtime_command"] == "export"
    assert payload["bundle"]["manifest"]["bundle_type"] == "operational_evidence_export"
    assert payload["write_result"] is None


def test_runtime_export_writes_to_operator_path(capsys, tmp_path):
    output_path = tmp_path / "bundle.json"

    result = cli_main.main(
        [
            "runtime",
            "export",
            "--runtime-summary-json",
            '{"status":"ok","session_id":"session-sample"}',
            "--output-path",
            str(output_path),
            "--output",
            "json",
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["write_result"]["status"] == "written"
    assert payload["write_result"]["path_stored"] is False
    assert output_path.exists()


def test_runtime_cli_output_has_no_private_identifiers(capsys):
    result = cli_main.main(["runtime", "status", "--output", "json"])

    assert result == 0
    output = capsys.readouterr().out
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(output)
