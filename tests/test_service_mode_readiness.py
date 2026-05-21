import json
import re

from core_engine.policy import PersistentReviewStore, build_review_record, create_policy
from core_engine.runtime import (
    build_manual_operator_checklist,
    build_service_command_previews,
    build_service_mode_definition,
    build_service_mode_preflight,
    build_service_mode_readiness,
    build_service_template_compatibility,
    summarize_service_mode_readiness,
)
from core_engine.storage.repositories import LocalStorageRepository
from core_engine.storage.sqlite_store import SQLiteStore


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


def _repository(tmp_path):
    return LocalStorageRepository(SQLiteStore(tmp_path / "service-mode.db"))


def _review_store(repository):
    store = PersistentReviewStore(repository)
    policy = create_policy(
        policy_id="policy-service-preview",
        name="Service Preview Review Policy",
        description="Review service-preview readiness records.",
        now="2026-01-01T00:00:00+00:00",
    )
    store.add_review(
        build_review_record(
            policy=policy,
            source_ref="finding:service-preview",
            category="service_mode_readiness",
            severity="medium",
            title="Service Preview Review",
            summary="Review dry-run service readiness before manual installation.",
            now="2026-01-01T00:00:00+00:00",
        )
    )
    return store


def test_service_mode_definition_uses_sanitized_placeholders():
    definition = build_service_mode_definition()

    assert definition["service_id"] == "service.portmap.runtime"
    assert definition["command"] == ["<portmap-command>", "runtime", "status", "--output", "json"]
    assert definition["working_directory"] == "<portmap-app-dir>"
    assert definition["environment_file"] == "<portmap-env-file>"


def test_template_compatibility_generates_preview_only_templates():
    compatibility = build_service_template_compatibility(platforms=["systemd", "windows"])
    previews = build_service_command_previews(compatibility)

    assert compatibility["compatible"] is True
    assert compatibility["install_executed"] is False
    assert compatibility["service_started"] is False
    assert set(previews["previews"]) == {"systemd", "windows"}
    assert "systemctl start" not in previews["previews"]["systemd"]["template_text"]
    assert "sc.exe create" in previews["previews"]["windows"]["template_text"]
    assert previews["previews"]["windows"]["service_enabled"] is False


def test_template_compatibility_reports_invalid_definitions():
    compatibility = build_service_template_compatibility(build_service_mode_definition(command=[]))

    assert compatibility["compatible"] is False
    assert compatibility["status"] == "review_required"
    assert any("command" in error for error in compatibility["errors"])


def test_service_mode_preflight_validates_profile_and_storage(tmp_path):
    repository = _repository(tmp_path)
    repository.insert_event(
        {
            "event_id": "event-service-preview",
            "event_type": "system_notice",
            "severity": "info",
            "source": "service.mode.test",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "message": "Sample service-mode event.",
        }
    )

    preflight = build_service_mode_preflight(
        repository=repository,
        generated_at="2026-01-02T00:00:00+00:00",
    )

    assert preflight["generated_at"] == "2026-01-02T00:00:00+00:00"
    assert preflight["profile_validation"]["ok"] is True
    assert any(check["name"] == "storage" for check in preflight["checks"])
    assert preflight["installation_performed"] is False


def test_service_mode_preflight_blocks_malformed_profiles():
    preflight = build_service_mode_preflight(profile={"profile_id": ""})

    assert preflight["status"] == "blocked"
    assert preflight["profile_validation"]["ok"] is False
    assert preflight["automatic_changes"] is False


def test_service_mode_readiness_combines_runtime_health_and_reviews(tmp_path):
    repository = _repository(tmp_path)
    repository.insert_finding({"finding_id": "finding-service-preview", "finding_type": "sample", "severity": "medium"})
    review_store = _review_store(repository)

    readiness = build_service_mode_readiness(
        repository=repository,
        review_store=review_store,
        scheduler={"scheduler_status": "running", "failed_job_count": 0, "executed_job_count": 1},
        event_queue=[],
        dashboard_provider={"status": "ok", "ready": True},
        edge_device=True,
        generated_at="2026-01-02T00:00:00+00:00",
    )

    assert readiness["runtime_session"]["mode"] == "service-preview"
    assert readiness["profile_summary"]["runtime_mode"] == "service-preview"
    assert readiness["health_summary"]["summary"]["check_count"] == 7
    assert readiness["template_compatibility"]["compatible"] is True
    assert readiness["summary"]["preview_count"] == 2
    assert readiness["dry_run"] is True
    assert readiness["service_enabled"] is False
    assert readiness["service_started"] is False
    assert readiness["registry_changed"] is False


def test_manual_operator_checklist_is_required_and_non_executing():
    checklist = build_manual_operator_checklist(platforms=["systemd"])

    assert any(item["step_id"] == "manual_install" for item in checklist)
    assert all(item["required"] is True for item in checklist)
    assert all(item["installation_performed"] is False for item in checklist)
    assert all(item["privilege_escalation"] is False for item in checklist)


def test_service_readiness_summary_is_operator_readable(tmp_path):
    readiness = build_service_mode_readiness(
        repository=_repository(tmp_path),
        platforms=["systemd"],
        generated_at="2026-01-02T00:00:00+00:00",
    )
    summary = summarize_service_mode_readiness(readiness)

    assert summary["readiness_id"] == readiness["readiness_id"]
    assert summary["template_count"] == 1
    assert summary["manual_checklist_count"] >= 5
    assert summary["automatic_changes"] is False


def test_service_mode_readiness_output_has_no_private_identifiers(tmp_path):
    readiness = build_service_mode_readiness(
        repository=_repository(tmp_path),
        generated_at="2026-01-02T00:00:00+00:00",
    )
    payload = json.dumps(readiness, sort_keys=True)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
