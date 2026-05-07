from pathlib import Path

from core_engine import runtime_setup


def test_platform_support_status_marks_primary_platforms():
    assert runtime_setup.platform_support_status("Darwin", "arm64")["level"] == "supported"
    assert runtime_setup.platform_support_status("Linux", "x86_64")["level"] == "supported"

    pi = runtime_setup.platform_support_status("Linux", "aarch64")
    assert pi["level"] == "supported"
    assert "Raspberry Pi OS" in pi["notes"]

    windows = runtime_setup.platform_support_status("Windows", "AMD64")
    assert windows["level"] == "experimental"


def test_initialize_runtime_creates_settings_and_export_dir(tmp_path, monkeypatch):
    app_root = tmp_path / ".portmap-ai"
    data_dir = app_root / "data"
    log_dir = app_root / "logs"
    settings_file = data_dir / "settings.json"
    export_dir = tmp_path / "exports"

    monkeypatch.setattr(runtime_setup, "APP_ROOT", app_root)
    monkeypatch.setattr(runtime_setup, "DATA_DIR", data_dir)
    monkeypatch.setattr(runtime_setup, "LOG_DIR", log_dir)
    monkeypatch.setattr(runtime_setup, "DEFAULT_SETTINGS_FILE", settings_file)
    monkeypatch.setattr("core_engine.config_loader.DEFAULT_SETTINGS_FILE", settings_file)
    monkeypatch.setattr("core_engine.config_loader.DATA_DIR", data_dir)
    monkeypatch.setattr("core_engine.config_loader.LOG_DIR", log_dir)
    monkeypatch.setenv("PORTMAP_EXPORT_DIR", str(export_dir))

    result = runtime_setup.initialize_runtime()

    assert data_dir.exists()
    assert log_dir.exists()
    assert settings_file.exists()
    assert export_dir.exists()
    assert result["settings_file_created"] is True
    assert result["settings"]["remediation_mode"] == "prompt"


def test_packaging_diagnostics_reports_configs(monkeypatch):
    monkeypatch.setattr(runtime_setup, "DEFAULT_ORCHESTRATOR_CFG", "core_engine/default_configs/orchestrator.json")
    monkeypatch.setattr(runtime_setup, "DEFAULT_MASTER_CFG", "core_engine/default_configs/master1.json")
    monkeypatch.setattr(runtime_setup, "DEFAULT_WORKER_CFG", "core_engine/default_configs/worker_orchestrated.json")

    result = runtime_setup.packaging_diagnostics()

    check_names = {check["name"] for check in result["checks"]}
    assert "python_version" in check_names
    assert "orchestrator_config" in check_names
    assert "master_config" in check_names
    assert "worker_config" in check_names
    assert result["platform"]["level"] in {"supported", "experimental", "unknown"}
