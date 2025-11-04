import logging
from pathlib import Path

from core_engine import logging_utils


def test_configure_logger_uses_rotation(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    data_dir = tmp_path / "data"

    monkeypatch.setattr("core_engine.config_loader.LOG_DIR", log_dir)
    monkeypatch.setattr("core_engine.config_loader.DATA_DIR", data_dir)
    monkeypatch.setattr("core_engine.logging_utils.LOG_DIR", log_dir)

    logger = logging_utils.configure_logger(
        "test.logger",
        "test.log",
        max_bytes=1024,
        backup_count=2,
        console=False,
    )

    try:
        rotating_handlers = [h for h in logger.handlers if h.__class__.__name__ == "RotatingFileHandler"]
        assert rotating_handlers, "Expected RotatingFileHandler in logger handlers"
        log_path = log_dir / "test.log"
        assert log_path.exists()
    finally:
        for handler in logger.handlers:
            handler.close()
        logger.handlers.clear()


def test_export_logs_creates_archive(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    data_dir = tmp_path / "data"
    log_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    sample_log = log_dir / "worker.log"
    sample_log.write_text("sample log line")
    state_file = data_dir / "connection_state.json"
    state_file.write_text("{}")

    monkeypatch.setattr("core_engine.config_loader.LOG_DIR", log_dir)
    monkeypatch.setattr("core_engine.config_loader.DATA_DIR", data_dir)
    monkeypatch.setattr("core_engine.log_exporter.LOG_DIR", log_dir)
    monkeypatch.setattr("core_engine.log_exporter.DATA_DIR", data_dir)

    from core_engine.log_exporter import export_logs

    archive_path = export_logs(output_dir=tmp_path / "archives")
    assert archive_path.exists()

    import zipfile

    with zipfile.ZipFile(archive_path, "r") as zf:
        names = zf.namelist()
        assert any(name.endswith("worker.log") for name in names)
        assert any(name.endswith("connection_state.json") for name in names)
