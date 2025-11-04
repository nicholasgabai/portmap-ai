# core_engine/logging_utils.py

"""
Central logging helpers for PortMap-AI components.
Creates scoped loggers that write both to stdout and the ~/.portmap-ai/logs directory.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config_loader import LOG_DIR, ensure_runtime_dirs

DEFAULT_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"


def configure_logger(
    name: str,
    logfile: str,
    level: int = logging.INFO,
    console: bool = True,
    fmt: str = DEFAULT_FORMAT,
    max_bytes: int | None = 5 * 1024 * 1024,
    backup_count: int = 5,
) -> logging.Logger:
    """
    Return a configured logger writing to ~/.portmap-ai/logs/<logfile>.
    Idempotent: repeated calls return the same configured logger.
    """
    ensure_runtime_dirs()
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    log_path = Path(LOG_DIR) / logfile

    formatter = logging.Formatter(fmt)

    log_path.parent.mkdir(parents=True, exist_ok=True)
    if max_bytes:
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
    else:
        file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if console:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    logger.propagate = False
    return logger


def update_log_level(logger: logging.Logger, level: int) -> None:
    logger.setLevel(level)
    for handler in logger.handlers:
        handler.setLevel(level)


__all__ = ["configure_logger", "update_log_level"]
