"""Application logging: a rotating file log in the per-user data directory, plus
stderr when a console is available. Used for production diagnostics."""
from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

APP_DIR_NAME = "iOSCrackabilityAnalyzer"
_configured = False


def data_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    path = os.path.join(base, APP_DIR_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def log_path() -> str:
    logs = os.path.join(data_dir(), "logs")
    os.makedirs(logs, exist_ok=True)
    return os.path.join(logs, "app.log")


def setup_logging(level: int = logging.INFO) -> str:
    """Configure root logging once. Returns the log file path."""
    global _configured
    path = log_path()
    if _configured:
        return path

    handlers: list[logging.Handler] = []
    try:
        handlers.append(RotatingFileHandler(
            path, maxBytes=1_000_000, backupCount=3, encoding="utf-8"))
    except Exception:
        pass
    if sys.stderr is not None:
        handlers.append(logging.StreamHandler(sys.stderr))

    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-7s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
    _configured = True
    logging.getLogger(__name__).info("logging initialised -> %s", path)
    return path
