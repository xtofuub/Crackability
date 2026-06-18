"""Tiny persistent settings store (JSON in the per-user data dir)."""
from __future__ import annotations

import json
import os
from typing import Any

from .logging_setup import data_dir

_PATH = os.path.join(data_dir(), "settings.json")


def load() -> dict:
    try:
        with open(_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def get(key: str, default: Any = None) -> Any:
    return load().get(key, default)


def set(key: str, value: Any) -> None:  # noqa: A001 - small deliberate API
    data = load()
    data[key] = value
    try:
        with open(_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except Exception:
        pass
