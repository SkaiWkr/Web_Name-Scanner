"""Configuration loading helpers for SiteGuard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_config(path: str | Path = "config.yaml") -> dict[str, Any]:
    """Load SiteGuard configuration from a YAML file."""
    config_path = Path(path)
    if not config_path.exists():
        package_default = Path(__file__).resolve().parent.parent / "config.yaml"
        config_path = package_default
    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data


def get_subdomain_words(config: dict[str, Any]) -> list[str]:
    """Return configured subdomain brute-force words."""
    words = config.get("subdomains", [])
    return [str(word).strip().lower() for word in words if str(word).strip()]
