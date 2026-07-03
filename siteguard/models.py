"""Shared data models for SiteGuard."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Candidate:
    """A discovered hostname or domain candidate and its discovery provenance."""

    hostname: str
    source: str
    parent_domain: str | None = None
    related_to_target_domain: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    """Enriched information about a candidate web property."""

    hostname: str
    source: str
    resolved_ips: list[str] = field(default_factory=list)
    registrar: str | None = None
    creation_date: datetime | None = None
    ssl_issuer: str | None = None
    is_live: bool = False
    url: str | None = None
    page_title: str | None = None
    meta_description: str | None = None
    related_to_target_domain: bool = True
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScoredFinding:
    """A finding with fraud-likelihood scoring details."""

    finding: Finding
    score: int
    reasons: list[str]
    components: dict[str, float]
