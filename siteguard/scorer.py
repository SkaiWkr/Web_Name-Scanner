"""Fraud-likelihood scoring for SiteGuard findings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from siteguard.models import Finding, ScoredFinding


def levenshtein_distance(left: str, right: str) -> int:
    """Compute Levenshtein edit distance without network or optional runtime dependencies."""
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insertion = current[j - 1] + 1
            deletion = previous[j] + 1
            substitution = previous[j - 1] + (left_char != right_char)
            current.append(min(insertion, deletion, substitution))
        previous = current
    return previous[-1]


def _weighted(value: float, weight: float) -> float:
    """Return a normalized 0-100 value scaled by a component weight."""
    return max(0.0, min(100.0, value)) * weight / 100.0


def levenshtein_similarity_score(name: str, hostname: str) -> float:
    """Score how visually similar the hostname label is to the protected name."""
    protected = "".join(ch for ch in name.lower() if ch.isalnum())
    label = hostname.split(".")[0].replace("-", "").lower()
    if not protected or not label:
        return 0.0
    dist = levenshtein_distance(protected, label)
    max_len = max(len(protected), len(label))
    return (1.0 - min(dist / max_len, 1.0)) * 100.0


def domain_age_score(creation_date: datetime | None, config: dict[str, Any]) -> float:
    """Score risk from domain age, with newer or missing domains scoring higher."""
    scoring = config.get("scoring", {})
    missing = float(scoring.get("missing_data_score", 50))
    if creation_date is None:
        return missing
    now = datetime.now(timezone.utc)
    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)
    age_days = max(0, (now - creation_date).days)
    thresholds = scoring.get("domain_age_days", {})
    if age_days <= int(thresholds.get("very_new", 30)):
        return 100.0
    if age_days <= int(thresholds.get("new", 180)):
        return 75.0
    if age_days <= int(thresholds.get("established", 365)):
        return 40.0
    return 10.0


def content_presence_score(name: str, finding: Finding, config: dict[str, Any]) -> float:
    """Score whether protected keywords appear in collected title or description."""
    haystack = " ".join(filter(None, [finding.page_title, finding.meta_description])).lower()
    needle = name.lower()
    if needle and needle in haystack:
        return float(config.get("scoring", {}).get("content_keyword_score", 100))
    return 0.0


def ssl_issuer_score(finding: Finding, config: dict[str, Any]) -> float:
    """Score TLS issuer reputation, where unknown or unusual issuers are riskier."""
    scoring = config.get("scoring", {})
    if not finding.ssl_issuer:
        return float(scoring.get("missing_data_score", 50))
    trusted = [issuer.lower() for issuer in scoring.get("ssl_trusted_issuers", [])]
    issuer = finding.ssl_issuer.lower()
    return 20.0 if any(name in issuer for name in trusted) else 80.0


def discovery_source_score(finding: Finding, config: dict[str, Any]) -> float:
    """Score risk based on the source that discovered the finding."""
    scores = config.get("scoring", {}).get("discovery_source_scores", {})
    source = finding.source
    if source == "cert_transparency_unrelated" and finding.related_to_target_domain:
        source = "cert_transparency_related"
    return float(scores.get(source, config.get("scoring", {}).get("missing_data_score", 50)))


def score_finding(name: str, finding: Finding, config: dict[str, Any]) -> ScoredFinding:
    """Compute a 0-100 fraud-likelihood score and component reasons for a finding."""
    weights = config.get("scoring", {}).get("weights", {})
    components = {
        "levenshtein_similarity": levenshtein_similarity_score(name, finding.hostname),
        "domain_age": domain_age_score(finding.creation_date, config),
        "brand_content_presence": content_presence_score(name, finding, config),
        "ssl_issuer_reputation": ssl_issuer_score(finding, config),
        "discovery_source": discovery_source_score(finding, config),
    }
    total = sum(_weighted(value, float(weights.get(key, 0))) for key, value in components.items())
    reasons = [f"{key}={value:.1f} weighted by {weights.get(key, 0)}" for key, value in components.items()]
    return ScoredFinding(finding=finding, score=int(round(max(0.0, min(100.0, total)))), reasons=reasons, components=components)


def score_findings(name: str, findings: list[Finding], config: dict[str, Any]) -> list[ScoredFinding]:
    """Score and sort findings by descending fraud-likelihood."""
    return sorted((score_finding(name, finding, config) for finding in findings), key=lambda item: item.score, reverse=True)
