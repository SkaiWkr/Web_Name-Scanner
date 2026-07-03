"""Unit tests for SiteGuard scoring logic."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from siteguard.models import Finding
from siteguard.scorer import domain_age_score, score_finding


def _config() -> dict:
    """Return a test scoring configuration."""
    return {
        "scoring": {
            "weights": {
                "levenshtein_similarity": 25,
                "domain_age": 20,
                "brand_content_presence": 20,
                "ssl_issuer_reputation": 15,
                "discovery_source": 20,
            },
            "domain_age_days": {"very_new": 30, "new": 180, "established": 365},
            "ssl_trusted_issuers": ["Let's Encrypt", "DigiCert"],
            "discovery_source_scores": {
                "cert_transparency_unrelated": 100,
                "google_search": 85,
                "typosquat_permutation": 75,
                "dns_bruteforce": 60,
                "cert_transparency_related": 50,
            },
            "content_keyword_score": 100,
            "missing_data_score": 50,
        }
    }


def test_domain_age_scores_new_domains_high() -> None:
    """Very new domains should receive the maximum age-risk score."""
    creation_date = datetime.now(timezone.utc) - timedelta(days=3)
    assert domain_age_score(creation_date, _config()) == 100.0


def test_domain_age_scores_old_domains_low() -> None:
    """Old domains should receive a low age-risk score."""
    creation_date = datetime.now(timezone.utc) - timedelta(days=800)
    assert domain_age_score(creation_date, _config()) == 10.0


def test_score_finding_prioritizes_unrelated_ct_brand_content() -> None:
    """Unrelated CT hits with brand content and new age should score as high risk."""
    finding = Finding(
        hostname="secure-brandname-login.example.net",
        source="cert_transparency_unrelated",
        creation_date=datetime.now(timezone.utc) - timedelta(days=1),
        ssl_issuer="Unknown CA",
        page_title="BrandName account verification",
        meta_description="Verify your BrandName account now",
        related_to_target_domain=False,
    )
    scored = score_finding("BrandName", finding, _config())
    assert scored.score >= 70
    assert scored.components["discovery_source"] == 100.0


def test_score_finding_trusted_ssl_reduces_ssl_component() -> None:
    """A trusted SSL issuer should lower the issuer-risk component."""
    finding = Finding(hostname="brandname.com", source="typosquat_permutation", ssl_issuer="Let's Encrypt")
    scored = score_finding("BrandName", finding, _config())
    assert scored.components["ssl_issuer_reputation"] == 20.0
