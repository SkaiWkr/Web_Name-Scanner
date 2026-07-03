"""Candidate generation using dnstwist permutations and subdomain combinations."""

from __future__ import annotations

import logging
from typing import Any

import dnstwist

from siteguard.config import get_subdomain_words
from siteguard.models import Candidate

LOGGER = logging.getLogger(__name__)
COMMON_TLDS = ("com", "net", "org", "co", "io", "info", "biz", "us")


def normalize_domain(name: str) -> str:
    """Normalize a brand/person name or domain-like input into a domain seed."""
    cleaned = name.strip().lower().replace("https://", "").replace("http://", "")
    cleaned = cleaned.split("/")[0].strip(".")
    if "." in cleaned:
        return cleaned
    label = "".join(ch for ch in cleaned if ch.isalnum() or ch == "-").strip("-")
    return f"{label}.com"


def generate_permutations(name: str, limit: int = 500) -> list[str]:
    """Generate typo, homoglyph, hyphenation, and TLD-swap domain permutations."""
    seed_domain = normalize_domain(name)
    domains: set[str] = {seed_domain}
    try:
        fuzzer = dnstwist.Fuzzer(seed_domain)
        fuzzer.generate()
        for row in fuzzer.domains:
            domain = str(row.get("domain", "")).lower().strip(".")
            if domain:
                domains.add(domain)
            if len(domains) >= limit:
                break
    except Exception as exc:  # noqa: BLE001 - generator should gracefully degrade.
        LOGGER.warning("dnstwist generation failed for %s: %s", seed_domain, exc)

    base_label = seed_domain.split(".")[0]
    for tld in COMMON_TLDS:
        domains.add(f"{base_label}.{tld}")
    return sorted(domains)[:limit]


def generate_candidates(name: str, config: dict[str, Any], limit: int = 500) -> list[Candidate]:
    """Generate domain and common subdomain candidates from permutations."""
    subdomains = get_subdomain_words(config)
    permutations = generate_permutations(name, limit=limit)
    candidates: dict[str, Candidate] = {}
    for domain in permutations:
        candidates[domain] = Candidate(hostname=domain, source="typosquat_permutation", parent_domain=domain)
        for word in subdomains:
            host = f"{word}.{domain}"
            candidates[host] = Candidate(hostname=host, source="dns_bruteforce", parent_domain=domain)
    return list(candidates.values())
