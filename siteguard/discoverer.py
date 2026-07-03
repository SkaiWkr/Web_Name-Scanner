"""Discovery engine combining certificate transparency, DNS brute force, and optional search."""

from __future__ import annotations

import logging
import os
from typing import Any

import dns.resolver
import requests
from dotenv import load_dotenv

from siteguard.config import get_subdomain_words
from siteguard.generator import generate_candidates, normalize_domain
from siteguard.models import Candidate
from siteguard.net import RateLimiter, retry

LOGGER = logging.getLogger(__name__)


class Discoverer:
    """Discover candidate fraudulent or lookalike domains from multiple sources."""

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize the discoverer with config, rate limiters, and resolver."""
        load_dotenv()
        self.config = config
        network = config.get("network", {})
        self.timeout = float(network.get("timeout_seconds", 8))
        self.retries = int(network.get("retries", 3))
        self.backoff = float(network.get("backoff_factor", 0.8))
        rates = network.get("rate_limit_seconds", {})
        self.crt_limiter = RateLimiter(float(rates.get("crtsh", 2.0)))
        self.dns_limiter = RateLimiter(float(rates.get("dns", 0.05)))
        self.google_limiter = RateLimiter(float(rates.get("google", 1.0)))
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = self.timeout
        self.resolver.timeout = self.timeout

    def discover(self, name: str) -> list[Candidate]:
        """Run all configured discovery sources and merge candidates by hostname."""
        merged: dict[str, Candidate] = {}
        for candidate in generate_candidates(name, self.config):
            merged[candidate.hostname] = candidate
        for source_func in (self.search_crtsh, self.bruteforce_dns, self.search_google):
            try:
                for candidate in source_func(name):
                    existing = merged.get(candidate.hostname)
                    if existing:
                        existing.metadata.setdefault("sources", [existing.source]).append(candidate.source)
                    else:
                        merged[candidate.hostname] = candidate
            except Exception as exc:  # noqa: BLE001 - one source must not crash scan.
                LOGGER.warning("discovery source %s failed: %s", source_func.__name__, exc)
        return list(merged.values())

    def search_crtsh(self, name: str) -> list[Candidate]:
        """Search crt.sh JSON API for names containing the brand/person string."""
        self.crt_limiter.wait()
        url = "https://crt.sh/"
        params = {"q": f"%{name}%", "output": "json"}

        def request_json() -> Any:
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()

        try:
            rows = retry(request_json, self.retries, self.backoff, LOGGER)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("crt.sh lookup failed for %s: %s", name, exc)
            return []
        target_domain = normalize_domain(name)
        candidates: dict[str, Candidate] = {}
        for row in rows if isinstance(rows, list) else []:
            value = str(row.get("name_value", ""))
            for raw_host in value.splitlines():
                host = raw_host.lower().lstrip("*. ").strip(".")
                if not host or " " in host:
                    continue
                related = host.endswith(target_domain)
                source = "cert_transparency_related" if related else "cert_transparency_unrelated"
                candidates[host] = Candidate(hostname=host, source=source, related_to_target_domain=related, metadata={"crtsh": row})
        return list(candidates.values())

    def bruteforce_dns(self, name: str) -> list[Candidate]:
        """Resolve configured subdomains against generated parent domains."""
        discovered: list[Candidate] = []
        words = get_subdomain_words(self.config)
        parents = {candidate.parent_domain for candidate in generate_candidates(name, self.config) if candidate.parent_domain}
        for parent in parents:
            for word in words:
                host = f"{word}.{parent}"
                self.dns_limiter.wait()
                try:
                    self.resolver.resolve(host, "A")
                    discovered.append(Candidate(hostname=host, source="dns_bruteforce", parent_domain=parent))
                except Exception:
                    LOGGER.debug("DNS brute-force miss: %s", host)
        return discovered

    def search_google(self, name: str) -> list[Candidate]:
        """Optionally search Google Custom Search for brand mentions on unrelated domains."""
        api_key = os.getenv("GOOGLE_API_KEY")
        cse_id = os.getenv("GOOGLE_CSE_ID")
        if not api_key or not cse_id:
            LOGGER.info("Google Custom Search skipped; GOOGLE_API_KEY or GOOGLE_CSE_ID missing")
            return []
        self.google_limiter.wait()
        params = {"key": api_key, "cx": cse_id, "q": name, "num": 10}

        def request_json() -> Any:
            response = requests.get("https://www.googleapis.com/customsearch/v1", params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()

        try:
            data = retry(request_json, self.retries, self.backoff, LOGGER)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Google Custom Search failed for %s: %s", name, exc)
            return []
        candidates: dict[str, Candidate] = {}
        for item in data.get("items", []) if isinstance(data, dict) else []:
            link = str(item.get("link", ""))
            host = link.split("//")[-1].split("/")[0].lower().strip(".")
            if host:
                candidates[host] = Candidate(hostname=host, source="google_search", related_to_target_domain=False, metadata={"google": item})
        return list(candidates.values())
