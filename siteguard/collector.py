"""Data collection and enrichment for discovered candidates."""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime
from typing import Any

import dns.resolver
import requests
import whois
from bs4 import BeautifulSoup

from siteguard.models import Candidate, Finding
from siteguard.net import RateLimiter, retry

LOGGER = logging.getLogger(__name__)


class Collector:
    """Collect DNS, WHOIS, TLS, and page metadata for candidates."""

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize collector with network behavior from config."""
        network = config.get("network", {})
        self.timeout = float(network.get("timeout_seconds", 8))
        self.retries = int(network.get("retries", 3))
        self.backoff = float(network.get("backoff_factor", 0.8))
        rates = network.get("rate_limit_seconds", {})
        self.http_limiter = RateLimiter(float(rates.get("http", 0.2)))
        self.dns_limiter = RateLimiter(float(rates.get("dns", 0.05)))
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = self.timeout
        self.resolver.timeout = self.timeout
        self.collect_whois_for_unresolved = bool(config.get("scan", {}).get("collect_whois_for_unresolved", False))

    def collect_many(self, candidates: list[Candidate]) -> list[Finding]:
        """Collect enrichment data for many candidates without batch failure."""
        findings: list[Finding] = []
        total = len(candidates)
        LOGGER.info("Collecting enrichment for %s candidates", total)
        for index, candidate in enumerate(candidates, start=1):
            LOGGER.info("Collecting candidate %s/%s: %s", index, total, candidate.hostname)
            findings.append(self.collect(candidate))
        return findings

    def collect(self, candidate: Candidate) -> Finding:
        """Collect enrichment data for one candidate."""
        finding = Finding(
            hostname=candidate.hostname,
            source=candidate.source,
            related_to_target_domain=candidate.related_to_target_domain,
            metadata=candidate.metadata,
        )
        try:
            finding.resolved_ips = self.resolve_dns(candidate.hostname)
        except Exception as exc:  # noqa: BLE001
            finding.errors.append(f"dns: {exc}")
        if finding.resolved_ips or self.collect_whois_for_unresolved:
            try:
                finding.registrar, finding.creation_date = self.lookup_whois(candidate.hostname)
            except Exception as exc:  # noqa: BLE001
                finding.errors.append(f"whois: {exc}")
        else:
            LOGGER.debug("Skipping WHOIS for unresolved host: %s", candidate.hostname)
        if finding.resolved_ips:
            try:
                finding.ssl_issuer = self.get_ssl_issuer(candidate.hostname)
            except Exception as exc:  # noqa: BLE001
                finding.errors.append(f"ssl: {exc}")
            try:
                self.fetch_page_metadata(finding)
            except Exception as exc:  # noqa: BLE001
                finding.errors.append(f"http: {exc}")
        return finding

    def resolve_dns(self, hostname: str) -> list[str]:
        """Resolve A and AAAA records for a hostname."""
        addresses: list[str] = []
        for record_type in ("A", "AAAA"):
            self.dns_limiter.wait()
            try:
                answers = self.resolver.resolve(hostname, record_type)
                addresses.extend(str(answer) for answer in answers)
            except Exception:
                LOGGER.debug("no %s records for %s", record_type, hostname)
        return sorted(set(addresses))

    def lookup_whois(self, hostname: str) -> tuple[str | None, datetime | None]:
        """Fetch WHOIS registrar and creation date, tolerating redacted fields."""
        domain = ".".join(hostname.split(".")[-2:])
        data = whois.whois(domain)
        registrar = data.get("registrar") if hasattr(data, "get") else getattr(data, "registrar", None)
        creation = data.get("creation_date") if hasattr(data, "get") else getattr(data, "creation_date", None)
        if isinstance(creation, list):
            creation = next((item for item in creation if isinstance(item, datetime)), None)
        if not isinstance(creation, datetime):
            creation = None
        return (str(registrar) if registrar else None, creation)

    def get_ssl_issuer(self, hostname: str) -> str | None:
        """Return the TLS certificate issuer organization, if available."""
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
        issuer = cert.get("issuer", ()) if isinstance(cert, dict) else ()
        parts = [value for attrs in issuer for key, value in attrs if key in {"organizationName", "commonName"}]
        return ", ".join(parts) if parts else None

    def fetch_page_metadata(self, finding: Finding) -> None:
        """Fetch a live page title and meta description using strict timeout."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{finding.hostname}"
            self.http_limiter.wait()

            def request_page() -> requests.Response:
                response = requests.get(url, timeout=self.timeout, headers={"User-Agent": "SiteGuard/0.1"})
                response.raise_for_status()
                return response

            try:
                response = retry(request_page, self.retries, self.backoff, LOGGER)
            except Exception:
                continue
            soup = BeautifulSoup(response.text[:250_000], "html.parser")
            finding.is_live = True
            finding.url = url
            finding.page_title = soup.title.string.strip() if soup.title and soup.title.string else None
            meta = soup.find("meta", attrs={"name": "description"})
            finding.meta_description = str(meta.get("content", "")).strip() if meta else None
            return
