"""Command-line interface for SiteGuard."""

from __future__ import annotations

import argparse
import logging

from siteguard.collector import Collector
from siteguard.config import load_config
from siteguard.discoverer import Discoverer
from siteguard.reporter import report
from siteguard.scorer import score_findings


def build_parser() -> argparse.ArgumentParser:
    """Build the SiteGuard argument parser."""
    parser = argparse.ArgumentParser(description="Detect fraudulent/lookalike websites for a brand or person name.")
    parser.add_argument("--name", required=True, help="Brand or person name to protect, e.g. 'BrandName'.")
    parser.add_argument("--output", required=True, help="Path to write JSON report, e.g. report.json.")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def main() -> int:
    """Run the SiteGuard CLI workflow."""
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config = load_config(args.config)
    candidates = Discoverer(config).discover(args.name)
    findings = Collector(config).collect_many(candidates)
    scored = score_findings(args.name, findings, config)
    report(scored, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
