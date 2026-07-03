"""Command-line interface for SiteGuard."""

from __future__ import annotations

import argparse
import logging

def build_parser() -> argparse.ArgumentParser:
    """Build the SiteGuard argument parser."""
    parser = argparse.ArgumentParser(description="Detect fraudulent/lookalike websites for a brand or person name.")
    parser.add_argument("--name", required=True, help="Brand or person name to protect, e.g. 'BrandName'.")
    parser.add_argument("--output", required=True, help="Path to write JSON report, e.g. report.json.")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml.")
    parser.add_argument("--max-candidates", type=int, help="Maximum number of candidates to enrich before reporting.")
    parser.add_argument("--max-permutations", type=int, help="Maximum number of dnstwist permutations to generate.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def main() -> int:
    """Run the SiteGuard CLI workflow."""
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    from siteguard.collector import Collector
    from siteguard.config import load_config
    from siteguard.discoverer import Discoverer
    from siteguard.reporter import report
    from siteguard.scorer import score_findings

    config = load_config(args.config)
    config.setdefault("scan", {})
    if args.max_candidates is not None:
        config["scan"]["max_candidates"] = args.max_candidates
    if args.max_permutations is not None:
        config["scan"]["max_permutations"] = args.max_permutations
    logging.info("Starting SiteGuard scan for %s", args.name)
    candidates = Discoverer(config).discover(args.name)
    logging.info("Discovery produced %s candidates; starting enrichment", len(candidates))
    findings = Collector(config).collect_many(candidates)
    scored = score_findings(args.name, findings, config)
    logging.info("Writing report to %s", args.output)
    report(scored, args.output)
    logging.info("SiteGuard scan complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
