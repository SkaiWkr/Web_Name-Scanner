"""Console and JSON reporting for SiteGuard findings."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from siteguard.models import ScoredFinding


def _json_default(value: object) -> str:
    """Serialize otherwise unsupported JSON values."""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def write_json_report(scored_findings: list[ScoredFinding], output_path: str | Path) -> None:
    """Write scored findings to a JSON report file."""
    payload = [asdict(item) for item in scored_findings]
    Path(output_path).write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")


def print_console_table(scored_findings: list[ScoredFinding]) -> None:
    """Print findings as a Rich console table."""
    table = Table(title="SiteGuard Findings")
    table.add_column("Score", justify="right")
    table.add_column("Hostname")
    table.add_column("Source")
    table.add_column("Live")
    table.add_column("Registrar")
    table.add_column("Title")
    for item in scored_findings:
        finding = item.finding
        table.add_row(
            str(item.score),
            finding.hostname,
            finding.source,
            "yes" if finding.is_live else "no",
            finding.registrar or "unknown",
            (finding.page_title or "")[:80],
        )
    Console().print(table)


def report(scored_findings: list[ScoredFinding], output_path: str | Path) -> None:
    """Emit both console and JSON reports."""
    print_console_table(scored_findings)
    write_json_report(scored_findings, output_path)
