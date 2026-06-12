"""
Report generator — exports analysis results to JSON and Markdown.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from correlator.incident_correlator import Incident
from parser.eve_parser import AlertRecord


def _severity_emoji(priority: str) -> str:
    return {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(priority, "⚪")


def generate_json_report(
    incidents: list[Incident],
    alerts: list[AlertRecord],
    output_path: str | Path,
) -> Path:
    """
    Write a comprehensive JSON report to disk.

    Includes metadata, summary statistics, all incidents (with AI triage),
    and the raw alert records.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    severity_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for inc in incidents:
        label = inc.priority_label
        severity_counts[label] = severity_counts.get(label, 0) + 1

    unique_src_ips = list({inc.src_ip for inc in incidents})
    attack_families = list({inc.attack_family for inc in incidents})

    report: dict[str, Any] = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "Network Intrusion Alert Analyzer v1.0",
            "model": "claude-sonnet-4-6",
        },
        "summary": {
            "total_raw_alerts": len(alerts),
            "total_incidents": len(incidents),
            "severity_distribution": severity_counts,
            "unique_attacker_ips": unique_src_ips,
            "attack_families_detected": attack_families,
            "time_range": {
                "first_alert": alerts[0].timestamp.isoformat() if alerts else None,
                "last_alert": alerts[-1].timestamp.isoformat() if alerts else None,
            },
        },
        "incidents": [inc.to_dict() for inc in incidents],
    }

    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path


def generate_markdown_report(
    incidents: list[Incident],
    alerts: list[AlertRecord],
    output_path: str | Path,
) -> Path:
    """
    Write a human-readable Markdown report to disk.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []

    # Header
    lines += [
        "# Network Intrusion Analysis Report",
        "",
        f"**Generated:** {now}  ",
        f"**Analyzer:** Network Intrusion Alert Analyzer v1.0  ",
        f"**AI Model:** claude-sonnet-4-6  ",
        "",
        "---",
        "",
    ]

    # Executive Summary
    severity_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for inc in incidents:
        label = inc.priority_label
        severity_counts[label] = severity_counts.get(label, 0) + 1

    lines += [
        "## Executive Summary",
        "",
        f"- **Total Raw Alerts:** {len(alerts)}",
        f"- **Correlated Incidents:** {len(incidents)}",
        f"- **Critical Incidents:** {severity_counts['Critical']}",
        f"- **High Incidents:** {severity_counts['High']}",
        f"- **Medium Incidents:** {severity_counts['Medium']}",
        f"- **Low Incidents:** {severity_counts['Low']}",
        "",
    ]

    # Attack family distribution
    family_counts: dict[str, int] = {}
    for inc in incidents:
        family_counts[inc.attack_family] = family_counts.get(inc.attack_family, 0) + 1

    if family_counts:
        lines += ["**Attack Families Detected:**", ""]
        for family, count in sorted(family_counts.items(), key=lambda x: -x[1]):
            lines.append(f"- `{family}`: {count} incident(s)")
        lines.append("")

    lines += ["---", ""]

    # Per-incident details
    lines += ["## Incident Details", ""]

    for idx, inc in enumerate(incidents, start=1):
        emoji = _severity_emoji(inc.priority_label)
        lines += [
            f"### {idx}. {emoji} {inc.title}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Incident ID** | `{inc.incident_id}` |",
            f"| **Priority** | **{inc.priority_label}** |",
            f"| **Attack Family** | `{inc.attack_family}` |",
            f"| **Source IP** | `{inc.src_ip}` |",
            f"| **Destination(s)** | {', '.join(f'`{ip}`' for ip in inc.dest_ips[:5])} |",
            f"| **Alert Count** | {inc.alert_count} |",
            f"| **First Seen** | {inc.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')} |",
            f"| **Last Seen** | {inc.last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')} |",
            f"| **Duration** | {inc.duration_seconds:.0f}s |",
            f"| **Internal Source** | {'Yes' if inc.is_internal_src else 'No'} |",
        ]

        if inc.cve_references:
            lines.append(f"| **CVE References** | {', '.join(inc.cve_references)} |")

        if inc.tags:
            tag_str = " ".join(f"`{t}`" for t in inc.tags)
            lines.append(f"| **Tags** | {tag_str} |")

        lines.append("")

        # AI Triage
        if inc.ai_triage:
            lines += [
                "**AI Triage Assessment:**",
                "",
                f"> {inc.ai_triage}",
                "",
            ]

        # Remediation
        if inc.remediation:
            lines += ["**Remediation Steps:**", ""]
            for step in inc.remediation:
                lines.append(f"1. {step}")
            lines.append("")

        # Sample alerts
        lines += ["**Sample Alerts:**", ""]
        for alert in inc.alerts[:3]:
            lines.append(
                f"- `{alert.timestamp.strftime('%H:%M:%S')}` "
                f"[{alert.priority_label}] "
                f"{alert.src_ip}:{alert.src_port} → "
                f"{alert.dest_ip}:{alert.dest_port} "
                f"— {alert.signature}"
            )
        if len(inc.alerts) > 3:
            lines.append(f"- *... and {len(inc.alerts) - 3} more alerts*")

        lines += ["", "---", ""]

    # Footer
    lines += [
        "",
        "*Report generated by Network Intrusion Alert Analyzer*",
        "*Powered by Suricata IDS + Claude AI (claude-sonnet-4-6)*",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")
    return path
