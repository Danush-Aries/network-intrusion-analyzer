"""
Rich terminal dashboard for the Network Intrusion Alert Analyzer.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from correlator.incident_correlator import Incident
from parser.eve_parser import AlertRecord

console = Console()

SEVERITY_STYLES: dict[str, str] = {
    "Critical": "bold white on red",
    "High": "bold red",
    "Medium": "bold yellow",
    "Low": "green",
}

SEVERITY_COLORS: dict[str, str] = {
    "Critical": "red",
    "High": "dark_orange",
    "Medium": "yellow",
    "Low": "green",
}


def _severity_badge(priority: str) -> Text:
    style = SEVERITY_STYLES.get(priority, "white")
    return Text(f" {priority} ", style=style)


def _truncate(s: str, max_len: int = 50) -> str:
    return s if len(s) <= max_len else s[: max_len - 3] + "..."


def render_header(alerts: list[AlertRecord], incidents: list[Incident]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    severity_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for inc in incidents:
        severity_counts[inc.priority_label] += 1

    title = Text("NETWORK INTRUSION ALERT ANALYZER", style="bold cyan", justify="center")
    subtitle = Text(f"Powered by Suricata IDS + Claude AI (claude-sonnet-4-6)  |  {now}", justify="center")

    console.print()
    console.print(Panel(Align.center(title + "\n" + subtitle), border_style="cyan", padding=(0, 2)))

    metrics = Table.grid(padding=(0, 4))
    for _ in range(6):
        metrics.add_column(justify="center")
    metrics.add_row(
        Text(f"{len(alerts)}", style="bold cyan") + Text("\nRaw Alerts", style="dim"),
        Text(f"{len(incidents)}", style="bold cyan") + Text("\nIncidents", style="dim"),
        Text(f"{severity_counts['Critical']}", style="bold red") + Text("\nCritical", style="dim"),
        Text(f"{severity_counts['High']}", style="red") + Text("\nHigh", style="dim"),
        Text(f"{severity_counts['Medium']}", style="yellow") + Text("\nMedium", style="dim"),
        Text(f"{severity_counts['Low']}", style="green") + Text("\nLow", style="dim"),
    )
    console.print(Panel(metrics, border_style="dim", padding=(0, 2)))


def render_severity_bars(incidents: list[Incident]) -> None:
    severity_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for inc in incidents:
        severity_counts[inc.priority_label] += 1
    total = max(len(incidents), 1)

    console.print(Rule("[bold]Severity Distribution[/]", style="dim cyan"))
    console.print()

    with Progress(
        TextColumn("[progress.description]{task.description}", style="bold", justify="right"),
        BarColumn(bar_width=40),
        TextColumn("{task.completed} incident(s)"),
        console=console,
        expand=False,
    ) as progress:
        for label, color in [("Critical", "red"), ("High", "dark_orange"), ("Medium", "yellow"), ("Low", "green")]:
            count = severity_counts.get(label, 0)
            progress.add_task(f"[{color}]{label:10}[/]", total=total, completed=count)
    console.print()


def render_incident_table(incidents: list[Incident]) -> None:
    console.print(Rule("[bold]Security Incidents[/]", style="dim cyan"))
    console.print()

    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=box.ROUNDED,
        border_style="cyan",
        row_styles=["", "dim"],
        expand=True,
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Priority", width=10, justify="center")
    table.add_column("Incident Title", min_width=30)
    table.add_column("Src IP", width=18)
    table.add_column("Alerts", width=7, justify="right")
    table.add_column("Duration", width=10, justify="right")
    table.add_column("Attack Family", width=20)
    table.add_column("CVEs", width=14)
    table.add_column("Tags", min_width=20)

    for idx, inc in enumerate(incidents, start=1):
        priority_label = inc.priority_label
        color = SEVERITY_COLORS.get(priority_label, "white")

        dur_secs = inc.duration_seconds
        if dur_secs < 60:
            dur_str = f"{dur_secs:.0f}s"
        elif dur_secs < 3600:
            dur_str = f"{dur_secs/60:.1f}m"
        else:
            dur_str = f"{dur_secs/3600:.1f}h"

        cve_str = ", ".join(inc.cve_references[:2]) or "-"
        if len(inc.cve_references) > 2:
            cve_str += f" +{len(inc.cve_references)-2}"

        visible_tags = [t for t in inc.tags if t not in ("multi_target", "partially_blocked", "internal_source")][:2]
        tag_str = " ".join(f"[dim cyan]{t}[/]" for t in visible_tags)
        if "internal_source" in inc.tags:
            tag_str += " [yellow]INT[/]"
        if "partially_blocked" in inc.tags:
            tag_str += " [green]BLK[/]"

        table.add_row(
            str(idx),
            _severity_badge(priority_label),
            Text(_truncate(inc.title, 48), style=color),
            Text(inc.src_ip),
            str(inc.alert_count),
            dur_str,
            Text(_truncate(inc.attack_family, 18), style="dim cyan"),
            Text(cve_str, style="dim red"),
            tag_str,
        )

    console.print(table)
    console.print()


def render_incident_detail(incident: Incident, index: int) -> None:
    priority_label = incident.priority_label
    color = SEVERITY_COLORS.get(priority_label, "white")

    header = Text()
    header.append(f"  INC-{index:03d} ", style="bold dim")
    header.append(f"[{priority_label.upper()}] ", style=SEVERITY_STYLES.get(priority_label, "white"))
    header.append(incident.title, style=f"bold {color}")
    header.append(f"  ({incident.attack_family})", style="dim")

    content_lines = []

    # Meta
    content_lines.append(
        f"Src: [bold]{incident.src_ip}[/]   "
        f"Alerts: {incident.alert_count}   "
        f"Seen: {incident.first_seen.strftime('%H:%M:%S')} to {incident.last_seen.strftime('%H:%M:%S')}   "
        f"Dests: {', '.join(incident.dest_ips[:3])}"
    )
    content_lines.append("")

    if incident.cve_references:
        content_lines.append(f"[bold]CVEs:[/] [red]{', '.join(incident.cve_references)}[/]")
        content_lines.append("")

    if incident.ai_triage:
        content_lines.append("[bold yellow]AI Triage:[/]")
        content_lines.append(f"[italic]{incident.ai_triage}[/]")
        content_lines.append("")

    if incident.remediation:
        content_lines.append("[bold green]Remediation Steps:[/]")
        for i, step in enumerate(incident.remediation, start=1):
            content_lines.append(f"  {i}. {step}")
        content_lines.append("")

    content_lines.append("[bold]Sample Alerts:[/]")
    for alert in incident.alerts[:4]:
        action_style = "green" if alert.action == "blocked" else "red"
        extra = ""
        if alert.http_url:
            extra = f" [dim cyan]{_truncate(alert.http_url, 45)}[/]"
        elif alert.dns_query:
            extra = f" [dim cyan]{_truncate(alert.dns_query, 45)}[/]"
        content_lines.append(
            f"  [dim]{alert.timestamp.strftime('%H:%M:%S')}[/] "
            f"[{alert.priority_color}][{alert.priority_label}][/{alert.priority_color}] "
            f"{alert.src_ip}:{alert.src_port} -> {alert.dest_ip}:{alert.dest_port}  "
            f"[{action_style}]{alert.action.upper()}[/{action_style}]"
            f"{extra}"
        )

    if len(incident.alerts) > 4:
        content_lines.append(f"  [dim]... and {len(incident.alerts) - 4} more alerts[/]")

    console.print(Panel(
        "\n".join(content_lines),
        title=header,
        border_style=color,
        padding=(1, 2),
    ))


def render_full_dashboard(
    alerts: list[AlertRecord],
    incidents: list[Incident],
    show_details: bool = True,
    max_details: int = 5,
) -> None:
    render_header(alerts, incidents)
    render_severity_bars(incidents)
    render_incident_table(incidents)

    if show_details and incidents:
        console.print(Rule("[bold]Top Incident Details[/]", style="dim cyan"))
        console.print()
        for idx, incident in enumerate(incidents[:max_details], start=1):
            render_incident_detail(incident, idx)


def render_analysis_progress(message: str, style: str = "cyan") -> None:
    console.print(f"[{style}]  {message}[/{style}]")


def render_complete_message(json_path: str, md_path: str) -> None:
    console.print()
    console.print(Panel(
        f"[bold green]Analysis complete![/]\n\n"
        f"  [cyan]JSON report:[/]     {json_path}\n"
        f"  [cyan]Markdown report:[/] {md_path}",
        title="[bold]Export Complete[/]",
        border_style="green",
        padding=(1, 2),
    ))
