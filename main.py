"""
Network Intrusion Alert Analyzer — CLI entry point.

Usage:
  python main.py --demo                          # Use built-in sample data
  python main.py --log alerts.json               # Parse a real Suricata EVE log
  python main.py --demo --no-ai                  # Skip Claude API (uses fallback triage)
  python main.py --demo --output-dir ./reports   # Custom report output directory
  python main.py --demo --max-details 10         # Show more incident detail panels
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure project root is on the path so sub-packages resolve correctly
sys.path.insert(0, str(Path(__file__).parent))

from analyzer.claude_analyzer import ClaudeAnalyzer
from correlator.incident_correlator import correlate
from parser.eve_parser import parse_file, parse_json_list
from reporter.report_generator import generate_json_report, generate_markdown_report
from ui.dashboard import (
    console,
    render_analysis_progress,
    render_complete_message,
    render_full_dashboard,
)


def load_demo_data() -> list[dict]:
    """Load the bundled sample Suricata alerts."""
    sample_path = Path(__file__).parent / "data" / "sample_alerts.json"
    if not sample_path.exists():
        console.print(f"[red]Sample data file not found: {sample_path}[/]")
        sys.exit(1)
    return json.loads(sample_path.read_text(encoding="utf-8"))


def run_analysis(
    log_path: str | None,
    demo: bool,
    use_ai: bool,
    output_dir: str,
    max_details: int,
) -> None:
    """Main analysis pipeline."""

    # ── 1. Load alerts ──────────────────────────────────────────────────────
    render_analysis_progress("Loading alert data...")

    if demo:
        raw_data = load_demo_data()
        from parser.eve_parser import parse_json_list
        alerts = parse_json_list(raw_data)
        render_analysis_progress(f"Loaded {len(alerts)} sample alerts (demo mode)", style="green")
    elif log_path:
        path = Path(log_path)
        if not path.exists():
            console.print(f"[red]Log file not found: {path}[/]")
            sys.exit(1)
        alerts = parse_file(path)
        render_analysis_progress(f"Parsed {len(alerts)} alerts from {path}", style="green")
    else:
        console.print("[red]Provide --demo or --log <file>[/]")
        sys.exit(1)

    if not alerts:
        console.print("[yellow]No alert events found in the provided data.[/]")
        sys.exit(0)

    # ── 2. Correlate incidents ──────────────────────────────────────────────
    render_analysis_progress("Correlating alerts into incidents...")
    incidents = correlate(alerts)
    render_analysis_progress(
        f"Correlated {len(alerts)} alerts into {len(incidents)} incidents",
        style="green",
    )

    # ── 3. AI triage ────────────────────────────────────────────────────────
    analyzer = ClaudeAnalyzer()

    if use_ai and analyzer.is_available:
        render_analysis_progress(
            f"Sending {len(incidents)} incident(s) to Claude (claude-sonnet-4-6) for AI triage..."
        )
        incidents = analyzer.analyze_incidents(incidents)
        render_analysis_progress("AI triage complete", style="green")
    else:
        mode = "no API key set" if not analyzer.is_available else "AI disabled by --no-ai flag"
        render_analysis_progress(
            f"Applying fallback triage ({mode})",
            style="yellow",
        )
        incidents = analyzer._apply_fallback_triage(incidents)

    # ── 4. Render dashboard ─────────────────────────────────────────────────
    render_full_dashboard(alerts, incidents, show_details=True, max_details=max_details)

    # ── 5. Export reports ───────────────────────────────────────────────────
    render_analysis_progress("Exporting reports...")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "intrusion_report.json"
    md_path = out_dir / "intrusion_report.md"

    generate_json_report(incidents, alerts, json_path)
    generate_markdown_report(incidents, alerts, md_path)

    render_complete_message(str(json_path), str(md_path))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-intrusion-analyzer",
        description="AI-powered Suricata IDS alert analyzer using Claude",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --demo                    Run with built-in sample data
  python main.py --log /var/log/eve.json   Analyze a real Suricata log
  python main.py --demo --no-ai            Demo without Claude API
  python main.py --demo --output-dir /tmp  Write reports to /tmp
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--demo",
        action="store_true",
        help="Run analysis on built-in sample alerts (no Suricata needed)",
    )
    group.add_argument(
        "--log",
        metavar="FILE",
        help="Path to a Suricata EVE JSON log file",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip Claude AI analysis (use deterministic fallback triage)",
    )
    parser.add_argument(
        "--output-dir",
        default="./reports",
        metavar="DIR",
        help="Directory for JSON + Markdown report output (default: ./reports)",
    )
    parser.add_argument(
        "--max-details",
        type=int,
        default=5,
        metavar="N",
        help="Maximum number of incident detail panels to render (default: 5)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    run_analysis(
        log_path=args.log,
        demo=args.demo,
        use_ai=not args.no_ai,
        output_dir=args.output_dir,
        max_details=args.max_details,
    )


if __name__ == "__main__":
    main()
