# Network Intrusion Alert Analyzer

AI-powered network intrusion alert analyzer. Parses Suricata IDS EVE JSON logs,
correlates raw alerts into incidents, and uses Claude (claude-sonnet-4-6) to
triage each incident with threat summaries and remediation steps.
Renders a colour-coded Rich terminal dashboard and exports JSON + Markdown reports.

## Features

- **Suricata EVE JSON parsing** — supports JSON array and NDJSON formats
- **Alert correlation** — groups alerts by source IP + attack family within time windows
- **Claude AI triage** — sends incident batches to claude-sonnet-4-6 with prompt caching
- **Fallback mode** — deterministic per-family triage when no API key is configured
- **Rich terminal dashboard** — severity bars, incident table, detail panels with CVEs and tags
- **Report export** — structured JSON report + Markdown investigation report
- **10 real Suricata rules** — port scan, SQLi, XSS, SSH/FTP brute force, C2 beacon,
  DNS tunnel, ICMP tunnel, Log4Shell, EternalBlue

## Quick Start

```bash
# 1. Clone and install dependencies
git clone https://github.com/Dhanush-Aries/network-intrusion-analyzer
cd network-intrusion-analyzer
pip install -r requirements.txt

# 2. (Optional) Set your Anthropic API key
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 3. Run the demo (no Suricata needed)
python main.py --demo

# 4. Analyze a real Suricata EVE log
python main.py --log /var/log/suricata/eve.json
```

## Usage

```
python main.py --demo                         # Built-in 20-alert sample dataset
python main.py --log alerts.json              # Real Suricata EVE JSON log
python main.py --demo --no-ai                 # Skip Claude API, use fallback triage
python main.py --demo --output-dir ./reports  # Custom report output directory
python main.py --demo --max-details 10        # Show more incident detail panels
```

## Project Structure

```
network-intrusion-analyzer/
├── main.py                          # CLI entry point
├── parser/
│   └── eve_parser.py                # Suricata EVE JSON parser → AlertRecord dataclass
├── correlator/
│   └── incident_correlator.py       # Alert correlation → Incident dataclass
├── analyzer/
│   └── claude_analyzer.py           # Claude AI triage (claude-sonnet-4-6)
├── reporter/
│   └── report_generator.py          # JSON + Markdown report export
├── ui/
│   └── dashboard.py                 # Rich terminal dashboard
├── rules/
│   └── local.rules                  # 10 Suricata detection rules
├── data/
│   └── sample_alerts.json           # 20 realistic EVE alerts for demo mode
├── requirements.txt
└── .env.example
```

## Detection Rules

The `rules/local.rules` file contains 10 production-quality Suricata rules:

| SID      | Rule                                   | Category                  |
|----------|----------------------------------------|---------------------------|
| 9000001  | TCP SYN Port Scan                      | Reconnaissance            |
| 9000002  | SQL Injection (UNION SELECT)           | Web Application Attack    |
| 9000003  | XSS Script Tag Injection               | Web Application Attack    |
| 9000004  | SSH Brute Force                        | Credential Access         |
| 9000005  | C2 Beacon (Periodic HTTP Check-in)     | Command & Control         |
| 9000006  | DNS Tunneling (Long DNS Query)         | Exfiltration              |
| 9000007  | FTP Brute Force                        | Credential Access         |
| 9000008  | Log4Shell (CVE-2021-44228)             | Initial Access / RCE      |
| 9000009  | ICMP Tunnel / Exfiltration             | Exfiltration              |
| 9000010  | EternalBlue SMB RCE (MS17-010)         | Lateral Movement          |

## Configuration

Copy `.env.example` to `.env` and set your `ANTHROPIC_API_KEY`.
Without a key, all triage uses the built-in deterministic fallback — the
dashboard and reports still work fully.

## Reports

After each run, two report files are written to `./reports/` (configurable with `--output-dir`):

- `intrusion_report.json` — machine-readable report with all incidents and AI triage
- `intrusion_report.md`   — human-readable Markdown investigation report
