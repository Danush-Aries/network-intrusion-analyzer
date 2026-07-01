# Network Intrusion Analyzer

**Suricata EVE logs in. Claude-triaged incident dashboard out.**

<!-- hero: 1600x600 screenshot of the terminal dashboard with severity bars -->

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-IDS-red)
![Claude](https://img.shields.io/badge/Claude-sonnet--4--6-D97757?logo=anthropic&logoColor=white)
![Rich](https://img.shields.io/badge/UI-Rich-8A2BE2)
![License](https://img.shields.io/badge/License-MIT-yellow)

An AI-powered Suricata alert analyzer. It parses EVE JSON logs, correlates thousands of raw alerts into a handful of coherent incidents, sends each incident to Claude for triage, and renders a colour-coded terminal dashboard with severity bars, threat summaries, and remediation steps.

---

## Why this exists

A single misconfigured web server can produce 10,000 Suricata alerts an hour, most of which are the same attack repeating. Manually reading them is impossible. This tool collapses that flood into a small set of incidents, adds AI context ("this is a Log4Shell probe, likely automated, block IP + patch"), and gives you something you can actually act on inside a terminal — no Kibana required.

---

## Try it in 60 seconds

```bash
git clone https://github.com/Danush-Aries/network-intrusion-analyzer
cd network-intrusion-analyzer
pip install -r requirements.txt

# Optional: enable Claude triage
cp .env.example .env
# add ANTHROPIC_API_KEY=...

python main.py --input data/sample_eve.json
```

No API key? The tool falls back to deterministic per-family triage automatically — the dashboard still works.

---

## How it works

```
Suricata EVE JSON
       |
       v
+-- parser/ ---------------+
|  JSON array + NDJSON     |
+-------------|------------+
              v
+-- correlator/ -----------+
|  src IP + attack family  |
|  time-window grouping    |
+-------------|------------+
              v
+-- analyzer/ -------------+
|  Claude sonnet-4-6       |
|  (prompt-cached batches) |
|  fallback: rules-only    |
+-------------|------------+
              v
+-- ui/ + reporter/ -------+
|  Rich terminal dashboard |
|  JSON + Markdown export  |
+--------------------------+
```

Ships with 10 real Suricata rules covering port scans, SQLi, XSS, SSH/FTP brute force, C2 beacons, DNS/ICMP tunnels, Log4Shell, and EternalBlue.

---

## Screenshots

<!-- screenshot: dashboard.png -->
<!-- screenshot: incident-detail.png -->
<!-- screenshot: markdown-report.png -->

---

## Stack

| Layer | Tech |
|---|---|
| IDS input | Suricata EVE JSON (array or NDJSON) |
| Parsing / correlation | Pure Python — no external DB |
| AI triage | Anthropic Claude sonnet-4-6 with prompt caching |
| Fallback | Rule-based deterministic triage (no key needed) |
| UI | Rich (terminal dashboard, severity bars, detail panels) |
| Reports | JSON + Markdown export |

---

## More from Danush

Part of a broader stack of AI + security tooling:

- [jarvis](https://github.com/Danush-Aries/jarvis) — portable multi-provider AI assistant (voice/web/CLI)
- [breachintel](https://github.com/Danush-Aries/breachintel) — OSINT breach intelligence aggregator
- [cve-advisor](https://github.com/Danush-Aries/cve-advisor) — AI-powered CVE triage and patch recommendation
- [llm-fragility-lab](https://github.com/Danush-Aries/llm-fragility-lab) — adversarial testing lab for LLM robustness
- [leakhub](https://github.com/Danush-Aries/leakhub) — API endpoint & secret exposure indexer
- [autonomous-coding-agent](https://github.com/Danush-Aries/autonomous-coding-agent) — two-agent autonomous coding system

Built by [Dhanush](https://github.com/Danush-Aries) — AI engineering + cybersecurity.

## License

MIT.
