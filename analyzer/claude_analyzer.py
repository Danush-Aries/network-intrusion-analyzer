"""
Claude AI triage analyzer using the Anthropic SDK.

Sends batched incidents to claude-sonnet-4-6 for:
- Threat assessment and triage narrative
- Priority scoring (Critical/High/Medium/Low)
- Concrete remediation recommendations

Uses prompt caching on the system prompt for token efficiency across
multiple analysis batches in the same session.
"""

from __future__ import annotations

import json
import os
from typing import Any

import anthropic

from correlator.incident_correlator import Incident

MODEL = "claude-sonnet-4-6"

# System prompt is stable across calls → cache it for token savings
SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst with deep expertise in:
- Network intrusion detection and incident response
- MITRE ATT&CK framework mapping
- CVE exploitation analysis
- Threat hunting and forensics

Your task is to analyze Suricata IDS alert incidents and produce structured security triage.

For each incident you receive, you must return a JSON array where each element has exactly these fields:
{
  "incident_id": "<the incident_id from input>",
  "triage_summary": "<2-3 sentence threat assessment>",
  "attack_stage": "<Reconnaissance | Initial Access | Execution | Persistence | Lateral Movement | Exfiltration | C2>",
  "confidence": "<High | Medium | Low>",
  "false_positive_likelihood": "<High | Medium | Low>",
  "remediation": [
    "<specific actionable step 1>",
    "<specific actionable step 2>",
    "<specific actionable step 3>"
  ],
  "ioc_summary": "<key indicators of compromise to block/monitor>",
  "mitre_techniques": ["<technique ID like T1190>"]
}

Be specific and actionable. Reference CVEs where provided. Do not include any text outside the JSON array."""


def _build_incident_payload(incident: Incident) -> dict[str, Any]:
    """Build a concise incident summary for the AI prompt."""
    sample_alerts = incident.alerts[:3]  # send max 3 representative alerts
    alert_summaries = []
    for a in sample_alerts:
        summary = {
            "sig": a.signature,
            "src": f"{a.src_ip}:{a.src_port}",
            "dst": f"{a.dest_ip}:{a.dest_port}",
            "proto": a.proto,
            "action": a.action,
        }
        if a.http_url:
            summary["http_url"] = a.http_url[:200]
        if a.http_user_agent:
            summary["user_agent"] = a.http_user_agent[:100]
        if a.dns_query:
            summary["dns_query"] = a.dns_query[:150]
        alert_summaries.append(summary)

    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "attack_family": incident.attack_family,
        "src_ip": incident.src_ip,
        "dest_ips": incident.dest_ips[:5],
        "alert_count": incident.alert_count,
        "severity_numeric": incident.severity,
        "priority": incident.priority_label,
        "duration_seconds": round(incident.duration_seconds, 1),
        "cve_references": incident.cve_references,
        "tags": incident.tags,
        "is_internal_src": incident.is_internal_src,
        "sample_alerts": alert_summaries,
    }


class ClaudeAnalyzer:
    """
    Sends incident batches to Claude for AI-powered security triage.

    Uses prompt caching on the stable system prompt.
    Falls back gracefully if no API key is configured (demo mode).
    """

    def __init__(self, api_key: str | None = None) -> None:
        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if key:
            self.client: anthropic.Anthropic | None = anthropic.Anthropic(api_key=key)
        else:
            self.client = None
        self._cache_populated = False

    @property
    def is_available(self) -> bool:
        return self.client is not None

    def analyze_incidents(
        self,
        incidents: list[Incident],
        batch_size: int = 5,
    ) -> list[Incident]:
        """
        Analyze incidents using Claude.

        Processes incidents in batches to stay within context limits.
        Returns the incidents list with ai_triage and remediation fields populated.
        If the API key is not set, injects deterministic fallback triage.
        """
        if not self.client:
            return self._apply_fallback_triage(incidents)

        for i in range(0, len(incidents), batch_size):
            batch = incidents[i : i + batch_size]
            self._analyze_batch(batch)

        return incidents

    def _analyze_batch(self, batch: list[Incident]) -> None:
        """Send one batch to Claude and apply results back to incident objects."""
        payloads = [_build_incident_payload(inc) for inc in batch]
        user_content = (
            "Analyze the following security incidents and return a JSON array with one "
            "triage object per incident:\n\n"
            + json.dumps(payloads, indent=2)
        )

        try:
            # Use prompt caching on the system prompt (stable across all batches)
            response = self.client.messages.create(
                model=MODEL,
                max_tokens=4096,
                system=[
                    {
                        "type": "text",
                        "text": SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": user_content}],
            )

            raw_text = response.content[0].text.strip()

            # Parse the JSON array Claude returns
            # Handle code block wrappers if present
            if raw_text.startswith("```"):
                raw_text = raw_text.split("```")[1]
                if raw_text.startswith("json"):
                    raw_text = raw_text[4:]
            raw_text = raw_text.strip()

            triage_list: list[dict[str, Any]] = json.loads(raw_text)

            # Map results back to incidents by incident_id
            triage_by_id = {t["incident_id"]: t for t in triage_list}

            for incident in batch:
                triage = triage_by_id.get(incident.incident_id)
                if not triage:
                    continue
                incident.ai_triage = triage.get("triage_summary", "")
                incident.remediation = triage.get("remediation", [])
                # Attach extra fields as tags for display
                stage = triage.get("attack_stage", "")
                if stage and stage not in incident.tags:
                    incident.tags.append(stage)
                for mitre in triage.get("mitre_techniques", []):
                    if mitre not in incident.tags:
                        incident.tags.append(mitre)

        except (anthropic.APIError, json.JSONDecodeError, KeyError, IndexError) as exc:
            # Degrade gracefully — apply fallback triage for this batch
            self._apply_fallback_triage(batch, error=str(exc))

    def _apply_fallback_triage(
        self,
        incidents: list[Incident],
        error: str = "",
    ) -> list[Incident]:
        """
        Apply deterministic fallback triage when AI is unavailable.

        Provides sensible default remediation steps per attack family
        so the dashboard still shows useful information without an API key.
        """
        FALLBACK_TRIAGE: dict[str, dict[str, Any]] = {
            "sql_injection": {
                "summary": (
                    "SQL injection attempt detected from external IP. Attacker is using "
                    "UNION-based enumeration to extract database contents. Automated "
                    "SQLmap tooling signatures present — likely a targeted assessment."
                ),
                "remediation": [
                    "Immediately block source IP at perimeter firewall",
                    "Review web application firewall (WAF) rules for SQLi patterns",
                    "Audit all database queries for parameterized statement usage",
                    "Enable enhanced logging on the database server",
                    "Verify no data was successfully extracted via UNION queries",
                ],
            },
            "ssh_brute_force": {
                "summary": (
                    "Sustained SSH brute-force campaign from a single external source. "
                    "High connection rate indicates automated credential stuffing. "
                    "Risk of account compromise if weak passwords are in use."
                ),
                "remediation": [
                    "Block source IP with iptables/firewall: immediate priority",
                    "Enable fail2ban with a low retry threshold (5 attempts)",
                    "Enforce key-based SSH authentication; disable password auth",
                    "Restrict SSH access to known management IP ranges",
                    "Audit /var/log/auth.log for any successful logins",
                ],
            },
            "c2_beacon": {
                "summary": (
                    "Internal host is periodically beaconing to an external IP with "
                    "suspicious User-Agent strings. Regular interval strongly suggests "
                    "automated malware callback. Host may be compromised."
                ),
                "remediation": [
                    "Isolate the beaconing host from the network immediately",
                    "Block the C2 domain/IP at DNS resolver and perimeter firewall",
                    "Capture full packet capture for forensic analysis",
                    "Image the host drive before reimaging",
                    "Run full AV/EDR scan; collect memory dump for malware analysis",
                ],
            },
            "dns_tunneling": {
                "summary": (
                    "Abnormally long DNS queries detected — consistent with DNS "
                    "tunneling for data exfiltration. Base64-encoded payload strings "
                    "in query labels indicate active data transfer over DNS."
                ),
                "remediation": [
                    "Block the tunnel domain at DNS resolver",
                    "Enable DNS Response Policy Zones (RPZ) to block tunneling domains",
                    "Implement DNS query length limits at your recursive resolver",
                    "Review what data may have been exfiltrated",
                    "Deploy DNS inspection on outbound traffic",
                ],
            },
            "log4shell_exploit": {
                "summary": (
                    "Log4Shell exploitation attempt detected (CVE-2021-44228). JNDI "
                    "injection payloads in HTTP headers targeting Java applications. "
                    "If successful, this allows full remote code execution."
                ),
                "remediation": [
                    "Upgrade Log4j to version 2.17.1 or later immediately",
                    "As immediate mitigation: set LOG4J_FORMAT_MSG_NO_LOOKUPS=true",
                    "Block outbound LDAP/RMI connections at the firewall",
                    "Scan all Java applications for vulnerable Log4j versions",
                    "Check LDAP server logs for callback attempts from your hosts",
                ],
            },
            "eternalblue_exploit": {
                "summary": (
                    "EternalBlue SMB exploit attempt detected (MS17-010). This critical "
                    "vulnerability allows unauthenticated remote code execution against "
                    "Windows hosts. WannaCry and NotPetya used this same exploit."
                ),
                "remediation": [
                    "Apply MS17-010 security patch immediately on all Windows hosts",
                    "Block TCP 445 inbound from untrusted networks at perimeter",
                    "Disable SMBv1 on all hosts: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
                    "Segment internal network to limit lateral movement potential",
                    "Check for signs of successful exploitation in Windows Event Logs",
                ],
            },
            "port_scan": {
                "summary": (
                    "TCP SYN port scan detected from external IP. Attacker is mapping "
                    "open ports on target host — classic reconnaissance phase. "
                    "Likely precursor to a targeted attack."
                ),
                "remediation": [
                    "Add source IP to threat intelligence blocklist",
                    "Verify no unnecessary ports are exposed on the scanned host",
                    "Enable port scan detection and auto-blocking (e.g., PortSentry)",
                    "Review firewall rules to ensure minimal attack surface",
                    "Monitor for follow-up exploitation attempts from this IP",
                ],
            },
            "xss": {
                "summary": (
                    "Cross-site scripting (XSS) payload detected in HTTP request. "
                    "Script injection could enable session hijacking if reflected "
                    "to other users. Indicates web application input validation gap."
                ),
                "remediation": [
                    "Implement Content Security Policy (CSP) headers on the web app",
                    "Ensure all user input is HTML-encoded before rendering",
                    "Enable XSS filter in WAF with blocking mode",
                    "Review the affected endpoint for output encoding vulnerabilities",
                    "Scan codebase with SAST tools for XSS vulnerabilities",
                ],
            },
            "ftp_brute_force": {
                "summary": (
                    "FTP brute-force attack detected. High volume of authentication "
                    "attempts indicate credential stuffing. FTP transmits credentials "
                    "in plaintext, increasing the risk of interception."
                ),
                "remediation": [
                    "Block the source IP at the firewall immediately",
                    "Migrate from FTP to SFTP/FTPS for encrypted file transfer",
                    "Restrict FTP access to authorized IP ranges only",
                    "Enable account lockout after 5 failed attempts",
                    "Audit FTP logs for any successful logins",
                ],
            },
            "icmp_tunnel": {
                "summary": (
                    "Large ICMP echo request packets detected — consistent with ICMP "
                    "tunneling for covert data exfiltration or C2 communication. "
                    "Normal ICMP traffic does not use payloads this large."
                ),
                "remediation": [
                    "Block oversized ICMP packets at perimeter firewall",
                    "Restrict ICMP to required network management functions only",
                    "Inspect the source host for ICMP tunneling tools (ptunnel, icmptunnel)",
                    "Implement deep packet inspection to detect tunneled protocols",
                    "Review what data may have been transferred via ICMP tunnel",
                ],
            },
        }

        for incident in incidents:
            fallback = FALLBACK_TRIAGE.get(
                incident.attack_family,
                {
                    "summary": (
                        "Security alert detected. Manual investigation required to "
                        "determine scope and impact. Review raw alert data for indicators."
                    ),
                    "remediation": [
                        "Review raw alert data and network logs",
                        "Block source IP if external and confirmed malicious",
                        "Escalate to senior SOC analyst for investigation",
                    ],
                },
            )

            prefix = "[DEMO - no API key] " if not self.client else ""
            incident.ai_triage = prefix + fallback["summary"]
            incident.remediation = fallback["remediation"]

        return incidents
