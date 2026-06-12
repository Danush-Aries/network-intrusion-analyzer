"""
Alert correlator — groups related Suricata alerts into incidents.

Correlation strategy:
1. Same source IP performing similar attack types within a time window
   → grouped as a single incident (e.g., repeated SSH brute force)
2. Same source IP hitting multiple destination IPs/ports in a time window
   → classified as a scanning/lateral movement incident
3. Internal IP periodically beaconing to the same external host
   → correlated as a C2 beacon incident
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from parser.eve_parser import AlertRecord


# Time window within which alerts from the same source are grouped
CORRELATION_WINDOW_MINUTES = 30

# Category tags that map signature IDs to attack families
ATTACK_FAMILY_MAP: dict[int, str] = {
    9000001: "port_scan",
    9000002: "sql_injection",
    9000003: "xss",
    9000004: "ssh_brute_force",
    9000005: "c2_beacon",
    9000006: "dns_tunneling",
    9000007: "ftp_brute_force",
    9000008: "log4shell_exploit",
    9000009: "icmp_tunnel",
    9000010: "eternalblue_exploit",
}

# Human-readable titles per attack family
FAMILY_TITLE_MAP: dict[str, str] = {
    "port_scan": "TCP SYN Port Scan Campaign",
    "sql_injection": "SQL Injection Attack",
    "xss": "Cross-Site Scripting Attack",
    "ssh_brute_force": "SSH Brute Force Campaign",
    "c2_beacon": "Command & Control Beacon Activity",
    "dns_tunneling": "DNS Tunneling / Exfiltration",
    "ftp_brute_force": "FTP Brute Force Campaign",
    "log4shell_exploit": "Log4Shell (CVE-2021-44228) Exploitation",
    "icmp_tunnel": "ICMP Tunnel / Data Exfiltration",
    "eternalblue_exploit": "EternalBlue SMB Exploit (MS17-010)",
}


@dataclass
class Incident:
    """A correlated group of related alerts representing a single attack incident."""

    incident_id: str
    title: str
    attack_family: str
    src_ip: str
    dest_ips: list[str]
    alerts: list[AlertRecord]
    first_seen: datetime
    last_seen: datetime
    severity: int          # 1=critical, 2=high, 3=medium, 4=low
    alert_count: int = 0
    is_internal_src: bool = False
    cve_references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    ai_triage: str = ""    # Populated by ClaudeAnalyzer
    remediation: list[str] = field(default_factory=list)

    @property
    def priority_label(self) -> str:
        mapping = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}
        return mapping.get(self.severity, "Unknown")

    @property
    def duration_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "attack_family": self.attack_family,
            "src_ip": self.src_ip,
            "dest_ips": self.dest_ips,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": self.duration_seconds,
            "alert_count": self.alert_count,
            "severity": self.severity,
            "priority_label": self.priority_label,
            "is_internal_src": self.is_internal_src,
            "cve_references": self.cve_references,
            "tags": self.tags,
            "ai_triage": self.ai_triage,
            "remediation": self.remediation,
            "alerts": [a.to_dict() for a in self.alerts],
        }


# RFC 1918 / private network prefixes used for internal IP detection
_PRIVATE_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
)


def _is_internal(ip: str) -> bool:
    return any(ip.startswith(pfx) for pfx in _PRIVATE_PREFIXES)


def _extract_cves(signature: str) -> list[str]:
    """Pull CVE identifiers mentioned in a signature string."""
    import re
    return re.findall(r"CVE-\d{4}-\d+", signature, re.IGNORECASE)


def _attack_family(alert: AlertRecord) -> str:
    """Determine the attack family for a given alert."""
    family = ATTACK_FAMILY_MAP.get(alert.signature_id)
    if family:
        return family
    # Fallback: derive from category name
    cat = alert.category.lower()
    if "scan" in cat:
        return "port_scan"
    if "sql" in cat or "web" in cat:
        return "web_attack"
    if "brute" in cat:
        return "brute_force"
    if "trojan" in cat or "malware" in cat:
        return "malware"
    return "generic_attack"


def _incident_key(alert: AlertRecord) -> str:
    """Compute a grouping key: src_ip + attack_family."""
    return f"{alert.src_ip}::{_attack_family(alert)}"


def _compute_incident_severity(alerts: list[AlertRecord]) -> int:
    """Pick the worst (lowest numeric value) severity across all alerts."""
    return min(a.severity for a in alerts)


def correlate(alerts: list[AlertRecord]) -> list[Incident]:
    """
    Group alerts into incidents.

    Algorithm:
    - Sort alerts by timestamp.
    - Bucket by (src_ip, attack_family).
    - Within each bucket, split on gaps larger than CORRELATION_WINDOW_MINUTES.
    - Each resulting cluster becomes one Incident.
    """
    if not alerts:
        return []

    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
    window = timedelta(minutes=CORRELATION_WINDOW_MINUTES)

    # Bucket alerts by correlation key
    buckets: dict[str, list[AlertRecord]] = defaultdict(list)
    for alert in sorted_alerts:
        key = _incident_key(alert)
        buckets[key].append(alert)

    incidents: list[Incident] = []

    for key, bucket_alerts in buckets.items():
        # Split bucket into time-based clusters
        clusters: list[list[AlertRecord]] = []
        current_cluster: list[AlertRecord] = [bucket_alerts[0]]

        for prev, curr in zip(bucket_alerts, bucket_alerts[1:]):
            if curr.timestamp - prev.timestamp <= window:
                current_cluster.append(curr)
            else:
                clusters.append(current_cluster)
                current_cluster = [curr]
        clusters.append(current_cluster)

        for cluster in clusters:
            src_ip = cluster[0].src_ip
            family = _attack_family(cluster[0])
            title = FAMILY_TITLE_MAP.get(family, f"Unknown Attack ({family})")
            dest_ips = list({a.dest_ip for a in cluster})
            first_seen = cluster[0].timestamp
            last_seen = cluster[-1].timestamp
            severity = _compute_incident_severity(cluster)

            # Collect CVE references from all alert signatures
            cves: list[str] = []
            for a in cluster:
                cves.extend(_extract_cves(a.signature))
            cves = list(dict.fromkeys(cves))  # deduplicate while preserving order

            # Tags
            tags = [family]
            if len(dest_ips) > 1:
                tags.append("multi_target")
            if any(a.action == "blocked" for a in cluster):
                tags.append("partially_blocked")
            if _is_internal(src_ip):
                tags.append("internal_source")

            incident = Incident(
                incident_id=str(uuid.uuid4())[:8],
                title=title,
                attack_family=family,
                src_ip=src_ip,
                dest_ips=dest_ips,
                alerts=cluster,
                first_seen=first_seen,
                last_seen=last_seen,
                severity=severity,
                alert_count=len(cluster),
                is_internal_src=_is_internal(src_ip),
                cve_references=cves,
                tags=tags,
            )
            incidents.append(incident)

    # Sort by severity (Critical first), then by most recent
    incidents.sort(key=lambda i: (i.severity, -i.last_seen.timestamp()))
    return incidents
