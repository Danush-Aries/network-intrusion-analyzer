"""
Suricata EVE JSON log parser.

Parses Suricata's EVE (Extensible Event Format) JSON output and normalizes
alert records into structured Alert dataclass objects.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class AlertRecord:
    """Normalized representation of a single Suricata alert event."""

    timestamp: datetime
    flow_id: int
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    proto: str
    signature_id: int
    signature: str
    category: str
    severity: int  # 1=critical, 2=high, 3=medium, 4=low (Suricata convention)
    action: str    # allowed / blocked
    app_proto: str

    # Optional enrichment fields
    http_url: str = ""
    http_method: str = ""
    http_hostname: str = ""
    http_user_agent: str = ""
    http_status: int = 0
    dns_query: str = ""
    flow_bytes_toserver: int = 0
    flow_bytes_toclient: int = 0
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def priority_label(self) -> str:
        """Map Suricata severity (1-4) to human-readable label."""
        mapping = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}
        return mapping.get(self.severity, "Unknown")

    @property
    def priority_color(self) -> str:
        """Return Rich color string for severity."""
        mapping = {1: "bold red", 2: "red", 3: "yellow", 4: "green"}
        return mapping.get(self.severity, "white")

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "proto": self.proto,
            "signature_id": self.signature_id,
            "signature": self.signature,
            "category": self.category,
            "severity": self.severity,
            "priority_label": self.priority_label,
            "action": self.action,
            "app_proto": self.app_proto,
            "http_url": self.http_url,
            "http_method": self.http_method,
            "http_hostname": self.http_hostname,
            "http_user_agent": self.http_user_agent,
            "http_status": self.http_status,
            "dns_query": self.dns_query,
            "flow_bytes_toserver": self.flow_bytes_toserver,
            "flow_bytes_toclient": self.flow_bytes_toclient,
        }


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse Suricata ISO8601 timestamp with timezone offset."""
    try:
        # Handle both +0000 and Z suffixes
        ts_str = ts_str.replace("+0000", "+00:00").rstrip("Z")
        if "+" not in ts_str and ts_str[-6] != "+":
            ts_str += "+00:00"
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return datetime.utcnow()


def _extract_http(raw: dict[str, Any]) -> tuple[str, str, str, str, int]:
    """Extract HTTP fields from a raw EVE record."""
    http = raw.get("http", {})
    return (
        http.get("url", ""),
        http.get("http_method", ""),
        http.get("hostname", ""),
        http.get("http_user_agent", ""),
        int(http.get("status", 0) or 0),
    )


def _extract_dns(raw: dict[str, Any]) -> str:
    """Extract DNS query name from a raw EVE record."""
    dns = raw.get("dns", {})
    return dns.get("rrname", "")


def _extract_flow(raw: dict[str, Any]) -> tuple[int, int]:
    """Extract flow byte counts from a raw EVE record."""
    flow = raw.get("flow", {})
    return (
        int(flow.get("bytes_toserver", 0) or 0),
        int(flow.get("bytes_toclient", 0) or 0),
    )


def parse_record(raw: dict[str, Any]) -> AlertRecord | None:
    """
    Parse a single EVE JSON object into an AlertRecord.

    Returns None if the record is not an alert event or is malformed.
    """
    if raw.get("event_type") != "alert":
        return None

    alert_block = raw.get("alert", {})
    if not alert_block:
        return None

    ts = _parse_timestamp(raw.get("timestamp", ""))
    http_url, http_method, http_hostname, http_ua, http_status = _extract_http(raw)
    dns_query = _extract_dns(raw)
    bytes_to_server, bytes_to_client = _extract_flow(raw)

    return AlertRecord(
        timestamp=ts,
        flow_id=int(raw.get("flow_id", 0)),
        src_ip=raw.get("src_ip", "0.0.0.0"),
        src_port=int(raw.get("src_port", 0)),
        dest_ip=raw.get("dest_ip", "0.0.0.0"),
        dest_port=int(raw.get("dest_port", 0)),
        proto=raw.get("proto", "UNKNOWN"),
        signature_id=int(alert_block.get("signature_id", 0)),
        signature=alert_block.get("signature", "Unknown Signature"),
        category=alert_block.get("category", "Uncategorized"),
        severity=int(alert_block.get("severity", 3)),
        action=alert_block.get("action", "allowed"),
        app_proto=raw.get("app_proto", "unknown"),
        http_url=http_url,
        http_method=http_method,
        http_hostname=http_hostname,
        http_user_agent=http_ua,
        http_status=http_status,
        dns_query=dns_query,
        flow_bytes_toserver=bytes_to_server,
        flow_bytes_toclient=bytes_to_client,
        raw=raw,
    )


def parse_file(log_path: str | Path) -> list[AlertRecord]:
    """
    Parse a Suricata EVE JSON log file.

    Supports both newline-delimited JSON (one object per line) and
    a JSON array containing multiple EVE objects.

    Returns a list of AlertRecord objects sorted by timestamp.
    """
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    records: list[AlertRecord] = []
    content = path.read_text(encoding="utf-8").strip()

    if not content:
        return records

    # Try JSON array first
    if content.startswith("["):
        try:
            raw_list = json.loads(content)
            for raw in raw_list:
                record = parse_record(raw)
                if record:
                    records.append(record)
            records.sort(key=lambda r: r.timestamp)
            return records
        except json.JSONDecodeError:
            pass

    # Fall back to newline-delimited JSON (NDJSON)
    for line_no, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
            record = parse_record(raw)
            if record:
                records.append(record)
        except json.JSONDecodeError as exc:
            # Skip malformed lines, continue parsing
            import logging
            logging.warning("Skipping malformed JSON at line %d: %s", line_no, exc)

    records.sort(key=lambda r: r.timestamp)
    return records


def parse_json_list(data: list[dict[str, Any]]) -> list[AlertRecord]:
    """Parse a list of raw EVE dicts (e.g. from in-memory demo data)."""
    records = []
    for raw in data:
        record = parse_record(raw)
        if record:
            records.append(record)
    records.sort(key=lambda r: r.timestamp)
    return records
