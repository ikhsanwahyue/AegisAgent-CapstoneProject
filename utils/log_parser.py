"""
utils/log_parser.py
-------------------
Regex-based log parser for AegisAgent.

Parses Apache/Nginx-style Combined Log Format entries and extracts
structured fields: IP, timestamp, HTTP method, endpoint, status code,
and any query parameters embedded in the request URI.

Suspicious-log filter reduces token volume sent to the LLM by dropping
clean 200-OK GET requests that carry no anomaly signals.
"""

import re
from typing import Any

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Combined Log Format:
#   IP - - [timestamp] "METHOD /path?params HTTP/1.x" STATUS size "ref" "ua"
_LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'           # IP address
    r'\s+-\s+-\s+'
    r'\[(?P<timestamp>[^\]]+)\]'                   # timestamp in brackets
    r'\s+"(?P<method>[A-Z]+)'                      # HTTP method
    r'\s+(?P<path>[^\s"]*)'                        # request path + query string
    r'\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})'                           # status code
    r'\s+(?P<size>\d+|-)',                          # response size (or '-')
    re.IGNORECASE,
)

# Query-string key=value pairs (handles both & and ; delimiters)
_PARAM_PATTERN = re.compile(r'[?&;](?P<key>[^=&;]+)=(?P<value>[^&;]*)')

# SQL-injection heuristic keywords in URI
_SQLI_PATTERN = re.compile(
    r"(select|union|insert|update|delete|drop|--|;|'|%27|%22|xp_|exec)",
    re.IGNORECASE,
)

# XSS heuristic
_XSS_PATTERN = re.compile(r'(<script|javascript:|on\w+=|alert\()', re.IGNORECASE)

# Directory traversal
_TRAVERSAL_PATTERN = re.compile(r'(\.\./|\.\.\\|%2e%2e)', re.IGNORECASE)

# Common brute-force / scanner UA strings
_SCANNER_UA_PATTERN = re.compile(
    r'(nikto|sqlmap|nmap|masscan|zgrab|hydra|medusa|nessus|acunetix|burpsuite)',
    re.IGNORECASE,
)

# HTTP methods that are unusual on standard web servers
_SUSPICIOUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "OPTIONS"}

# Status codes that indicate authentication or authorisation failure
_AUTH_FAIL_CODES = {401, 403, 407}

# Status codes that indicate server errors worth investigating
_SERVER_ERROR_CODES = set(range(500, 512))


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def parse_logs(raw_log_text: str) -> list[dict[str, Any]]:
    """Parse raw log text into a list of structured log entry dicts.

    Each entry contains:
        ip, timestamp, method, path, status (int), size, params (dict),
        raw_line (str).

    Lines that do not match the Combined Log Format are silently skipped.

    Args:
        raw_log_text: Multi-line string of raw server/network logs.

    Returns:
        List of parsed log entry dictionaries, preserving original order.
    """
    if not raw_log_text or not raw_log_text.strip():
        return []

    entries: list[dict[str, Any]] = []
    for line in raw_log_text.splitlines():
        line = line.strip()
        if not line:
            continue

        match = _LOG_PATTERN.search(line)
        if not match:
            # Emit a minimal skeleton so the agent can still see the raw line
            entries.append({"raw_line": line, "parse_error": True})
            continue

        groups = match.groupdict()
        params: dict[str, str] = {
            m.group("key"): m.group("value")
            for m in _PARAM_PATTERN.finditer(groups["path"])
        }

        try:
            status_code = int(groups["status"])
        except ValueError:
            status_code = 0

        entries.append(
            {
                "ip": groups["ip"],
                "timestamp": groups["timestamp"],
                "method": groups["method"].upper(),
                "path": groups["path"].split("?")[0],
                "query_string": (
                    groups["path"].split("?", 1)[1]
                    if "?" in groups["path"]
                    else ""
                ),
                "params": params,
                "status": status_code,
                "size": groups["size"],
                "raw_line": line,
                "parse_error": False,
            }
        )

    return entries


def filter_suspicious_logs(
    parsed_entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Filter parsed log entries, retaining only those with anomaly signals.

    Retention criteria (any one is sufficient):
        - Status code in auth-failure set (401, 403, 407)
        - Status code in server-error range (5xx)
        - Status code 4xx other than 200/304/206 (client errors)
        - HTTP method is uncommon (PUT, DELETE, TRACE, CONNECT, PATCH, OPTIONS)
        - Request path/query contains SQL-injection pattern
        - Request path/query contains XSS pattern
        - Request path/query contains directory-traversal pattern
        - Entries that failed parsing (preserve for manual review)

    Args:
        parsed_entries: Output of :func:`parse_logs`.

    Returns:
        Filtered list; may be empty if no anomalies were detected.
    """
    suspicious: list[dict[str, Any]] = []

    for entry in parsed_entries:
        # Always keep unparseable lines for the analyst to review
        if entry.get("parse_error"):
            suspicious.append(entry)
            continue

        status = entry.get("status", 0)
        method = entry.get("method", "")
        full_path = entry.get("path", "") + entry.get("query_string", "")

        reasons: list[str] = []

        if status in _AUTH_FAIL_CODES:
            reasons.append(f"auth_failure:{status}")
        if status in _SERVER_ERROR_CODES:
            reasons.append(f"server_error:{status}")
        if 400 <= status < 500 and status not in {200, 304, 206, 301, 302}:
            reasons.append(f"client_error:{status}")
        if method in _SUSPICIOUS_METHODS:
            reasons.append(f"unusual_method:{method}")
        if _SQLI_PATTERN.search(full_path):
            reasons.append("sqli_pattern")
        if _XSS_PATTERN.search(full_path):
            reasons.append("xss_pattern")
        if _TRAVERSAL_PATTERN.search(full_path):
            reasons.append("traversal_pattern")

        if reasons:
            flagged = dict(entry)
            flagged["anomaly_reasons"] = reasons
            suspicious.append(flagged)

    return suspicious


def format_for_llm(filtered_entries: list[dict[str, Any]], max_entries: int = 150) -> str:
    """Serialise filtered log entries into a compact, token-efficient string
    suitable for inclusion in an LLM prompt.

    Args:
        filtered_entries: Output of :func:`filter_suspicious_logs`.
        max_entries: Hard cap to avoid exceeding context window limits.

    Returns:
        Formatted multi-line string representation of the log entries.
    """
    if not filtered_entries:
        return "(no suspicious log entries detected)"

    lines: list[str] = []
    for i, entry in enumerate(filtered_entries[:max_entries]):
        if entry.get("parse_error"):
            lines.append(f"[{i+1:03d}] RAW(unparsed): {entry['raw_line']}")
            continue

        reasons = ", ".join(entry.get("anomaly_reasons", []))
        params_str = ""
        if entry.get("params"):
            params_str = " params=" + str(entry["params"])

        lines.append(
            f"[{i+1:03d}] {entry['timestamp']} | {entry['ip']} | "
            f"{entry['method']} {entry['path']}{params_str} | "
            f"HTTP {entry['status']} | flags=[{reasons}]"
        )

    if len(filtered_entries) > max_entries:
        lines.append(
            f"\n... {len(filtered_entries) - max_entries} additional entries truncated "
            f"(total suspicious: {len(filtered_entries)})"
        )

    return "\n".join(lines)
