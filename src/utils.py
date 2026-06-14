from __future__ import annotations

import re
import json
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SUSPICIOUS_PATH_KEYWORDS = (
    "/admin",
    "/wp-login.php",
    "/wp-admin",
    "/phpmyadmin",
    "../",
    "..\\",
    "/etc/passwd",
    "cmd.exe",
    "powershell",
    "/.env",
    "/config",
    "/login",
    "/robots.txt",
)

AUTH_FAIL_KEYWORDS = (
    "failed password",
    "invalid password",
    "login failed",
    "authentication failure",
    "failed login",
)

AUTH_SUCCESS_KEYWORDS = (
    "accepted password",
    "login successful",
    "authenticated",
    "success login",
    "successful login",
    "logged in",
)

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ISO_TS_REGEX = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")
SYSLOG_TS_REGEX = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
NGINX_TS_REGEX = re.compile(r"\[(\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2})\s+[+-]\d{4}\]")
HTTP_METHOD_REGEX = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)", re.IGNORECASE)
STATUS_REGEX = re.compile(r'"\s+(\d{3})(?:\s|$)')
USER_AGENT_REGEX = re.compile(r'"[^"]*"\s+\d{3}\s+\S+\s+"[^"]*"\s+"([^"]*)"')
USERNAME_PATTERNS = (
    re.compile(r"\buser(?:name)?[=:]\s*([A-Za-z0-9_.@-]+)", re.IGNORECASE),
    re.compile(r"invalid user\s+([A-Za-z0-9_.@=-]+)", re.IGNORECASE),
    re.compile(r"for\s+([A-Za-z0-9_.@=-]+)\s+from\s+", re.IGNORECASE),
)
EVENT_TYPE_ALIASES = {
    "authentication_failure": "AUTH_FAIL",
    "auth_failure": "AUTH_FAIL",
    "login_failure": "AUTH_FAIL",
    "failed_login": "AUTH_FAIL",
    "authentication_success": "AUTH_SUCCESS",
    "auth_success": "AUTH_SUCCESS",
    "login_success": "AUTH_SUCCESS",
    "successful_login": "AUTH_SUCCESS",
}


def extract_timestamp(line: str, default_year: int | None = None) -> datetime | None:
    match = ISO_TS_REGEX.search(line)
    if match:
        value = match.group(1).replace("T", " ")
        return _parse_datetime(value, "%Y-%m-%d %H:%M:%S")

    match = NGINX_TS_REGEX.search(line)
    if match:
        return _parse_datetime(match.group(1), "%d/%b/%Y:%H:%M:%S")

    match = SYSLOG_TS_REGEX.search(line)
    if match:
        year = default_year or datetime.now().year
        return _parse_datetime(f"{year} {match.group(1)}", "%Y %b %d %H:%M:%S")

    return None


def extract_ip(line: str) -> str | None:
    json_value = _load_json(line)
    if json_value:
        for key in ("src_ip", "source_ip", "client_ip", "remote_addr", "ip"):
            value = json_value.get(key)
            if value and _is_valid_ip(str(value)):
                return str(value)

    for match in IP_REGEX.finditer(line):
        candidate = match.group(0)
        if _is_valid_ip(candidate):
            return candidate
    return None


def extract_username(line: str) -> str | None:
    json_value = _load_json(line)
    if json_value:
        for key in ("username", "user", "account", "principal"):
            value = json_value.get(key)
            if value:
                return str(value).strip().lower()

    for pattern in USERNAME_PATTERNS:
        match = pattern.search(line)
        if match:
            username = match.group(1).strip()
            if username.lower().startswith("user="):
                username = username.split("=", 1)[1]
            return username.lower()
    return None


def find_endpoint(line: str) -> str | None:
    json_value = _load_json(line)
    if json_value:
        for key in ("path", "url", "uri", "request_uri", "endpoint"):
            value = json_value.get(key)
            if value:
                return str(value)

    match = HTTP_METHOD_REGEX.search(line)
    return match.group(2) if match else None


def guess_event_type(line: str) -> str:
    json_value = _load_json(line)
    if json_value:
        event_name = str(json_value.get("event_type") or json_value.get("event") or json_value.get("action") or "")
        normalized = event_name.lower().replace(" ", "_").replace("-", "_")
        if normalized in EVENT_TYPE_ALIASES:
            return EVENT_TYPE_ALIASES[normalized]

    lowered = line.lower()
    if any(keyword in lowered for keyword in AUTH_FAIL_KEYWORDS):
        return "AUTH_FAIL"
    if any(keyword in lowered for keyword in AUTH_SUCCESS_KEYWORDS):
        return "AUTH_SUCCESS"
    return "OTHER"


def extract_status_code(line: str) -> int | None:
    json_value = _load_json(line)
    if json_value:
        for key in ("status", "status_code", "http_status"):
            value = json_value.get(key)
            if value is not None:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return None

    match = STATUS_REGEX.search(line)
    if not match:
        return None
    return int(match.group(1))


def extract_user_agent(line: str) -> str | None:
    json_value = _load_json(line)
    if json_value:
        value = json_value.get("user_agent") or json_value.get("ua")
        return str(value) if value else None

    match = USER_AGENT_REGEX.search(line)
    return match.group(1) if match else None


def detect_log_format(line: str) -> str:
    if _load_json(line):
        return "json"
    if NGINX_TS_REGEX.search(line) and HTTP_METHOD_REGEX.search(line):
        return "web_access"
    if "sshd" in line.lower() or SYSLOG_TS_REGEX.search(line):
        return "syslog"
    if ISO_TS_REGEX.search(line):
        return "iso_text"
    return "unknown"


def is_suspicious_endpoint(endpoint: str | None) -> bool:
    if not endpoint:
        return False
    lowered = endpoint.lower()
    return any(keyword in lowered for keyword in SUSPICIOUS_PATH_KEYWORDS)


def risk_label(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def risk_color(label: str) -> str:
    return {"HIGH": "RED", "MEDIUM": "AMBER", "LOW": "GREEN"}.get(label, "GRAY")


def parse_log_text(log_text: str) -> pd.DataFrame:
    events = []
    default_year = datetime.now().year

    for idx, line in enumerate(log_text.splitlines()):
        if not line.strip():
            continue

        events.append(
            {
                "line_no": idx + 1,
                "timestamp": extract_timestamp(line, default_year=default_year),
                "ip": extract_ip(line),
                "username": extract_username(line),
                "event_type": guess_event_type(line),
                "endpoint": find_endpoint(line),
                "status_code": extract_status_code(line),
                "user_agent": extract_user_agent(line),
                "format": detect_log_format(line),
                "raw": line,
            }
        )

    return pd.DataFrame(
        events,
        columns=[
            "line_no",
            "timestamp",
            "ip",
            "username",
            "event_type",
            "endpoint",
            "status_code",
            "user_agent",
            "format",
            "raw",
        ],
    )


def top_ip_counts(df: pd.DataFrame, limit: int = 5) -> pd.DataFrame:
    if df.empty or "ip" not in df:
        return pd.DataFrame(columns=["ip", "count"])

    top_ips = df["ip"].dropna().value_counts().head(limit).reset_index()
    top_ips.columns = ["ip", "count"]
    return top_ips


def load_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _parse_datetime(value: str, fmt: str) -> datetime | None:
    try:
        return datetime.strptime(value, fmt)
    except ValueError:
        return None


def _is_valid_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _load_json(line: str) -> dict[str, object] | None:
    stripped = line.strip()
    if not stripped.startswith("{"):
        return None
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None
