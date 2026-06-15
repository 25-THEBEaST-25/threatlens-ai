from __future__ import annotations

import re
from ipaddress import ip_address

import pandas as pd


IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_REGEX = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
ENDPOINT_REGEX = re.compile(r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s\"']+)", re.IGNORECASE)
USERNAME_PATTERNS = (
    re.compile(r"\buser(?:name)?[=:]\s*([A-Za-z0-9_.@-]+)", re.IGNORECASE),
    re.compile(r"invalid user\s+([A-Za-z0-9_.@=-]+)", re.IGNORECASE),
    re.compile(r"for\s+([A-Za-z0-9_.@=-]+)\s+from\s+", re.IGNORECASE),
)


def extract_iocs(log_text: str | None = None, df: pd.DataFrame | None = None) -> pd.DataFrame:
    indicators: dict[tuple[str, str], None] = {}

    def add(indicator: object, indicator_type: str) -> None:
        if indicator is None:
            return
        value = str(indicator).strip().strip(".,);]")
        if not value:
            return
        indicators[(indicator_type, value)] = None

    if log_text:
        for line in log_text.splitlines():
            for match in IP_REGEX.finditer(line):
                value = match.group(0)
                if _is_valid_ip(value):
                    add(value, "IP Address")

            for match in URL_REGEX.finditer(line):
                add(match.group(0), "URL")

            for match in ENDPOINT_REGEX.finditer(line):
                add(match.group(1), "Endpoint")

            for pattern in USERNAME_PATTERNS:
                match = pattern.search(line)
                if match:
                    username = match.group(1)
                    if username.lower().startswith("user="):
                        username = username.split("=", 1)[1]
                    add(username.lower(), "Username")

    if df is not None and not df.empty:
        for column, indicator_type in (
            ("ip", "IP Address"),
            ("username", "Username"),
            ("endpoint", "Endpoint"),
        ):
            if column in df:
                for value in df[column].dropna().unique():
                    add(value, indicator_type)

        if "raw" in df:
            for raw_line in df["raw"].dropna().astype(str):
                for match in URL_REGEX.finditer(raw_line):
                    add(match.group(0), "URL")

    rows = [
        {"Indicator": indicator, "Type": indicator_type}
        for indicator_type, indicator in sorted(indicators.keys(), key=lambda item: (item[0], item[1]))
    ]
    return pd.DataFrame(rows, columns=["Indicator", "Type"])


def summarize_ioc_counts(ioc_df: pd.DataFrame) -> dict[str, int]:
    if ioc_df.empty:
        return {"Unique IPs": 0, "Endpoints": 0, "Usernames": 0, "URLs": 0}

    counts = ioc_df.groupby("Type")["Indicator"].nunique().to_dict()
    return {
        "Unique IPs": int(counts.get("IP Address", 0)),
        "Endpoints": int(counts.get("Endpoint", 0)),
        "Usernames": int(counts.get("Username", 0)),
        "URLs": int(counts.get("URL", 0)),
    }


def _is_valid_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True
