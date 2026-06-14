from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address

import pandas as pd

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


RESERVED_DOC_IPS = ("192.0.2.", "198.51.100.", "203.0.113.")
COMMON_SCANNER_UA_HINTS = ("nikto", "sqlmap", "nmap", "acunetix", "nessus", "masscan", "gobuster", "dirbuster")


@dataclass(frozen=True)
class ThreatIntelSettings:
    abuseipdb_api_key: str | None = None
    abuseipdb_max_age_days: int = 90
    abuseipdb_timeout_seconds: int = 8


def enrich_alerts(alert_df: pd.DataFrame, df: pd.DataFrame, settings: ThreatIntelSettings | None = None) -> pd.DataFrame:
    settings = settings or ThreatIntelSettings()
    if alert_df.empty:
        return alert_df

    enriched = alert_df.copy()
    intel_by_ip = {ip: summarize_ip_intel(ip, df, settings) for ip in enriched["ip"].dropna().unique()}
    enriched["threat_intel"] = enriched["ip"].map(lambda ip: intel_by_ip.get(ip, {}).get("summary", "No enrichment available."))
    enriched["intel_tags"] = enriched["ip"].map(lambda ip: ", ".join(intel_by_ip.get(ip, {}).get("tags", [])) or "none")
    enriched["score"] = enriched.apply(lambda row: min(100, int(row["score"]) + intel_by_ip.get(row["ip"], {}).get("score_boost", 0)), axis=1)
    enriched["risk"] = enriched["score"].apply(_risk_label)
    return enriched.sort_values(by=["score", "type"], ascending=[False, True]).reset_index(drop=True)


def summarize_ip_intel(ip: str, df: pd.DataFrame, settings: ThreatIntelSettings) -> dict[str, object]:
    tags: list[str] = []
    score_boost = 0

    try:
        parsed_ip = ip_address(ip)
    except ValueError:
        return {"summary": "Invalid IP address.", "tags": ["invalid-ip"], "score_boost": 0}

    if parsed_ip.is_private:
        tags.append("private-network")
    if parsed_ip.is_loopback:
        tags.append("loopback")
    if any(ip.startswith(prefix) for prefix in RESERVED_DOC_IPS):
        tags.append("documentation-range")

    ip_events = df[df["ip"] == ip]
    unique_users = int(ip_events["username"].nunique(dropna=True)) if "username" in ip_events else 0
    unique_endpoints = int(ip_events["endpoint"].nunique(dropna=True)) if "endpoint" in ip_events else 0
    scanner_agents = [
        agent for agent in ip_events.get("user_agent", pd.Series(dtype=object)).dropna().unique()
        if any(hint in str(agent).lower() for hint in COMMON_SCANNER_UA_HINTS)
    ]

    if unique_users >= 4:
        tags.append("many-usernames")
        score_boost += 5
    if unique_endpoints >= 6:
        tags.append("wide-endpoint-scan")
        score_boost += 5
    if scanner_agents:
        tags.append("scanner-user-agent")
        score_boost += 8

    abuse_result = lookup_abuseipdb(ip, settings)
    if abuse_result:
        abuse_score = int(abuse_result.get("abuseConfidenceScore", 0))
        if abuse_score >= 75:
            tags.append("high-abuseipdb-score")
            score_boost += 12
        elif abuse_score >= 25:
            tags.append("medium-abuseipdb-score")
            score_boost += 6

    summary_parts = [
        f"{len(ip_events)} observed event(s)",
        f"{unique_users} username(s)",
        f"{unique_endpoints} endpoint(s)",
    ]
    if abuse_result:
        summary_parts.append(f"AbuseIPDB score {abuse_result.get('abuseConfidenceScore', 0)}")
    if tags:
        summary_parts.append(f"tags: {', '.join(tags)}")

    return {"summary": "; ".join(summary_parts), "tags": tags, "score_boost": score_boost}


def lookup_abuseipdb(ip: str, settings: ThreatIntelSettings) -> dict[str, object] | None:
    if not settings.abuseipdb_api_key or requests is None:
        return None

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": settings.abuseipdb_max_age_days},
            timeout=settings.abuseipdb_timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException:
        return None

    result = data.get("data")
    return result if isinstance(result, dict) else None


def _risk_label(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"
