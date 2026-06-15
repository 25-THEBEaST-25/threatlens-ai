from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address

import pandas as pd

from .geoip import lookup_geoip
from .reputation import lookup_abuseipdb as reputation_lookup_abuseipdb
from .reputation import lookup_virustotal_ip


RESERVED_DOC_IPS = ("192.0.2.", "198.51.100.", "203.0.113.")
COMMON_SCANNER_UA_HINTS = ("nikto", "sqlmap", "nmap", "acunetix", "nessus", "masscan", "gobuster", "dirbuster")

MITRE_MAPPING = {
    "Brute Force Attempt": {
        "id": "T1110",
        "name": "Brute Force",
    },
    "Credential Stuffing Pattern": {
        "id": "T1110.004",
        "name": "Credential Stuffing",
    },
    "Suspicious Endpoint Probing": {
        "id": "T1595",
        "name": "Active Scanning",
    },
    "Successful Login After Failures": {
        "id": "T1078",
        "name": "Valid Accounts",
    },
}

UNKNOWN_MITRE = {
    "id": "N/A",
    "name": "Unmapped",
}


@dataclass(frozen=True)
class ThreatIntelSettings:
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None
    enable_geoip: bool = False
    enable_virustotal: bool = False
    enable_abuseipdb: bool = False
    abuseipdb_max_age_days: int = 90
    abuseipdb_timeout_seconds: int = 8
    virustotal_timeout_seconds: int = 8
    geoip_timeout_seconds: int = 5


def enrich_alerts(alert_df: pd.DataFrame, df: pd.DataFrame, settings: ThreatIntelSettings | None = None) -> pd.DataFrame:
    settings = settings or ThreatIntelSettings()
    if alert_df.empty:
        return attach_mitre_metadata(_ensure_alert_schema(alert_df))

    enriched = attach_mitre_metadata(_ensure_alert_schema(alert_df.copy()))
    intel_by_ip = {ip: summarize_ip_intel(ip, df, settings) for ip in enriched["ip"].dropna().unique()}
    enriched["threat_intel"] = enriched["ip"].map(lambda ip: intel_by_ip.get(ip, {}).get("summary", "No enrichment available."))
    enriched["intel_tags"] = enriched["ip"].map(lambda ip: ", ".join(intel_by_ip.get(ip, {}).get("tags", [])) or "none")
    enriched["score"] = enriched.apply(lambda row: min(100, int(row["score"]) + intel_by_ip.get(row["ip"], {}).get("score_boost", 0)), axis=1)
    enriched["risk"] = enriched["score"].apply(_risk_label)
    enriched["risk_score"] = enriched["score"]
    enriched["severity"] = enriched["risk"]
    enriched["confidence_score"] = enriched.apply(
        lambda row: min(100, int(row["confidence_score"]) + intel_by_ip.get(row["ip"], {}).get("confidence_boost", 0)),
        axis=1,
    )
    enriched["confidence"] = enriched["confidence_score"].apply(confidence_label)

    for column, key, default in (
        ("geo_country", "country", "N/A"),
        ("geo_city", "city", "N/A"),
        ("geo_isp", "isp", "N/A"),
        ("geo_status", "status", "unavailable"),
        ("vt_malicious", "malicious", 0),
        ("vt_suspicious", "suspicious", 0),
        ("vt_harmless", "harmless", 0),
        ("abuse_confidence_score", "abuseConfidenceScore", 0),
        ("abuse_total_reports", "totalReports", 0),
        ("abuse_last_reported", "lastReportedAt", "N/A"),
    ):
        source_name = "geo" if column.startswith("geo_") else "virustotal" if column.startswith("vt_") else "abuseipdb"
        enriched[column] = enriched["ip"].map(lambda ip, name=source_name, item=key, fallback=default: intel_by_ip.get(ip, {}).get(name, {}).get(item, fallback))

    enriched["geo"] = enriched["ip"].map(lambda ip: intel_by_ip.get(ip, {}).get("geo", {}))
    enriched["virustotal"] = enriched["ip"].map(lambda ip: intel_by_ip.get(ip, {}).get("virustotal", {}))
    enriched["abuseipdb"] = enriched["ip"].map(lambda ip: intel_by_ip.get(ip, {}).get("abuseipdb", {}))
    return enriched.sort_values(by=["score", "type"], ascending=[False, True]).reset_index(drop=True)


def summarize_ip_intel(ip: str, df: pd.DataFrame, settings: ThreatIntelSettings) -> dict[str, object]:
    tags: list[str] = []
    score_boost = 0
    confidence_boost = 0
    geo_result: dict[str, object] = {}
    virustotal_result: dict[str, object] = {}
    abuse_result: dict[str, object] = {}

    try:
        parsed_ip = ip_address(ip)
    except ValueError:
        return {"summary": "Invalid IP address.", "tags": ["invalid-ip"], "score_boost": 0, "confidence_boost": 0}

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
        confidence_boost += 4

    if settings.enable_geoip:
        geo_lookup = lookup_geoip(ip, settings.geoip_timeout_seconds)
        geo_result = geo_lookup or {}

    if settings.enable_virustotal:
        vt_lookup = lookup_virustotal_ip(ip, settings.virustotal_api_key, settings.virustotal_timeout_seconds)
        virustotal_result = vt_lookup or {}
        malicious = int(virustotal_result.get("malicious", 0) or 0)
        suspicious = int(virustotal_result.get("suspicious", 0) or 0)
        if malicious:
            tags.append("virustotal-malicious")
            score_boost += min(15, malicious * 3)
            confidence_boost += min(10, malicious * 2)
        elif suspicious:
            tags.append("virustotal-suspicious")
            score_boost += min(8, suspicious * 2)
            confidence_boost += min(6, suspicious)

    if settings.enable_abuseipdb:
        abuse_lookup = lookup_abuseipdb(ip, settings)
        abuse_result = abuse_lookup or {}
    if abuse_result:
        abuse_score = int(abuse_result.get("abuseConfidenceScore", 0))
        if abuse_score >= 75:
            tags.append("high-abuseipdb-score")
            score_boost += 12
            confidence_boost += 8
        elif abuse_score >= 25:
            tags.append("medium-abuseipdb-score")
            score_boost += 6
            confidence_boost += 4

    summary_parts = [
        f"{len(ip_events)} observed event(s)",
        f"{unique_users} username(s)",
        f"{unique_endpoints} endpoint(s)",
    ]
    if geo_result and geo_result.get("status") == "success":
        summary_parts.append(
            f"GeoIP {geo_result.get('country', 'N/A')}/{geo_result.get('city', 'N/A')} via {geo_result.get('isp', 'N/A')}"
        )
    if virustotal_result:
        summary_parts.append(
            "VirusTotal "
            f"malicious={virustotal_result.get('malicious', 0)}, "
            f"suspicious={virustotal_result.get('suspicious', 0)}, "
            f"harmless={virustotal_result.get('harmless', 0)}"
        )
    if abuse_result:
        summary_parts.append(f"AbuseIPDB score {abuse_result.get('abuseConfidenceScore', 0)}")
    if tags:
        summary_parts.append(f"tags: {', '.join(tags)}")

    return {
        "summary": "; ".join(summary_parts),
        "tags": tags,
        "score_boost": score_boost,
        "confidence_boost": confidence_boost,
        "geo": geo_result,
        "virustotal": virustotal_result,
        "abuseipdb": abuse_result,
    }


def lookup_abuseipdb(ip: str, settings: ThreatIntelSettings) -> dict[str, object] | None:
    return reputation_lookup_abuseipdb(
        ip,
        api_key=settings.abuseipdb_api_key,
        max_age_days=settings.abuseipdb_max_age_days,
        timeout_seconds=settings.abuseipdb_timeout_seconds,
    )


def attach_mitre_metadata(alert_df: pd.DataFrame) -> pd.DataFrame:
    if alert_df.empty and "mitre" in alert_df:
        return alert_df

    enriched = alert_df.copy()
    enriched["mitre"] = enriched["type"].map(lambda alert_type: MITRE_MAPPING.get(str(alert_type), UNKNOWN_MITRE).copy())
    enriched["mitre_id"] = enriched["mitre"].map(lambda value: value.get("id", "N/A"))
    enriched["mitre_name"] = enriched["mitre"].map(lambda value: value.get("name", "Unmapped"))
    return enriched


def confidence_label(score: int) -> str:
    if score >= 90:
        return "High"
    if score >= 70:
        return "Medium"
    return "Low"


def confidence_score_for_label(label: object) -> int:
    normalized = str(label or "").strip().lower()
    if normalized == "high":
        return 90
    if normalized == "medium":
        return 75
    if normalized == "low":
        return 50
    return 70


def _risk_label(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _ensure_alert_schema(alert_df: pd.DataFrame) -> pd.DataFrame:
    enriched = alert_df.copy()
    if "score" not in enriched:
        enriched["score"] = 0
    if "risk" not in enriched:
        enriched["risk"] = enriched["score"].apply(_risk_label)
    if "risk_score" not in enriched:
        enriched["risk_score"] = enriched["score"]
    if "severity" not in enriched:
        enriched["severity"] = enriched["risk"]
    if "confidence_score" not in enriched:
        enriched["confidence_score"] = enriched.get("confidence", pd.Series(dtype=object)).apply(confidence_score_for_label)
    enriched["confidence"] = enriched["confidence_score"].apply(confidence_label)
    return enriched
