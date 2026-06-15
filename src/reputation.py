from __future__ import annotations

import os
from functools import lru_cache

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


@lru_cache(maxsize=512)
def lookup_virustotal_ip(ip: str, api_key: str | None = None, timeout_seconds: int = 8) -> dict[str, int] | None:
    key = api_key or os.getenv("VT_API_KEY")
    if not key or requests is None:
        return None

    try:
        response = requests.get(
            VIRUSTOTAL_IP_URL.format(ip=ip),
            headers={"x-apikey": key},
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return None

    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    if not isinstance(stats, dict):
        return None

    return {
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "timeout": int(stats.get("timeout", 0) or 0),
        "reputation": int(attributes.get("reputation", 0) or 0),
    }


@lru_cache(maxsize=512)
def lookup_abuseipdb(
    ip: str,
    api_key: str | None = None,
    max_age_days: int = 90,
    timeout_seconds: int = 8,
) -> dict[str, object] | None:
    key = api_key or os.getenv("ABUSEIPDB_API_KEY")
    if not key or requests is None:
        return None

    try:
        response = requests.get(
            ABUSEIPDB_CHECK_URL,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return None

    result = data.get("data")
    if not isinstance(result, dict):
        return None

    return {
        "ipAddress": result.get("ipAddress") or ip,
        "abuseConfidenceScore": int(result.get("abuseConfidenceScore", 0) or 0),
        "totalReports": int(result.get("totalReports", 0) or 0),
        "lastReportedAt": result.get("lastReportedAt") or "N/A",
        "countryCode": result.get("countryCode") or "N/A",
        "usageType": result.get("usageType") or "N/A",
        "isp": result.get("isp") or "N/A",
    }
