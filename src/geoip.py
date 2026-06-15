from __future__ import annotations

from functools import lru_cache
from ipaddress import ip_address

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


IP_API_URL = "http://ip-api.com/json/{ip}"
IP_API_FIELDS = "status,message,query,country,city,isp"


@lru_cache(maxsize=512)
def lookup_geoip(ip: str, timeout_seconds: int = 5) -> dict[str, str] | None:
    try:
        parsed_ip = ip_address(ip)
    except ValueError:
        return _empty_result(ip, "invalid IP address")

    if not parsed_ip.is_global:
        return _empty_result(ip, "private or reserved IP address")

    if requests is None:
        return _empty_result(ip, "requests is not installed")

    try:
        response = requests.get(
            IP_API_URL.format(ip=ip),
            params={"fields": IP_API_FIELDS},
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return _empty_result(ip, "GeoIP lookup failed")

    if data.get("status") != "success":
        return _empty_result(ip, str(data.get("message") or "GeoIP lookup failed"))

    return {
        "query": str(data.get("query") or ip),
        "country": str(data.get("country") or "Unknown"),
        "city": str(data.get("city") or "Unknown"),
        "isp": str(data.get("isp") or "Unknown"),
        "status": "success",
        "message": "",
    }


def _empty_result(ip: str, message: str) -> dict[str, str]:
    return {
        "query": ip,
        "country": "N/A",
        "city": "N/A",
        "isp": "N/A",
        "status": "unavailable",
        "message": message,
    }
