from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network


DEFAULT_INTERNAL_NETWORKS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
)


@dataclass(frozen=True)
class DetectionSettings:
    brute_force_threshold: int = 8
    credential_stuffing_threshold: int = 4
    endpoint_probe_threshold: int = 3
    impossible_travel_minutes: int = 15
    successful_login_after_failures: int = 5
    allowlisted_ips: tuple[str, ...] = field(default_factory=tuple)
    allowlisted_networks: tuple[str, ...] = DEFAULT_INTERNAL_NETWORKS
    trusted_user_agents: tuple[str, ...] = field(default_factory=tuple)


def parse_csv_values(value: str | None) -> tuple[str, ...]:
    if not value:
        return tuple()
    return tuple(item.strip() for item in value.split(",") if item.strip())


def is_allowlisted_ip(ip: str | None, settings: DetectionSettings) -> bool:
    if not ip:
        return False

    if ip in settings.allowlisted_ips:
        return True

    try:
        parsed_ip = ip_address(ip)
    except ValueError:
        return False

    for network in settings.allowlisted_networks:
        try:
            if parsed_ip in ip_network(network, strict=False):
                return True
        except ValueError:
            continue

    return False


def is_trusted_user_agent(user_agent: str | None, settings: DetectionSettings) -> bool:
    if not user_agent:
        return False

    lowered = user_agent.lower()
    return any(agent.lower() in lowered for agent in settings.trusted_user_agents)

