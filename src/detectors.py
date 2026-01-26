import re
from collections import defaultdict

def detect_bruteforce_attempts(lines, threshold=10):
    ip_fail_count = defaultdict(int)
    alerts = []

    for line in lines:
        match = re.search(r"Failed login.*IP:\s*([\d.]+)", line)
        if match:
            ip = match.group(1)
            ip_fail_count[ip] += 1

    for ip, count in ip_fail_count.items():
        if count >= threshold:
            alerts.append({
                "type": "Brute Force Attempt",
                "ip": ip,
                "evidence": f"{count} failed login attempts from same IP",
                "score": 95
            })

    return alerts


def detect_credential_stuffing(lines, threshold=5):
    ip_users = defaultdict(set)
    alerts = []

    for line in lines:
        match = re.search(r"Failed login.*User:\s*(\S+).*IP:\s*([\d.]+)", line)
        if match:
            user = match.group(1)
            ip = match.group(2)
            ip_users[ip].add(user)

    for ip, users in ip_users.items():
        if len(users) >= threshold:
            alerts.append({
                "type": "Credential Stuffing Pattern",
                "ip": ip,
                "evidence": f"Failed logins across {len(users)} usernames",
                "score": 95
            })

    return alerts


def detect_suspicious_endpoints(lines, threshold=5):
    suspicious_paths = ["/admin", "/wp-admin", "/.env", "/phpmyadmin", "/login", "/config"]
    ip_hits = defaultdict(int)
    alerts = []

    for line in lines:
        match = re.search(r"GET\s+(\S+)\s+.*IP:\s*([\d.]+)", line)
        if match:
            path = match.group(1)
            ip = match.group(2)

            if any(susp in path for susp in suspicious_paths):
                ip_hits[ip] += 1

    for ip, hits in ip_hits.items():
        if hits >= threshold:
            alerts.append({
                "type": "Suspicious Endpoint Probing",
                "ip": ip,
                "evidence": f"{hits} suspicious endpoint hits (e.g. /admin, .env)",
                "score": 91
            })

    return alerts
