from __future__ import annotations

import pandas as pd

from .config import DetectionSettings, is_allowlisted_ip, is_trusted_user_agent
from .intelligence import attach_mitre_metadata, confidence_label, confidence_score_for_label
from .utils import is_suspicious_endpoint, parse_log_text, risk_label


def detect_threats(
    df: pd.DataFrame,
    settings: DetectionSettings | None = None,
) -> pd.DataFrame:
    settings = settings or DetectionSettings()
    alerts: list[dict[str, object]] = []

    if df.empty:
        return _alerts_frame(alerts)

    candidate_df = _filter_trusted_events(df, settings)

    alerts.extend(_detect_bruteforce(candidate_df, settings.brute_force_threshold))
    alerts.extend(_detect_credential_stuffing(candidate_df, settings.credential_stuffing_threshold))
    alerts.extend(_detect_success_after_failures(candidate_df, settings.successful_login_after_failures))
    alerts.extend(_detect_suspicious_endpoints(candidate_df, settings.endpoint_probe_threshold))

    alert_df = _alerts_frame(alerts)
    if not alert_df.empty:
        alert_df["risk"] = alert_df["score"].apply(risk_label)
        alert_df = alert_df.sort_values(by=["score", "type"], ascending=[False, True]).reset_index(drop=True)
    return alert_df


def detect_bruteforce_attempts(lines: list[str], threshold: int = 8) -> list[dict[str, object]]:
    return _detect_bruteforce(parse_log_text("\n".join(lines)), threshold)


def detect_credential_stuffing(lines: list[str], threshold: int = 4) -> list[dict[str, object]]:
    return _detect_credential_stuffing(parse_log_text("\n".join(lines)), threshold)


def detect_suspicious_endpoints(lines: list[str], threshold: int = 3) -> list[dict[str, object]]:
    return _detect_suspicious_endpoints(parse_log_text("\n".join(lines)), threshold)


def _detect_bruteforce(df: pd.DataFrame, threshold: int) -> list[dict[str, object]]:
    alerts = []
    fail_df = df[(df["event_type"] == "AUTH_FAIL") & df["ip"].notna()]

    for ip, count in fail_df["ip"].value_counts().items():
        if count >= threshold:
            alerts.append(
                {
                    "type": "Brute Force Attempt",
                    "ip": ip,
                    "evidence": f"{count} failed login attempts from the same IP",
                    "score": min(100, 30 + int(count) * 5),
                    "confidence_score": 95,
                    "confidence": "High",
                    "attack_stage": "Credential Access",
                    "recommended_action": "Rate-limit or block the source IP and enforce account lockout controls.",
                }
            )

    return alerts


def _detect_credential_stuffing(df: pd.DataFrame, threshold: int) -> list[dict[str, object]]:
    alerts = []
    fail_df = df[(df["event_type"] == "AUTH_FAIL") & df["ip"].notna() & df["username"].notna()]

    for ip, group in fail_df.groupby("ip"):
        user_count = group["username"].nunique()
        if user_count >= threshold:
            alerts.append(
                {
                    "type": "Credential Stuffing Pattern",
                    "ip": ip,
                    "evidence": f"Failed logins across {user_count} distinct usernames",
                    "score": min(100, 45 + int(user_count) * 10),
                    "confidence_score": 92,
                    "confidence": "High",
                    "attack_stage": "Credential Access",
                    "recommended_action": "Enable MFA, CAPTCHA or progressive delays, and review accounts targeted by the source IP.",
                }
            )

    return alerts


def _detect_suspicious_endpoints(df: pd.DataFrame, threshold: int) -> list[dict[str, object]]:
    alerts = []
    web_df = df[df["endpoint"].notna()].copy()

    if web_df.empty:
        return alerts

    suspicious_hits = web_df[web_df["endpoint"].apply(is_suspicious_endpoint)]

    for ip, count in suspicious_hits["ip"].dropna().value_counts().items():
        if count >= threshold:
            alerts.append(
                {
                    "type": "Suspicious Endpoint Probing",
                    "ip": ip,
                    "evidence": f"{count} suspicious endpoint hits such as admin panels, config files, or traversal paths",
                    "score": min(100, 35 + int(count) * 8),
                    "confidence_score": 78,
                    "confidence": "Medium",
                    "attack_stage": "Reconnaissance",
                    "recommended_action": "Block or challenge the source IP and verify exposed admin/config routes are protected.",
                }
            )

    return alerts


def _detect_success_after_failures(df: pd.DataFrame, threshold: int) -> list[dict[str, object]]:
    alerts = []
    if "timestamp" not in df or df["timestamp"].notna().sum() == 0:
        return alerts

    auth_df = df[df["event_type"].isin(["AUTH_FAIL", "AUTH_SUCCESS"]) & df["ip"].notna()].copy()
    auth_df = auth_df.sort_values(["ip", "timestamp", "line_no"])

    for ip, group in auth_df.groupby("ip"):
        failures = group[group["event_type"] == "AUTH_FAIL"]
        successes = group[group["event_type"] == "AUTH_SUCCESS"]
        if failures.empty or successes.empty:
            continue

        first_success = successes.iloc[0]
        prior_failures = failures[failures["line_no"] < first_success["line_no"]]
        if len(prior_failures) >= threshold:
            username = first_success.get("username") or "unknown user"
            alerts.append(
                {
                    "type": "Successful Login After Failures",
                    "ip": ip,
                    "evidence": f"{len(prior_failures)} failures were followed by a successful login as {username}",
                    "score": min(100, 70 + int(len(prior_failures)) * 3),
                    "confidence_score": 93,
                    "confidence": "High",
                    "attack_stage": "Initial Access",
                    "recommended_action": "Immediately review the account session, rotate credentials, and confirm whether the login was legitimate.",
                }
            )

    return alerts


def _filter_trusted_events(df: pd.DataFrame, settings: DetectionSettings) -> pd.DataFrame:
    trusted_ip_mask = df["ip"].apply(lambda value: is_allowlisted_ip(value, settings))
    trusted_ua_mask = df["user_agent"].apply(lambda value: is_trusted_user_agent(value, settings))
    return df[~(trusted_ip_mask | trusted_ua_mask)].copy()


def _alerts_frame(alerts: list[dict[str, object]]) -> pd.DataFrame:
    columns = [
        "risk",
        "severity",
        "type",
        "ip",
        "evidence",
        "score",
        "risk_score",
        "confidence",
        "confidence_score",
        "attack_stage",
        "recommended_action",
        "mitre",
        "mitre_id",
        "mitre_name",
    ]
    alert_df = pd.DataFrame(alerts)
    if alert_df.empty:
        return pd.DataFrame(columns=columns)

    alert_df["risk"] = alert_df["score"].apply(risk_label)
    alert_df["severity"] = alert_df["risk"]
    alert_df["risk_score"] = alert_df["score"]
    if "confidence_score" not in alert_df:
        alert_df["confidence_score"] = alert_df["confidence"].apply(confidence_score_for_label)
    alert_df["confidence"] = alert_df["confidence_score"].apply(confidence_label)
    alert_df = attach_mitre_metadata(alert_df)
    return alert_df.reindex(columns=columns, fill_value="")
