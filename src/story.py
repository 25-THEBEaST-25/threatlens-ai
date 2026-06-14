from __future__ import annotations

import pandas as pd


def build_attack_story(df: pd.DataFrame, alert_df: pd.DataFrame) -> list[str]:
    if df.empty:
        return ["No events were available to build an attack story."]

    if alert_df.empty:
        return ["No high-confidence attack chain was detected. Continue monitoring for repeated failures or suspicious endpoint access."]

    story: list[str] = []
    most_suspicious_ip = str(alert_df.iloc[0]["ip"])
    ip_events = df[df["ip"] == most_suspicious_ip].sort_values(["timestamp", "line_no"], na_position="last")
    alert_types = alert_df[alert_df["ip"] == most_suspicious_ip]["type"].tolist()

    story.append(f"Primary suspect: {most_suspicious_ip}. It triggered {len(alert_types)} alert type(s): {', '.join(alert_types)}.")

    fail_count = int((ip_events["event_type"] == "AUTH_FAIL").sum())
    success_count = int((ip_events["event_type"] == "AUTH_SUCCESS").sum())
    usernames = sorted(ip_events["username"].dropna().unique().tolist())
    endpoints = sorted(ip_events["endpoint"].dropna().unique().tolist())

    if fail_count:
        target_text = f" across {len(usernames)} username(s)" if usernames else ""
        story.append(f"It produced {fail_count} failed authentication event(s){target_text}.")

    if success_count:
        story.append(f"It later produced {success_count} successful authentication event(s), which should be treated as possible initial access.")

    if endpoints:
        sample_endpoints = ", ".join(endpoints[:5])
        suffix = "..." if len(endpoints) > 5 else ""
        story.append(f"It touched {len(endpoints)} unique endpoint(s): {sample_endpoints}{suffix}")

    first_ts = ip_events["timestamp"].dropna().min()
    last_ts = ip_events["timestamp"].dropna().max()
    if pd.notna(first_ts) and pd.notna(last_ts):
        story.append(f"Observed window: {first_ts} to {last_ts}.")

    story.append("Recommended response: contain the source, check for successful login after failures, rotate exposed credentials, and review adjacent activity.")
    return story


def build_investigation_commands(alert_df: pd.DataFrame) -> list[str]:
    if alert_df.empty:
        return [
            "grep -Ei 'failed|invalid|accepted|login' auth.log",
            "grep -Ei 'admin|wp-login|\\.env|phpmyadmin|passwd' access.log",
        ]

    commands: list[str] = []
    for ip in alert_df["ip"].dropna().unique()[:5]:
        commands.extend(
            [
                f"grep '{ip}' auth.log",
                f"grep '{ip}' access.log",
                f"last | grep '{ip}'",
                f"journalctl -u ssh --since '24 hours ago' | grep '{ip}'",
            ]
        )

    return commands


def build_prevention_checklist(alert_df: pd.DataFrame) -> list[str]:
    if alert_df.empty:
        return ["Keep audit logging enabled.", "Review allowlists quarterly.", "Monitor unusual authentication spikes."]

    checklist = [
        "Block, rate-limit, or challenge high-risk IPs at the edge.",
        "Enable MFA for privileged and externally exposed accounts.",
        "Configure account lockout or progressive delays for repeated failures.",
        "Verify admin/config endpoints are not publicly exposed.",
        "Rotate credentials for any account with suspicious successful login activity.",
        "Create a case owner and review status before closing the incident.",
    ]

    if "Successful Login After Failures" not in alert_df["type"].tolist():
        checklist.append("Search for successful logins shortly after the detected failure burst.")

    return checklist

