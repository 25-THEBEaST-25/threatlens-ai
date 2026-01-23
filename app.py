import streamlit as st
import pandas as pd
import re
from collections import defaultdict
from datetime import datetime




st.set_page_config(page_title="ThreatLens AI", layout="wide")

col1, col2 = st.columns([1, 1])

with col1:
    demo_clicked = st.button("⚡ Try Demo Log (No upload needed)")

with col2:
    reset_clicked = st.button("🧹 Reset / Clear")

if reset_clicked:
    for key in ["log_text", "alerts_df", "filtered_df", "risk_level", "ip_filter"]:
        if key in st.session_state:
            del st.session_state[key]
    st.rerun()

st.title("🛡️ ThreatLens AI")
st.write("AI-powered Cybersecurity Log Analyzer (MVP)")
st.info("🔒 Privacy note: Your log is processed in-memory for analysis. Avoid uploading sensitive logs containing passwords, tokens, API keys, or private customer data. For maximum privacy, run locally.")


# -----------------------------
# Helpers
# -----------------------------
SUSPICIOUS_PATH_KEYWORDS = [
    "/admin", "/wp-login.php", "/wp-admin", "/phpmyadmin",
    "../", "..\\", "/etc/passwd", "cmd.exe", "powershell",
    "/.env", "/config", "/login", "/robots.txt"
]

AUTH_FAIL_KEYWORDS = ["failed password", "invalid password", "login failed", "authentication failure", "failed login"]
AUTH_SUCCESS_KEYWORDS = ["accepted password", "login successful", "authenticated", "success login"]

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ip(line: str):
    m = IP_REGEX.search(line)
    return m.group(0) if m else None


def guess_event_type(line: str):
    low = line.lower()
    if any(k in low for k in AUTH_FAIL_KEYWORDS):
        return "AUTH_FAIL"
    if any(k in low for k in AUTH_SUCCESS_KEYWORDS):
        return "AUTH_SUCCESS"
    return "OTHER"


def find_endpoint(line: str):
    m = re.search(r"(GET|POST|PUT|DELETE|PATCH)\s+(\S+)", line)
    if m:
        return m.group(2)
    return None


def is_suspicious_endpoint(endpoint: str):
    if not endpoint:
        return False
    low = endpoint.lower()
    return any(k in low for k in SUSPICIOUS_PATH_KEYWORDS)


def risk_label(score: int):
    if score >= 80:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def risk_color(label: str):
    return {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟢"}.get(label, "⚪")


# -----------------------------
# UI
# -----------------------------
uploaded_file = st.file_uploader("Upload a log file (.log / .txt)", type=["log", "txt"])

log_text = None

if demo_clicked:
    with open("sample_auth.log", "r", encoding="utf-8", errors="ignore") as f:
        log_text = f.read()
    st.session_state["log_text"] = log_text
    st.info("✅ Demo log loaded: sample_auth.log")

elif uploaded_file:
    log_text = uploaded_file.read().decode("utf-8", errors="ignore")
    st.session_state["log_text"] = log_text
    st.success("✅ File loaded successfully!")

if log_text:
    # Parse events
    events = []
    for idx, line in enumerate(log_text.splitlines()):
        ip = extract_ip(line)
        evt = guess_event_type(line)
        endpoint = find_endpoint(line)

        events.append({
            "line_no": idx + 1,
            "ip": ip,
            "event_type": evt,
            "endpoint": endpoint,
            "raw": line
        })

    df = pd.DataFrame(events)

    # -----------------------------
    # Detection Rules
    # -----------------------------
    alerts = []

    # Rule 1: Brute force (many AUTH_FAIL from same IP)
    fail_df = df[df["event_type"] == "AUTH_FAIL"].copy()
    if not fail_df.empty:
        fail_counts = fail_df["ip"].value_counts(dropna=True)
        for ip, cnt in fail_counts.items():
            if ip and cnt >= 8:
                score = min(100, 30 + cnt * 5)
                alerts.append({
                    "type": "Brute Force Attempt",
                    "ip": ip,
                    "evidence": f"{cnt} failed login attempts from same IP",
                    "score": score
                })

    # Rule 2: Credential stuffing (same IP tries multiple usernames)
    def extract_username(line: str):
        low = line.lower()
        m1 = re.search(r"user=([a-zA-Z0-9_.-]+)", low)
        if m1:
            return m1.group(1)
        m2 = re.search(r"for\s+([a-zA-Z0-9_.-]+)", low)
        if m2:
            return m2.group(1)
        return None

    ip_to_users = defaultdict(set)
    for row in events:
        if row["ip"] and row["event_type"] == "AUTH_FAIL":
            u = extract_username(row["raw"])
            if u:
                ip_to_users[row["ip"]].add(u)

    for ip, users in ip_to_users.items():
        if len(users) >= 4:
            score = min(100, 45 + len(users) * 10)
            alerts.append({
                "type": "Credential Stuffing Pattern",
                "ip": ip,
                "evidence": f"Failed logins across {len(users)} usernames",
                "score": score
            })

    # Rule 3: Suspicious endpoints
    web_df = df[df["endpoint"].notna()].copy()
    if not web_df.empty:
        suspicious_hits = web_df[web_df["endpoint"].apply(is_suspicious_endpoint)]
        if not suspicious_hits.empty:
            top_ips = suspicious_hits["ip"].value_counts(dropna=True)
            for ip, cnt in top_ips.items():
                if ip and cnt >= 3:
                    score = min(100, 35 + cnt * 8)
                    alerts.append({
                        "type": "Suspicious Endpoint Probing",
                        "ip": ip,
                        "evidence": f"{cnt} suspicious endpoint hits (e.g. /admin, ../, /.env)",
                        "score": score
                    })

    # -----------------------------
    # Quick Stats (Overview)
    # -----------------------------
    st.subheader("📊 Overview")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total log lines", len(df))
    c2.metric("Auth fails", int((df["event_type"] == "AUTH_FAIL").sum()))
    c3.metric("Auth success", int((df["event_type"] == "AUTH_SUCCESS").sum()))
    c4.metric("Unique IPs", int(df["ip"].nunique(dropna=True)))

    st.markdown("### Top IPs in Logs")
    top_ip_df = (
        df["ip"]
        .dropna()
        .value_counts()
        .head(5)
        .reset_index()
    )
    top_ip_df.columns = ["ip", "count"]
    st.dataframe(top_ip_df, width="stretch", hide_index=True)
    st.bar_chart(top_ip_df.set_index("ip"))

    # Alerts table
    st.subheader("🚨 Alerts")

    if not alerts:
        st.success("✅ No high-confidence threats detected (based on current rules).")
    else:
        alert_df = pd.DataFrame(alerts)
        alert_df["risk"] = alert_df["score"].apply(risk_label)
        alert_df["risk_badge"] = alert_df["risk"].apply(risk_color) + " " + alert_df["risk"]

        # Sort by score high -> low
        alert_df = alert_df.sort_values(by="score", ascending=False)

        # -----------------------------
        # Sidebar Filters
        # -----------------------------
        st.sidebar.header("🔎 Filters")

        risk_options = ["ALL"] + sorted(alert_df["risk"].unique().tolist())
        selected_risk = st.sidebar.selectbox("Risk Level", risk_options, key="risk_level")

        unique_ips = sorted(alert_df["ip"].unique().tolist())
        ip_options = ["ALL"] + unique_ips
        selected_ip = st.sidebar.selectbox("IP Address", ip_options, key="ip_filter")

        filtered_alerts = alert_df.copy()

        if selected_risk != "ALL":
            filtered_alerts = filtered_alerts[filtered_alerts["risk"] == selected_risk]

        if selected_ip != "ALL":
            filtered_alerts = filtered_alerts[filtered_alerts["ip"] == selected_ip]

        c1, c2, c3 = st.columns(3)
        c1.metric("Total Alerts", len(alert_df))
        c2.metric("High Risk", int((alert_df["risk"] == "HIGH").sum()))
        c3.metric("Medium Risk", int((alert_df["risk"] == "MEDIUM").sum()))

        st.dataframe(
            filtered_alerts[["risk_badge", "type", "ip", "evidence", "score"]],
            width="stretch",
            hide_index=True
        )

        # -----------------------------
        # AI-style Explanation + Copy
        # -----------------------------
        st.subheader("🧠 AI-style Explanation (MVP)")

        summary_text = "\n".join([
            f"[{row['risk_badge']}] {row['type']} | IP: {row['ip']} | Score: {row['score']} | Evidence: {row['evidence']}"
            for _, row in alert_df.iterrows()
        ])

        st.code(summary_text)
        st.download_button(
            label="📋 Copy Summary to Clipboard",
            data=summary_text,
            file_name="alert_summary.txt",
            mime="text/plain"
        )
        for _, row in filtered_alerts.iterrows():
            st.markdown(
                f"""
**{row['risk_badge']} — {row['type']}**  
**IP:** `{row['ip']}`  
**Why it's suspicious:** {row['evidence']}  
**Suggested action:** Block/Rate-limit the IP, enable account lockout, monitor additional activity.
"""
            )

        # -----------------------------
        # Report Download (Markdown)
        # -----------------------------
        st.subheader("📥 Download Incident Report")

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report_md = f"""# ThreatLens AI — Incident Report

**Generated:** {now}

## Summary
- Total alerts: {len(alert_df)}
- High risk: {(alert_df["risk"] == "HIGH").sum()}
- Medium risk: {(alert_df["risk"] == "MEDIUM").sum()}
- Low risk: {(alert_df["risk"] == "LOW").sum()}

## Alerts
"""

        for _, row in alert_df.iterrows():
            report_md += f"""
### {row['risk']} — {row['type']}
- **IP:** {row['ip']}
- **Evidence:** {row['evidence']}
- **Risk Score:** {row['score']}
- **Recommended Action:** Block/Rate-limit IP, enable lockout, monitor activity.
"""

        st.download_button(
            label="⬇️ Download Report (.md)",
            data=report_md,
            file_name="threatlens_incident_report.md",
            mime="text/markdown"
        )
