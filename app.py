import streamlit as st
import pandas as pd
import re
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode
from collections import defaultdict
from datetime import datetime
from openai import OpenAI

# -----------------------------
# Config
def build_html_report(summary, alerts_df, top_ips_df):
    now = datetime.now().strftime("%d %b %Y, %I:%M %p")

    alerts_rows = ""
    if alerts_df is not None and not alerts_df.empty:
        for _, row in alerts_df.iterrows():
            alerts_rows += f"""
            <tr>
                <td>{row.get('type','')}</td>
                <td>{row.get('ip','')}</td>
                <td>{row.get('risk','')}</td>
                <td>{row.get('evidence','')}</td>
            </tr>
            """

    top_ips_rows = ""
    if top_ips_df is not None and not top_ips_df.empty:
        for _, row in top_ips_df.iterrows():
            top_ips_rows += f"""
            <tr>
                <td>{row.get('ip','')}</td>
                <td>{row.get('count','')}</td>
            </tr>
            """

    html = f"""
    <html>
    <head>
        <meta charset="utf-8" />
        <title>ThreatLens AI - Incident Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                padding: 24px;
                background: #0b1220;
                color: #e5e7eb;
            }}
            .card {{
                background: #111827;
                padding: 18px;
                border-radius: 12px;
                margin-bottom: 16px;
                border: 1px solid #1f2937;
            }}
            h1, h2 {{
                margin: 0 0 12px 0;
            }}
            .muted {{
                color: #9ca3af;
                font-size: 14px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }}
            th, td {{
                border: 1px solid #1f2937;
                padding: 10px;
                text-align: left;
            }}
            th {{
                background: #1f2937;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>ThreatLens AI - Incident Report</h1>
            <p class="muted">Generated on {now}</p>
        </div>
        
        <div class="card">
            <h2>Executive Summary</h2>
            <p>{summary}</p>
        </div>

        <div class="card">
            <h2>Alerts Detailed</h2>
            <table>
                <thead>
                    <tr>
                        <th>Alert Type</th>
                        <th>IP Address</th>
                        <th>Risk Level</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {alerts_rows}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Top IPs Detected</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Event Count</th>
                    </tr>
                </thead>
                <tbody>
                    {top_ips_rows}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return html



st.set_page_config(page_title="ThreatLens AI", layout="wide")

col1, col2 = st.columns([1, 1])

with col1:
    demo_clicked = st.button("⚡ Try Demo Log (No upload needed)")

with col2:
    reset_clicked = st.button("🧹 Reset / Clear")

# ✅ Sidebar Demo Mode Button
st.sidebar.markdown("## 🚀 Quick Demo")
demo_mode = st.sidebar.button("▶️ Run Demo Mode")

if reset_clicked:
    for key in ["log_text", "alerts_df", "filtered_df", "risk_level", "ip_filter"]:
        if key in st.session_state:
            del st.session_state[key]
    st.rerun()

st.title("🛡️ ThreatLens AI")
st.write("AI-powered Cybersecurity Log Analyzer (MVP)")
st.info("🔒 Privacy note: Your log is processed in-memory for analysis. Avoid uploading sensitive logs containing passwords, tokens, API keys, or private customer data. For maximum privacy, run locally.")
st.caption("Built by Aryan (Wesu) • ThreatLens AI MVP • Streamlit + Python")

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

# ✅ Timestamp extraction for timeline
TS_REGEX = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


def extract_timestamp(line: str):
    """
    Extracts timestamp in format: YYYY-MM-DD HH:MM:SS
    Returns datetime or None.
    """
    m = TS_REGEX.search(line)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    except:
        return None


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


def generate_ai_report(alert_df, df):
    api_key = st.secrets.get("OPENAI_API_KEY")

    if not api_key:
        return "❌ OPENAI_API_KEY not found in Streamlit secrets."

    client = OpenAI(api_key=api_key)

    # Basic stats
    total_lines = len(df)
    auth_fails = int((df["event_type"] == "AUTH_FAIL").sum())
    auth_success = int((df["event_type"] == "AUTH_SUCCESS").sum())
    unique_ips = int(df["ip"].nunique(dropna=True))

    # Top IPs
    top_ips = df["ip"].dropna().value_counts().head(5)
    top_ips_text = "\n".join([f"- {ip}: {cnt} events" for ip, cnt in top_ips.items()]) or "N/A"

    # Alerts
    if alert_df is not None and not alert_df.empty:
        alerts_text = "\n".join([
            f"- [{row['risk']}] {row['type']} | IP={row['ip']} | score={row['score']} | evidence={row['evidence']}"
            for _, row in alert_df.iterrows()
        ])
    else:
        alerts_text = "No alerts detected by rules."

    prompt = f"""
You are a professional SOC Analyst.

Based on the data below, generate a clear incident report.
Be concise but actionable.

LOG OVERVIEW:
- Total lines: {total_lines}
- Auth fails: {auth_fails}
- Auth success: {auth_success}
- Unique IPs: {unique_ips}

TOP IPs:
{top_ips_text}

ALERTS DETECTED:
{alerts_text}

Return in this structure:
## Executive Summary
## Key Findings
## Most Suspicious IPs
## Immediate Actions (next 30 minutes)
## Hardening / Prevention Checklist
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a cybersecurity incident response assistant."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
        )
        return response.choices[0].message.content

    except Exception as e:
        return f"⚠️ AI Report failed due to API issue:\n\n`{e}`\n\n✅ Your ThreatLens rules & dashboard still work perfectly."


# -----------------------------
# UI
# -----------------------------
uploaded_file = st.file_uploader("Upload a log file (.log / .txt)", type=["log", "txt"])

log_text = None

# ✅ Keep the uploaded/demo log persistent even after reruns
if "log_text" in st.session_state:
    log_text = st.session_state["log_text"]


def load_demo_log():
    with open("sample_auth.log", "r", encoding="utf-8", errors="ignore") as f:
        demo_text = f.read()
    st.session_state["log_text"] = demo_text
    return demo_text


if demo_clicked or demo_mode:
    log_text = load_demo_log()
    st.info("✅ Demo log loaded: sample_auth.log")

elif uploaded_file:
    log_text = uploaded_file.read().decode("utf-8", errors="ignore")
    st.session_state["log_text"] = log_text
    st.success("✅ File loaded successfully!")

if log_text:
    # Parse events
    events = []
    for idx, line in enumerate(log_text.splitlines()):
        ts = extract_timestamp(line)
        ip = extract_ip(line)
        evt = guess_event_type(line)
        endpoint = find_endpoint(line)

        events.append({
            "line_no": idx + 1,
            "timestamp": ts,
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

    # Rule 1: Brute force
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

    # Rule 2: Credential stuffing
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
    # Overview
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

    # Timeline
    st.markdown("### ⏳ Threat Timeline")

    if df["timestamp"].notna().sum() == 0:
        st.info("No timestamps detected in logs, so timeline is hidden. (Tip: include `YYYY-MM-DD HH:MM:SS` in logs)")
    else:
        timeline_df = df.dropna(subset=["timestamp"]).copy()
        timeline_df["minute"] = timeline_df["timestamp"].dt.floor("min")

        event_counts = (
            timeline_df
            .groupby(["minute", "event_type"])
            .size()
            .reset_index(name="count")
        )

        pivot = event_counts.pivot(index="minute", columns="event_type", values="count").fillna(0)
        st.line_chart(pivot)

    # Alerts
    st.markdown('<div id="alerts_section"></div>', unsafe_allow_html=True)
    st.subheader("🚨 Alerts")

    if not alerts:
        st.success("✅ No high-confidence threats detected (based on current rules).")

    else:
        alert_df = pd.DataFrame(alerts)

        alert_df["risk"] = alert_df["score"].apply(risk_label)
        alert_df["risk_badge"] = alert_df["risk"].apply(risk_color) + " " + alert_df["risk"].astype(str)


        # Sort by score high -> low
        alert_df = alert_df.sort_values(by="score", ascending=False)

        # Sidebar filters
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
        st.markdown("### 🖱️ Click an alert to view details")

        gb = GridOptionsBuilder.from_dataframe(
            filtered_alerts[["risk_badge", "type", "ip", "evidence", "score"]]
        )

        gb.configure_selection(
            selection_mode="single",
            use_checkbox=True
        )

        gridOptions = gb.build()

        grid_response = AgGrid(
            filtered_alerts[["risk_badge", "type", "ip", "evidence", "score"]],
            gridOptions=gridOptions,
            update_mode=GridUpdateMode.SELECTION_CHANGED,
            theme="alpine",
            height=250,
            fit_columns_on_grid_load=True
        )

        selected = grid_response["selected_rows"]

        if selected is not None and len(selected) > 0:
            st.markdown("## ✅ Selected Alert Details")
            if isinstance(selected, pd.DataFrame):
                st.json(selected.iloc[0].to_dict())
            else:
                st.json(selected[0])


        # AI-style Explanation
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
**{row['risk_badge']} - {row['type']}**  
**IP:** `{row['ip']}`  
**Why it's suspicious:** {row['evidence']}  
**Suggested action:** Block/Rate-limit the IP, enable account lockout, monitor additional activity.
"""
            )

        # AI Analyst Summary
        st.subheader("🤖 AI Analyst Summary")

        top = alert_df.iloc[0]
        analyst_text = f"""
**What’s happening:**  
Most likely **{top['type']}** activity was detected, mainly from IP **{top['ip']}**.

**Why this matters:**  
{top['evidence']} (Risk Score: **{top['score']}**)

**Most recommended action (next 10 mins):**
- Block or rate-limit the IP `{top['ip']}`
- Enable account lockout + CAPTCHA on login
- Monitor for further attempts or suspicious endpoints

**What to check next:**
- Look for multiple failed logins across many users
- Check if any successful login happened after failures
- Review access logs for admin endpoint hits
"""
        st.markdown(analyst_text)

        # ✅ OpenAI Incident Report (REAL AI)
        st.subheader("🧨 AI Incident Report (OpenAI)")

        if st.button("🤖 Generate AI Report"):
            with st.spinner("Generating AI report..."):
                ai_report = generate_ai_report(alert_df, df)

            st.markdown(ai_report)

            st.download_button(
                label="⬇️ Download AI Report (.md)",
                data=ai_report,
                file_name="threatlens_ai_report.md",
                mime="text/markdown"
            )

        # Report Download (Markdown)
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

        # HTML Report Download
        try:
            summary_info = f"Total alerts: {len(alert_df)}. High Risk: {(alert_df['risk'] == 'HIGH').sum()}."
            html_report = build_html_report(summary_info, alert_df, top_ip_df)
            st.download_button(
                label="🌐 Download Report (.html)",
                data=html_report,
                file_name="threatlens_incident_report.html",
                mime="text/html"
            )
        except Exception as e:
            st.error(f"Error generating HTML report: {e}")
