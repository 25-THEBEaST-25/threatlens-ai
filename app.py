from __future__ import annotations

import os
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover
    OpenAI = None

try:
    from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode
except ImportError:  # pragma: no cover
    AgGrid = None
    GridOptionsBuilder = None
    GridUpdateMode = None

from src.cases import CASE_STATUSES, build_case_summary, render_case_markdown
from src.config import DetectionSettings, parse_csv_values
from src.detectors import detect_threats
from src.ioc import extract_iocs, summarize_ioc_counts
from src.intelligence import ThreatIntelSettings, enrich_alerts
from src.monitor import read_live_log
from src.reports import build_html_report, build_json_report, build_markdown_report
from src.story import build_attack_story, build_investigation_commands, build_prevention_checklist
from src.utils import PROJECT_ROOT, load_text_file, parse_log_text, top_ip_counts

try:
    import plotly.graph_objects as go
except ImportError:  # pragma: no cover
    go = None


st.set_page_config(page_title="ThreatLens AI", layout="wide")


def main() -> None:
    st.title("ThreatLens AI")
    st.caption("Production-style cybersecurity log analyzer with attack story mode and incident workflow.")
    st.info("Logs are processed in memory. Do not upload secrets, credentials, API keys, or private customer data.")

    settings, intel_settings, input_mode = render_sidebar()
    render_controls()
    log_text = get_log_text(input_mode)

    if not log_text:
        st.warning("Upload a .log/.txt file, choose a live log path, or run demo mode to begin analysis.")
        return

    df = parse_log_text(log_text)
    if df.empty:
        st.warning("No readable log lines were found in the selected input.")
        return

    alert_df = detect_threats(df, settings=settings)
    alert_df = enrich_alerts(alert_df, df, settings=intel_settings)
    ioc_df = extract_iocs(log_text, df)
    top_ip_df = top_ip_counts(df, limit=10)

    render_overview(df, alert_df, top_ip_df, ioc_df)

    tab_story, tab_alerts, tab_iocs, tab_events, tab_case, tab_reports = st.tabs(
        ["Attack Story", "Alerts", "IOCs", "Events", "Case", "Reports"]
    )

    with tab_story:
        render_attack_story(df, alert_df)
    with tab_alerts:
        render_alerts(alert_df)
    with tab_iocs:
        render_iocs(ioc_df)
    with tab_events:
        render_events(df)
    with tab_case:
        render_case(alert_df)
    with tab_reports:
        render_reports(alert_df, df, top_ip_df, ioc_df)


def render_sidebar() -> tuple[DetectionSettings, ThreatIntelSettings, str]:
    with st.sidebar:
        st.header("Input")
        input_mode = st.radio("Log source", ["Upload Log", "Live Monitor"], horizontal=False)

        st.header("Detection Settings")
        brute_force_threshold = st.slider("Brute force threshold", 3, 30, 8)
        credential_stuffing_threshold = st.slider("Credential stuffing users", 2, 20, 4)
        endpoint_probe_threshold = st.slider("Endpoint probe threshold", 2, 30, 3)
        success_after_failures = st.slider("Success after failures", 2, 30, 5)

        st.header("False Positive Controls")
        allowlisted_ips = st.text_input("Allowlisted IPs", placeholder="1.2.3.4, 5.6.7.8")
        allowlisted_networks = st.text_input("Trusted networks", value="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16")
        trusted_agents = st.text_input("Trusted user agents", placeholder="UptimeRobot, healthcheck")

        st.header("Threat Intel")
        enable_geoip = st.checkbox("Use GeoIP API", value=True)
        vt_env_configured = bool(os.getenv("VT_API_KEY"))
        abuse_env_configured = bool(os.getenv("ABUSEIPDB_API_KEY"))
        enable_virustotal = st.checkbox("Use VirusTotal API", value=vt_env_configured)
        if enable_virustotal and not vt_env_configured:
            st.caption("Set VT_API_KEY in the environment to enable VirusTotal lookups.")
        enable_abuseipdb = st.checkbox("Use AbuseIPDB API", value=abuse_env_configured)
        abuse_key = st.text_input("AbuseIPDB API key", type="password") if enable_abuseipdb else None
        if enable_abuseipdb and not abuse_key and not abuse_env_configured:
            st.caption("Paste a key here or set ABUSEIPDB_API_KEY in the environment.")

    settings = DetectionSettings(
        brute_force_threshold=brute_force_threshold,
        credential_stuffing_threshold=credential_stuffing_threshold,
        endpoint_probe_threshold=endpoint_probe_threshold,
        successful_login_after_failures=success_after_failures,
        allowlisted_ips=parse_csv_values(allowlisted_ips),
        allowlisted_networks=parse_csv_values(allowlisted_networks),
        trusted_user_agents=parse_csv_values(trusted_agents),
    )
    intel_settings = ThreatIntelSettings(
        abuseipdb_api_key=abuse_key,
        enable_geoip=enable_geoip,
        enable_virustotal=enable_virustotal,
        enable_abuseipdb=enable_abuseipdb,
    )
    return settings, intel_settings, input_mode


def render_controls() -> None:
    left, right = st.columns([1, 1])
    with left:
        if st.button("Run Demo Log", use_container_width=True):
            st.session_state["log_text"] = load_text_file(PROJECT_ROOT / "sample_auth.log")
            st.session_state["source_name"] = "sample_auth.log"
            st.rerun()
    with right:
        if st.button("Reset", use_container_width=True):
            for key in (
                "log_text",
                "source_name",
                "severity_filter",
                "ip_search",
                "alert_ioc_search",
                "ioc_search",
                "event_type_filter",
            ):
                st.session_state.pop(key, None)
            st.rerun()

    with st.sidebar:
        st.header("Quick Demo")
        demo_choice = st.selectbox("Demo source", ["sample_auth.log", "demo_bruteforce.log", "demo_endpoint_probe.log"])
        if st.button("Load Selected Demo", use_container_width=True):
            st.session_state["log_text"] = load_text_file(PROJECT_ROOT / demo_choice)
            st.session_state["source_name"] = demo_choice
            st.rerun()


def get_log_text(input_mode: str) -> str | None:
    if input_mode == "Live Monitor":
        with st.sidebar:
            st.header("Live Monitor")
            live_path = st.text_input("Log file path", value=str(PROJECT_ROOT / "sample_auth.log"))
            max_lines = st.number_input("Lines to tail", min_value=100, max_value=20000, value=1000, step=100)
            refresh_seconds = st.slider("Refresh seconds", 2, 30, 5)

        log_text = read_live_log(live_path, max_lines=int(max_lines))
        source_name = Path(live_path).name if live_path else "live log"
        if log_text:
            st.session_state["source_name"] = source_name
            st.caption(f"Live monitoring: {live_path}")
            schedule_autorefresh(refresh_seconds)
            return log_text

        st.warning(f"No readable lines found for live monitor path: {live_path}")
        schedule_autorefresh(refresh_seconds)
        return None

    uploaded_file = st.file_uploader("Upload a log file", type=["log", "txt", "json"])

    if uploaded_file:
        st.session_state["log_text"] = uploaded_file.read().decode("utf-8", errors="ignore")
        st.session_state["source_name"] = uploaded_file.name
        st.success(f"Loaded {uploaded_file.name}")

    log_text = st.session_state.get("log_text")
    source_name = st.session_state.get("source_name")
    if log_text and source_name:
        st.caption(f"Analyzing: {source_name}")
    return log_text


def schedule_autorefresh(refresh_seconds: int) -> None:
    refresh_ms = max(2, int(refresh_seconds)) * 1000
    components.html(
        f"""
        <script>
        window.setTimeout(function() {{
            window.parent.location.reload();
        }}, {refresh_ms});
        </script>
        """,
        height=0,
    )


def render_overview(df: pd.DataFrame, alert_df: pd.DataFrame, top_ip_df: pd.DataFrame, ioc_df: pd.DataFrame) -> None:
    ioc_counts = summarize_ioc_counts(ioc_df)
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Events", len(df))
    c2.metric("Alerts", len(alert_df))
    c3.metric("High Risk", int((alert_df["risk"] == "HIGH").sum()) if not alert_df.empty else 0)
    c4.metric("Unique IPs", ioc_counts["Unique IPs"])
    c5.metric("Endpoints", ioc_counts["Endpoints"])
    c6.metric("Usernames", ioc_counts["Usernames"])

    st.subheader("Threat Timeline")
    render_timeline(df, alert_df)

    with st.expander("Top IPs", expanded=False):
        if top_ip_df.empty:
            st.info("No IP addresses detected.")
        else:
            st.dataframe(top_ip_df, use_container_width=True, hide_index=True)


def render_timeline(df: pd.DataFrame, alert_df: pd.DataFrame) -> None:
    if df["timestamp"].notna().sum() == 0:
        st.info("No supported timestamps detected. Supported formats include ISO, syslog, nginx/apache, and JSON logs.")
        return

    timeline_df = build_timeline_dataset(df, alert_df)
    if timeline_df.empty:
        st.info("No timeline events are available.")
        return

    if go is None:
        st.dataframe(timeline_df, use_container_width=True, hide_index=True)
        return

    fig = go.Figure()
    color_map = {
        "Failed Login": "#ef4444",
        "Successful Login": "#22c55e",
        "Endpoint Access": "#38bdf8",
        "Other Event": "#94a3b8",
        "Brute Force Detected": "#f97316",
        "Credential Stuffing Detected": "#eab308",
        "Endpoint Probing Detected": "#a855f7",
        "Successful Login After Failures": "#f43f5e",
    }

    for event_type, group in timeline_df.groupby("event_type", sort=False):
        fig.add_trace(
            go.Scatter(
                x=group["timestamp"],
                y=group["source_ip"],
                mode="markers",
                name=event_type,
                marker={"size": 12, "color": color_map.get(event_type, "#64748b"), "line": {"width": 1, "color": "#111827"}},
                hovertemplate="%{x}<br>%{y}<br>" + event_type + "<extra></extra>",
            )
        )

    fig.update_layout(
        template=_plotly_template(),
        height=340,
        margin={"l": 10, "r": 10, "t": 8, "b": 10},
        xaxis_title="Time",
        yaxis_title="Source IP",
        legend_title_text="Event",
    )
    st.plotly_chart(fig, use_container_width=True)
    st.dataframe(timeline_df, use_container_width=True, hide_index=True)


def build_timeline_dataset(df: pd.DataFrame, alert_df: pd.DataFrame) -> pd.DataFrame:
    event_rows: list[dict[str, object]] = []
    event_name_map = {
        "AUTH_FAIL": "Failed Login",
        "AUTH_SUCCESS": "Successful Login",
    }

    event_df = df.dropna(subset=["timestamp"]).copy()
    for _, row in event_df.iterrows():
        event_rows.append(
            {
                "timestamp": row["timestamp"],
                "event_type": event_name_map.get(str(row.get("event_type")), "Endpoint Access" if pd.notna(row.get("endpoint")) else "Other Event"),
                "source_ip": row.get("ip") or "unknown",
            }
        )

    detection_name_map = {
        "Brute Force Attempt": "Brute Force Detected",
        "Credential Stuffing Pattern": "Credential Stuffing Detected",
        "Suspicious Endpoint Probing": "Endpoint Probing Detected",
        "Successful Login After Failures": "Successful Login After Failures",
    }
    if not alert_df.empty:
        for _, alert in alert_df.iterrows():
            source_ip = alert.get("ip")
            ip_events = event_df[event_df["ip"] == source_ip] if source_ip else event_df
            detection_time = ip_events["timestamp"].max() if not ip_events.empty else event_df["timestamp"].max()
            if pd.isna(detection_time):
                continue
            event_rows.append(
                {
                    "timestamp": detection_time + pd.Timedelta(seconds=1),
                    "event_type": detection_name_map.get(str(alert.get("type")), str(alert.get("type") or "Alert Detected")),
                    "source_ip": source_ip or "unknown",
                }
            )

    timeline_df = pd.DataFrame(event_rows, columns=["timestamp", "event_type", "source_ip"])
    if timeline_df.empty:
        return timeline_df
    return timeline_df.sort_values(["timestamp", "event_type", "source_ip"]).reset_index(drop=True)


def _plotly_template() -> str:
    return "plotly_dark" if st.get_option("theme.base") == "dark" else "plotly_white"


def render_attack_story(df: pd.DataFrame, alert_df: pd.DataFrame) -> None:
    st.subheader("Attack Story Mode")
    for step_number, line in enumerate(build_attack_story(df, alert_df), start=1):
        st.markdown(f"**{step_number}.** {line}")

    left, right = st.columns(2)
    with left:
        st.markdown("### Analyst Commands")
        st.code("\n".join(build_investigation_commands(alert_df)), language="bash")
    with right:
        st.markdown("### Prevention Checklist")
        for item in build_prevention_checklist(alert_df):
            st.checkbox(item, value=False)


def render_alerts(alert_df: pd.DataFrame) -> None:
    st.subheader("Alerts")

    if alert_df.empty:
        st.success("No high-confidence threats detected by the current rules.")
        return

    severity_options = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    present_severities = [severity for severity in severity_options if severity in alert_df["severity"].dropna().unique().tolist()]
    col1, col2, col3 = st.columns([1.2, 1, 1])
    selected_severities = col1.multiselect(
        "Severity",
        severity_options,
        default=present_severities or severity_options,
        key="severity_filter",
    )
    ip_query = col2.text_input("IP search", key="ip_search", placeholder="45.33.12.9")
    ioc_query = col3.text_input("IOC search", key="alert_ioc_search", placeholder="admin, T1110, endpoint")

    filtered_alerts = alert_df.copy()
    if selected_severities:
        filtered_alerts = filtered_alerts[filtered_alerts["severity"].isin(selected_severities)]
    if ip_query:
        filtered_alerts = filtered_alerts[filtered_alerts["ip"].fillna("").str.contains(ip_query, case=False, regex=False)]
    if ioc_query:
        searchable = filtered_alerts.apply(lambda row: " ".join(str(value) for value in row.values), axis=1)
        filtered_alerts = filtered_alerts[searchable.str.contains(ioc_query, case=False, regex=False)]

    display_cols = [
        "severity",
        "type",
        "ip",
        "risk_score",
        "confidence",
        "confidence_score",
        "mitre_id",
        "mitre_name",
        "attack_stage",
        "evidence",
        "intel_tags",
        "threat_intel",
        "recommended_action",
    ]
    available_cols = [column for column in display_cols if column in filtered_alerts]
    st.dataframe(filtered_alerts[available_cols], use_container_width=True, hide_index=True)

    st.markdown("### Alert Cards")
    for _, row in filtered_alerts.iterrows():
        render_alert_card(row)

    if AgGrid is None:
        return

    st.markdown("### Click an Alert")
    grid_options = GridOptionsBuilder.from_dataframe(filtered_alerts[available_cols])
    grid_options.configure_selection(selection_mode="single", use_checkbox=True)
    grid_response = AgGrid(
        filtered_alerts[available_cols],
        gridOptions=grid_options.build(),
        update_mode=GridUpdateMode.SELECTION_CHANGED,
        theme="alpine",
        height=260,
        fit_columns_on_grid_load=True,
    )

    selected = grid_response.get("selected_rows")
    if selected is not None and len(selected) > 0:
        st.json(selected.iloc[0].to_dict() if isinstance(selected, pd.DataFrame) else selected[0])


def render_alert_card(row: pd.Series) -> None:
    with st.container(border=True):
        header_left, header_mid, header_right = st.columns([2.2, 1, 1])
        header_left.markdown(f"#### {row.get('type', 'Alert')}")
        header_left.caption(f"Source IP: {row.get('ip', 'N/A')}")
        header_mid.metric("Risk Score", int(row.get("risk_score", row.get("score", 0)) or 0))
        header_right.metric("Confidence", str(row.get("confidence", "N/A")))

        mitre_id = row.get("mitre_id", "N/A")
        mitre_name = row.get("mitre_name", "Unmapped")
        st.markdown("**MITRE ATT&CK**")
        st.write(f"{mitre_id} - {mitre_name}")

        geo_col, vt_col, abuse_col = st.columns(3)
        with geo_col:
            st.markdown("**GeoIP**")
            st.write(f"Country: {row.get('geo_country', 'N/A')}")
            st.write(f"City: {row.get('geo_city', 'N/A')}")
            st.write(f"ISP: {row.get('geo_isp', 'N/A')}")
        with vt_col:
            st.markdown("**VirusTotal**")
            st.write(f"Malicious: {int(row.get('vt_malicious', 0) or 0)}")
            st.write(f"Suspicious: {int(row.get('vt_suspicious', 0) or 0)}")
            st.write(f"Harmless: {int(row.get('vt_harmless', 0) or 0)}")
        with abuse_col:
            st.markdown("**AbuseIPDB**")
            st.write(f"Abuse Confidence Score: {int(row.get('abuse_confidence_score', 0) or 0)}")
            st.write(f"Total Reports: {int(row.get('abuse_total_reports', 0) or 0)}")
            st.write(f"Last Reported: {row.get('abuse_last_reported', 'N/A')}")

        st.markdown(f"**Evidence:** {row.get('evidence', 'N/A')}")
        st.markdown(f"**Recommended action:** {row.get('recommended_action', 'N/A')}")


def render_iocs(ioc_df: pd.DataFrame) -> None:
    st.subheader("Extracted IOCs")
    counts = summarize_ioc_counts(ioc_df)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Unique IPs", counts["Unique IPs"])
    c2.metric("Endpoints", counts["Endpoints"])
    c3.metric("Usernames", counts["Usernames"])
    c4.metric("URLs", counts["URLs"])

    if ioc_df.empty:
        st.info("No IOCs were extracted from the current log input.")
        return

    col1, col2 = st.columns([1, 1.3])
    type_options = sorted(ioc_df["Type"].dropna().unique().tolist())
    selected_types = col1.multiselect("IOC Type", type_options, default=type_options)
    search_query = col2.text_input("IOC search", key="ioc_search", placeholder="IP, username, URL, endpoint")

    filtered = ioc_df.copy()
    if selected_types:
        filtered = filtered[filtered["Type"].isin(selected_types)]
    if search_query:
        filtered = filtered[filtered["Indicator"].str.contains(search_query, case=False, regex=False)]

    st.dataframe(filtered[["Indicator", "Type"]], use_container_width=True, hide_index=True)
    st.download_button(
        "Download IOCs CSV",
        data=filtered[["Indicator", "Type"]].to_csv(index=False),
        file_name="threatlens_iocs.csv",
        mime="text/csv",
    )


def render_events(df: pd.DataFrame) -> None:
    st.subheader("Parsed Events")
    event_options = ["ALL"] + sorted(df["event_type"].dropna().unique().tolist())
    selected_type = st.selectbox("Event Type", event_options, key="event_type_filter")
    filtered = df if selected_type == "ALL" else df[df["event_type"] == selected_type]

    columns = ["line_no", "timestamp", "format", "event_type", "ip", "username", "endpoint", "status_code", "user_agent", "raw"]
    st.dataframe(filtered[columns], use_container_width=True, hide_index=True)
    st.download_button(
        "Download Parsed Events CSV",
        data=filtered[columns].to_csv(index=False),
        file_name="threatlens_events.csv",
        mime="text/csv",
    )


def render_case(alert_df: pd.DataFrame) -> None:
    st.subheader("Case Workflow")
    col1, col2 = st.columns(2)
    status = col1.selectbox("Status", CASE_STATUSES)
    owner = col2.text_input("Owner", placeholder="Analyst name")
    notes = st.text_area("Analyst notes", placeholder="What was confirmed, contained, or still needs review?")

    case = build_case_summary(alert_df, status=status, owner=owner, notes=notes)
    st.json(case)
    st.download_button(
        "Download Case File",
        data=render_case_markdown(case),
        file_name=f"{case['case_id']}.md",
        mime="text/markdown",
    )


def render_reports(alert_df: pd.DataFrame, df: pd.DataFrame, top_ip_df: pd.DataFrame, ioc_df: pd.DataFrame) -> None:
    st.subheader("Incident Reports")

    markdown_report = build_markdown_report(alert_df, total_events=len(df))
    ioc_counts = summarize_ioc_counts(ioc_df)
    summary_data = {
        "total_events": int(len(df)),
        "total_alerts": int(len(alert_df)),
        "high_risk_alerts": int((alert_df["risk"] == "HIGH").sum()) if not alert_df.empty else 0,
        "unique_ips": ioc_counts["Unique IPs"],
        "endpoints": ioc_counts["Endpoints"],
        "usernames": ioc_counts["Usernames"],
        "urls": ioc_counts["URLs"],
    }
    summary = (
        f"Analyzed {len(df)} events and detected {len(alert_df)} alert(s). "
        f"High-risk alerts: {int((alert_df['risk'] == 'HIGH').sum()) if not alert_df.empty else 0}."
    )
    html_report = build_html_report(summary, alert_df, top_ip_df)
    json_report = build_json_report(summary_data, alert_df, ioc_df)

    col1, col2, col3 = st.columns(3)
    col1.download_button("Download Markdown Report", markdown_report, "threatlens_incident_report.md", "text/markdown")
    col2.download_button("Download HTML Report", html_report, "threatlens_incident_report.html", "text/html")
    col3.download_button("Download JSON Report", json_report, "threatlens_incident_report.json", "application/json")

    render_ai_report(alert_df, df)


def render_ai_report(alert_df: pd.DataFrame, df: pd.DataFrame) -> None:
    st.markdown("### AI Analyst Report")
    if OpenAI is None:
        st.caption("Install the openai package to enable AI report generation.")
        return

    if st.button("Generate AI Report"):
        api_key = st.secrets.get("OPENAI_API_KEY")
        if not api_key:
            st.error("OPENAI_API_KEY is not configured in Streamlit secrets.")
            return

        with st.spinner("Generating AI report..."):
            ai_report = generate_ai_report(api_key, alert_df, df)

        st.markdown(ai_report)
        st.download_button("Download AI Report", ai_report, "threatlens_ai_report.md", "text/markdown")


def generate_ai_report(api_key: str, alert_df: pd.DataFrame, df: pd.DataFrame) -> str:
    client = OpenAI(api_key=api_key)
    top_ips = top_ip_counts(df)
    top_ips_text = "\n".join(f"- {row.ip}: {row.count} events" for row in top_ips.itertuples()) or "N/A"
    alerts_text = "\n".join(
        f"- [{row.severity}] {row.type} | IP={row.ip} | MITRE={row.mitre_id} {row.mitre_name} | "
        f"risk={row.risk_score} | confidence={row.confidence} | evidence={row.evidence} | intel={row.threat_intel}"
        for row in alert_df.itertuples()
    ) or "No alerts detected by rules."
    story_text = "\n".join(f"- {line}" for line in build_attack_story(df, alert_df))

    prompt = f"""
You are a professional SOC analyst. Generate a concise, actionable incident report.

LOG OVERVIEW:
- Total lines: {len(df)}
- Auth fails: {int((df["event_type"] == "AUTH_FAIL").sum())}
- Auth success: {int((df["event_type"] == "AUTH_SUCCESS").sum())}
- Unique IPs: {int(df["ip"].nunique(dropna=True))}

TOP IPS:
{top_ips_text}

ATTACK STORY:
{story_text}

ALERTS DETECTED:
{alerts_text}

Return sections for Executive Summary, Key Findings, Attack Narrative, Most Suspicious IPs, Immediate Actions, and Prevention Checklist.
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a cybersecurity incident response assistant."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
        )
        return response.choices[0].message.content or "No AI response was returned."
    except Exception as exc:
        return f"AI report generation failed: {exc}"


if __name__ == "__main__":
    main()
