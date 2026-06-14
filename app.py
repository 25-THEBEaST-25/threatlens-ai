from __future__ import annotations

import pandas as pd
import streamlit as st

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
from src.intelligence import ThreatIntelSettings, enrich_alerts
from src.reports import build_html_report, build_markdown_report
from src.story import build_attack_story, build_investigation_commands, build_prevention_checklist
from src.utils import PROJECT_ROOT, load_text_file, parse_log_text, top_ip_counts


st.set_page_config(page_title="ThreatLens AI", layout="wide")


def main() -> None:
    st.title("ThreatLens AI")
    st.caption("Production-style cybersecurity log analyzer with attack story mode and incident workflow.")
    st.info("Logs are processed in memory. Do not upload secrets, credentials, API keys, or private customer data.")

    settings, intel_settings = render_sidebar()
    render_controls()
    log_text = get_log_text()

    if not log_text:
        st.warning("Upload a .log/.txt file or run demo mode to begin analysis.")
        return

    df = parse_log_text(log_text)
    if df.empty:
        st.warning("No readable log lines were found in the selected input.")
        return

    alert_df = detect_threats(df, settings=settings)
    alert_df = enrich_alerts(alert_df, df, settings=intel_settings)
    top_ip_df = top_ip_counts(df, limit=10)

    render_overview(df, alert_df, top_ip_df)

    tab_story, tab_alerts, tab_events, tab_case, tab_reports = st.tabs(
        ["Attack Story", "Alerts", "Events", "Case", "Reports"]
    )

    with tab_story:
        render_attack_story(df, alert_df)
    with tab_alerts:
        render_alerts(alert_df)
    with tab_events:
        render_events(df)
    with tab_case:
        render_case(alert_df)
    with tab_reports:
        render_reports(alert_df, df, top_ip_df)


def render_sidebar() -> tuple[DetectionSettings, ThreatIntelSettings]:
    with st.sidebar:
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
        enable_abuseipdb = st.checkbox("Use AbuseIPDB API", value=False)
        abuse_key = st.text_input("AbuseIPDB API key", type="password") if enable_abuseipdb else None

    settings = DetectionSettings(
        brute_force_threshold=brute_force_threshold,
        credential_stuffing_threshold=credential_stuffing_threshold,
        endpoint_probe_threshold=endpoint_probe_threshold,
        successful_login_after_failures=success_after_failures,
        allowlisted_ips=parse_csv_values(allowlisted_ips),
        allowlisted_networks=parse_csv_values(allowlisted_networks),
        trusted_user_agents=parse_csv_values(trusted_agents),
    )
    intel_settings = ThreatIntelSettings(abuseipdb_api_key=abuse_key)
    return settings, intel_settings


def render_controls() -> None:
    left, right = st.columns([1, 1])
    with left:
        if st.button("Run Demo Log", use_container_width=True):
            st.session_state["log_text"] = load_text_file(PROJECT_ROOT / "sample_auth.log")
            st.session_state["source_name"] = "sample_auth.log"
            st.rerun()
    with right:
        if st.button("Reset", use_container_width=True):
            for key in ("log_text", "source_name", "risk_level", "ip_filter", "event_type_filter"):
                st.session_state.pop(key, None)
            st.rerun()

    with st.sidebar:
        st.header("Quick Demo")
        demo_choice = st.selectbox("Demo source", ["sample_auth.log", "demo_bruteforce.log", "demo_endpoint_probe.log"])
        if st.button("Load Selected Demo", use_container_width=True):
            st.session_state["log_text"] = load_text_file(PROJECT_ROOT / demo_choice)
            st.session_state["source_name"] = demo_choice
            st.rerun()


def get_log_text() -> str | None:
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


def render_overview(df: pd.DataFrame, alert_df: pd.DataFrame, top_ip_df: pd.DataFrame) -> None:
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Events", len(df))
    c2.metric("Alerts", len(alert_df))
    c3.metric("High Risk", int((alert_df["risk"] == "HIGH").sum()) if not alert_df.empty else 0)
    c4.metric("Unique IPs", int(df["ip"].nunique(dropna=True)))
    c5.metric("Formats", int(df["format"].nunique(dropna=True)))

    with st.expander("Top IPs and Timeline", expanded=False):
        left, right = st.columns([1, 2])
        with left:
            if top_ip_df.empty:
                st.info("No IP addresses detected.")
            else:
                st.dataframe(top_ip_df, use_container_width=True, hide_index=True)
        with right:
            render_timeline(df)


def render_timeline(df: pd.DataFrame) -> None:
    if df["timestamp"].notna().sum() == 0:
        st.info("No supported timestamps detected. Supported formats include ISO, syslog, nginx/apache, and JSON logs.")
        return

    timeline_df = df.dropna(subset=["timestamp"]).copy()
    timeline_df["minute"] = timeline_df["timestamp"].dt.floor("min")
    event_counts = timeline_df.groupby(["minute", "event_type"]).size().reset_index(name="count")
    pivot = event_counts.pivot(index="minute", columns="event_type", values="count").fillna(0)
    st.line_chart(pivot)


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

    risk_options = ["ALL"] + sorted(alert_df["risk"].unique().tolist())
    ip_options = ["ALL"] + sorted(alert_df["ip"].dropna().unique().tolist())
    col1, col2 = st.columns(2)
    selected_risk = col1.selectbox("Risk Level", risk_options, key="risk_level")
    selected_ip = col2.selectbox("IP Address", ip_options, key="ip_filter")

    filtered_alerts = alert_df.copy()
    if selected_risk != "ALL":
        filtered_alerts = filtered_alerts[filtered_alerts["risk"] == selected_risk]
    if selected_ip != "ALL":
        filtered_alerts = filtered_alerts[filtered_alerts["ip"] == selected_ip]

    display_cols = [
        "risk",
        "type",
        "ip",
        "score",
        "confidence",
        "attack_stage",
        "evidence",
        "intel_tags",
        "threat_intel",
        "recommended_action",
    ]
    st.dataframe(filtered_alerts[display_cols], use_container_width=True, hide_index=True)

    if AgGrid is None:
        return

    st.markdown("### Click an Alert")
    grid_options = GridOptionsBuilder.from_dataframe(filtered_alerts[display_cols])
    grid_options.configure_selection(selection_mode="single", use_checkbox=True)
    grid_response = AgGrid(
        filtered_alerts[display_cols],
        gridOptions=grid_options.build(),
        update_mode=GridUpdateMode.SELECTION_CHANGED,
        theme="alpine",
        height=260,
        fit_columns_on_grid_load=True,
    )

    selected = grid_response.get("selected_rows")
    if selected is not None and len(selected) > 0:
        st.json(selected.iloc[0].to_dict() if isinstance(selected, pd.DataFrame) else selected[0])


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


def render_reports(alert_df: pd.DataFrame, df: pd.DataFrame, top_ip_df: pd.DataFrame) -> None:
    st.subheader("Incident Reports")

    markdown_report = build_markdown_report(alert_df, total_events=len(df))
    summary = (
        f"Analyzed {len(df)} events and detected {len(alert_df)} alert(s). "
        f"High-risk alerts: {int((alert_df['risk'] == 'HIGH').sum()) if not alert_df.empty else 0}."
    )
    html_report = build_html_report(summary, alert_df, top_ip_df)

    col1, col2 = st.columns(2)
    col1.download_button("Download Markdown Report", markdown_report, "threatlens_incident_report.md", "text/markdown")
    col2.download_button("Download HTML Report", html_report, "threatlens_incident_report.html", "text/html")

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
        f"- [{row.risk}] {row.type} | IP={row.ip} | score={row.score} | evidence={row.evidence} | intel={row.threat_intel}"
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

