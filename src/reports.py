from __future__ import annotations

import json
from datetime import datetime
from html import escape

import pandas as pd


def build_markdown_report(alerts_df: pd.DataFrame, total_events: int, generated_at: datetime | None = None) -> str:
    generated_at = generated_at or datetime.now()
    alerts_df = _safe_alerts(alerts_df)

    lines = [
        "# ThreatLens AI Incident Report",
        "",
        f"Generated: {generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        f"- Total events analyzed: {total_events}",
        f"- Total alerts: {len(alerts_df)}",
        f"- High risk: {int((alerts_df['risk'] == 'HIGH').sum())}",
        f"- Medium risk: {int((alerts_df['risk'] == 'MEDIUM').sum())}",
        f"- Low risk: {int((alerts_df['risk'] == 'LOW').sum())}",
        "",
        "## Alerts",
    ]

    if alerts_df.empty:
        lines.append("No high-confidence threats were detected by the current rules.")
    else:
        for _, row in alerts_df.iterrows():
            lines.extend(
                [
                    "",
                    f"### {row['risk']} - {row['type']}",
                    f"- IP: {row['ip']}",
                    f"- MITRE ATT&CK: {row['mitre_id']} - {row['mitre_name']}",
                    f"- Risk score: {row['risk_score']}",
                    f"- Confidence: {row['confidence']}",
                    f"- Confidence score: {row['confidence_score']}",
                    f"- Attack stage: {row['attack_stage']}",
                    f"- Evidence: {row['evidence']}",
                    f"- Threat intel: {row['threat_intel']}",
                    f"- GeoIP: {row['geo_country']} / {row['geo_city']} / {row['geo_isp']}",
                    f"- VirusTotal: malicious={row['vt_malicious']}, suspicious={row['vt_suspicious']}, harmless={row['vt_harmless']}",
                    f"- AbuseIPDB: confidence={row['abuse_confidence_score']}, reports={row['abuse_total_reports']}, last reported={row['abuse_last_reported']}",
                    f"- Recommended action: {row['recommended_action']}",
                ]
            )

    return "\n".join(lines)


def build_html_report(summary: str, alerts_df: pd.DataFrame, top_ips_df: pd.DataFrame) -> str:
    now = datetime.now().strftime("%d %b %Y, %I:%M %p")
    alerts_df = _safe_alerts(alerts_df)

    alerts_rows = "\n".join(
        f"""
        <tr>
            <td>{escape(str(row.get('risk', '')))}</td>
            <td>{escape(str(row.get('type', '')))}</td>
            <td>{escape(str(row.get('ip', '')))}</td>
            <td>{escape(str(row.get('mitre_id', '')))} - {escape(str(row.get('mitre_name', '')))}</td>
            <td>{escape(str(row.get('risk_score', '')))}</td>
            <td>{escape(str(row.get('confidence', '')))}</td>
            <td>{escape(str(row.get('evidence', '')))}</td>
            <td>{escape(str(row.get('geo_country', '')))} / {escape(str(row.get('geo_city', '')))} / {escape(str(row.get('geo_isp', '')))}</td>
            <td>Malicious: {escape(str(row.get('vt_malicious', '0')))}<br>Suspicious: {escape(str(row.get('vt_suspicious', '0')))}<br>Harmless: {escape(str(row.get('vt_harmless', '0')))}</td>
            <td>Score: {escape(str(row.get('abuse_confidence_score', '0')))}<br>Reports: {escape(str(row.get('abuse_total_reports', '0')))}<br>Last: {escape(str(row.get('abuse_last_reported', 'N/A')))}</td>
            <td>{escape(str(row.get('threat_intel', '')))}</td>
        </tr>
        """
        for _, row in alerts_df.iterrows()
    )

    if not alerts_rows:
        alerts_rows = '<tr><td colspan="10">No high-confidence threats detected.</td></tr>'

    top_ips_rows = "\n".join(
        f"""
        <tr>
            <td>{escape(str(row.get('ip', '')))}</td>
            <td>{escape(str(row.get('count', '')))}</td>
        </tr>
        """
        for _, row in top_ips_df.iterrows()
    )

    if not top_ips_rows:
        top_ips_rows = '<tr><td colspan="2">No IP addresses found.</td></tr>'

    return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>ThreatLens AI Incident Report</title>
    <style>
        body {{
            margin: 0;
            font-family: Arial, sans-serif;
            background: #f8fafc;
            color: #111827;
        }}
        main {{
            max-width: 1100px;
            margin: 0 auto;
            padding: 32px 20px;
        }}
        section {{
            margin-bottom: 24px;
        }}
        h1, h2 {{
            margin: 0 0 12px;
        }}
        .muted {{
            color: #64748b;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
        }}
        th, td {{
            border: 1px solid #e5e7eb;
            padding: 10px;
            text-align: left;
            vertical-align: top;
        }}
        th {{
            background: #e2e8f0;
        }}
    </style>
</head>
<body>
    <main>
        <section>
            <h1>ThreatLens AI Incident Report</h1>
            <p class="muted">Generated on {escape(now)}</p>
        </section>
        <section>
            <h2>Executive Summary</h2>
            <p>{escape(summary)}</p>
        </section>
        <section>
            <h2>Alerts</h2>
            <table>
                <thead>
                    <tr>
                        <th>Risk</th>
                        <th>Alert Type</th>
                        <th>IP Address</th>
                        <th>MITRE</th>
                        <th>Risk Score</th>
                        <th>Confidence</th>
                        <th>Evidence</th>
                        <th>GeoIP</th>
                        <th>VirusTotal</th>
                        <th>AbuseIPDB</th>
                        <th>Threat Intel</th>
                    </tr>
                </thead>
                <tbody>{alerts_rows}</tbody>
            </table>
        </section>
        <section>
            <h2>Top IPs</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Event Count</th>
                    </tr>
                </thead>
                <tbody>{top_ips_rows}</tbody>
            </table>
        </section>
    </main>
</body>
</html>"""


def build_json_report(
    summary: dict[str, object],
    alerts_df: pd.DataFrame,
    ioc_df: pd.DataFrame,
    generated_at: datetime | None = None,
) -> str:
    generated_at = generated_at or datetime.now()
    alerts_df = _safe_alerts(alerts_df)
    ioc_df = _safe_iocs(ioc_df)

    payload = {
        "generated_at": generated_at.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "alerts": _records(alerts_df),
        "ioc_data": _records(ioc_df),
    }
    return json.dumps(payload, indent=2, default=str)


def _safe_alerts(alerts_df: pd.DataFrame | None) -> pd.DataFrame:
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
        "threat_intel",
        "intel_tags",
        "mitre",
        "mitre_id",
        "mitre_name",
        "geo_country",
        "geo_city",
        "geo_isp",
        "geo_status",
        "vt_malicious",
        "vt_suspicious",
        "vt_harmless",
        "abuse_confidence_score",
        "abuse_total_reports",
        "abuse_last_reported",
    ]
    if alerts_df is None or alerts_df.empty:
        return pd.DataFrame(columns=columns)
    return alerts_df.reindex(columns=columns, fill_value="")


def _safe_iocs(ioc_df: pd.DataFrame | None) -> pd.DataFrame:
    columns = ["Indicator", "Type"]
    if ioc_df is None or ioc_df.empty:
        return pd.DataFrame(columns=columns)
    return ioc_df.reindex(columns=columns, fill_value="")


def _records(df: pd.DataFrame) -> list[dict[str, object]]:
    return df.where(pd.notna(df), None).to_dict(orient="records")
