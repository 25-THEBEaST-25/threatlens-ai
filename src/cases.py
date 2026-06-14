from __future__ import annotations

from datetime import datetime

import pandas as pd


CASE_STATUSES = ("Open", "Investigating", "Contained", "Resolved", "False Positive")


def build_case_summary(alert_df: pd.DataFrame, status: str, owner: str, notes: str) -> dict[str, object]:
    highest_risk = "LOW"
    top_ip = "N/A"
    if not alert_df.empty:
        highest_risk = str(alert_df.iloc[0]["risk"])
        top_ip = str(alert_df.iloc[0]["ip"])

    return {
        "case_id": f"TL-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "status": status,
        "owner": owner or "Unassigned",
        "highest_risk": highest_risk,
        "top_ip": top_ip,
        "alert_count": int(len(alert_df)),
        "notes": notes.strip(),
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def render_case_markdown(case: dict[str, object]) -> str:
    return f"""# ThreatLens Case

- Case ID: {case["case_id"]}
- Status: {case["status"]}
- Owner: {case["owner"]}
- Highest risk: {case["highest_risk"]}
- Top IP: {case["top_ip"]}
- Alert count: {case["alert_count"]}
- Updated: {case["updated_at"]}

## Notes

{case["notes"] or "No analyst notes added."}
"""

