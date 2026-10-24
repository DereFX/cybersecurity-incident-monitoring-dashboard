"""Security Overview page."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from ui.resources import get_mongo, mysql_rows
from ui.theme import configure_page

configure_page("Security Overview")

try:
    metrics = mysql_rows(
        """
        SELECT COUNT(*) total,
               SUM(status IN ('open','assigned','investigating')) open_count,
               SUM(severity = 'critical') critical_count,
               SUM(status = 'resolved') resolved_count,
               COUNT(DISTINCT user_id) affected_users
        FROM incidents
        """
    )[0]
    failed_logins = get_mongo().database.security_events.count_documents(
        {"event_type": "authentication", "authentication_result": "failure"}
    )
except Exception as error:
    st.error(f"Database connection failed: {error}")
    st.stop()

columns = st.columns(6)
labels = [
    ("Total incidents", metrics["total"]),
    ("Open incidents", metrics["open_count"] or 0),
    ("Critical incidents", metrics["critical_count"] or 0),
    ("Resolved incidents", metrics["resolved_count"] or 0),
    ("Failed logins", failed_logins),
    ("Affected users", metrics["affected_users"] or 0),
]
for column, (label, value) in zip(columns, labels, strict=True):
    column.metric(label, int(value))

left, right = st.columns(2)
trend = pd.DataFrame(
    mysql_rows(
        """
        SELECT DATE(incident_time) incident_date, COUNT(*) incident_count
        FROM incidents GROUP BY DATE(incident_time) ORDER BY incident_date
        """
    )
)
if not trend.empty:
    left.plotly_chart(
        px.line(trend, x="incident_date", y="incident_count", markers=True,
                title="Incidents over time"),
        width="stretch",
    )

severity = pd.DataFrame(
    mysql_rows(
        "SELECT severity, COUNT(*) incident_count FROM incidents GROUP BY severity"
    )
)
if not severity.empty:
    right.plotly_chart(
        px.pie(severity, names="severity", values="incident_count",
               title="Severity distribution", hole=0.45),
        width="stretch",
    )

st.subheader("Latest incidents")
latest = mysql_rows(
    """
    SELECT i.incident_id, i.incident_time, tc.category_name,
           i.severity, i.status, i.description
    FROM incidents i
    JOIN threat_categories tc ON tc.category_id = i.category_id
    ORDER BY i.incident_time DESC LIMIT 20
    """
)
latest_frame = pd.DataFrame(latest)
if latest_frame.empty:
    st.info("No incidents have been created yet.")
else:
    def highlight_high_severity_id(row: pd.Series) -> list[str]:
        """Highlight only the incident ID when its severity is high."""

        return [
            "color: #ff4b4b; font-weight: 700" if (
                column == "incident_id" and str(row["severity"]).lower() == "high"
            ) else ""
            for column in latest_frame.columns
        ]

    styled_latest = latest_frame.style.apply(highlight_high_severity_id, axis=1)
    st.dataframe(styled_latest, width="stretch", hide_index=True)
