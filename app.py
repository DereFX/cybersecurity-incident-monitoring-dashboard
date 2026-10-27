"""Executive SOC command center."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from detection.ml_network import DEFAULT_MODEL_PATH, load_model_bundle
from ui.resources import get_mongo, mysql_rows
from ui.filters import render_scope
from ui.presentation import display_table, duration_text
from ui.theme import COLORS, configure_page, incident_table, section_header, style_chart

configure_page("SOC Command Center")

try:
    mongo = get_mongo().database
except Exception as error:
    st.error(f"The dashboard could not reach its databases: {error}")
    st.caption("Confirm that MySQL and MongoDB are running, then refresh this page.")
    st.stop()

section_header("Operational picture", "Live posture across Python detection, MongoDB events and MySQL response records.", "Command center")
scope = render_scope("overview")
scope_where, scope_params = scope.sql()
available_severities = ["critical", "high", "medium", "low"]
severities = st.multiselect("Incident severity", available_severities, default=available_severities)
where_parts = [scope_where]
params: list[object] = list(scope_params)
if severities:
    where_parts.append(f"i.severity IN ({','.join(['%s'] * len(severities))})")
    params.extend(severities)
else:
    where_parts.append("1 = 0")
where_sql = " AND ".join(where_parts)

metrics = mysql_rows(f"""SELECT COUNT(*) total,
    SUM(i.status IN ('open','assigned','investigating')) active_count,
    SUM(i.severity IN ('critical','high')) serious_count,
    SUM(i.status = 'resolved') resolved_count, COUNT(DISTINCT i.user_id) affected_users,
    AVG(CASE WHEN i.status='resolved' AND i.resolved_at>=i.created_at
        THEN TIMESTAMPDIFF(SECOND,i.created_at,i.resolved_at) END) avg_resolution_seconds,
    SUM(i.severity IN ('high','critical') AND i.status IN ('open','assigned','investigating')
        AND NOT EXISTS (SELECT 1 FROM assignments a WHERE a.incident_id=i.incident_id AND a.resolved_at IS NULL)) unassigned_urgent
    FROM incidents i WHERE {where_sql}""", tuple(params))[0]
failed_logins = mongo.security_events.count_documents({**scope.mongo(), "event_type": "authentication", "authentication_result": "failure"})
event_count = mongo.security_events.count_documents(scope.mongo())
alert_count = mongo.security_alerts.count_documents(scope.mongo())
model_metrics = load_model_bundle(str(DEFAULT_MODEL_PATH.resolve()))["metadata"]["test_metrics"]
total, active = int(metrics["total"] or 0), int(metrics["active_count"] or 0)
serious, resolved = int(metrics["serious_count"] or 0), int(metrics["resolved_count"] or 0)

st.caption(f"Event store: {event_count:,} events · {alert_count:,} alerts in the selected scope. Model test recall: {model_metrics['recall']:.1%}.")
labels = [("Total incidents", total, f"{int(metrics['affected_users'] or 0):,} affected identities"),
          ("Active cases", active, f"{serious:,} high / critical in scope"),
          ("Unassigned urgent", int(metrics.get('unassigned_urgent') or 0), "Active high / critical cases"),
          ("Resolution rate", f"{resolved/total:.1%}" if total else "0.0%", f"{resolved:,} resolved"),
          ("Avg. resolution", duration_text(metrics.get('avg_resolution_seconds')) if metrics.get('avg_resolution_seconds') is not None else "—", "No resolved cases" if metrics.get('avg_resolution_seconds') is None else "From case creation to resolution"),
          ("Failed logins", failed_logins, "Selected event dates / dataset")]
for offset in (0, 3):
    columns = st.columns(3)
    for column, (label, value, delta) in zip(columns, labels[offset:offset + 3], strict=True):
        column.metric(label, f"{value:,}" if isinstance(value, int) else value, delta, delta_color="off")

trend = pd.DataFrame(mysql_rows(f"""SELECT DATE(i.incident_time) incident_date, i.severity, COUNT(*) incident_count
    FROM incidents i WHERE {where_sql} GROUP BY DATE(i.incident_time), i.severity ORDER BY incident_date""", tuple(params)))
severity = pd.DataFrame(mysql_rows(f"SELECT i.severity, COUNT(*) incident_count FROM incidents i WHERE {where_sql} GROUP BY i.severity", tuple(params)))
categories = pd.DataFrame(mysql_rows(f"""SELECT tc.category_name, COUNT(*) incident_count FROM incidents i
    JOIN threat_categories tc ON tc.category_id=i.category_id WHERE {where_sql}
    GROUP BY tc.category_name ORDER BY incident_count DESC""", tuple(params)))
statuses = pd.DataFrame(mysql_rows(f"SELECT i.status, COUNT(*) incident_count FROM incidents i WHERE {where_sql} GROUP BY i.status", tuple(params)))

st.divider()
section_header("Incident intelligence", "Select a severity or category in a risk chart to filter the investigation queue below.", "Live analytics")

def drill_from_chart(event, key: str, field: str) -> None:
    points = event.selection.points
    if points:
        value = points[0].get("customdata", [None])[0]
        signature = (field, value)
        if value and st.session_state.get(key + "_last") != signature:
            st.session_state[key + "_last"] = signature
            st.session_state["queue_drill"] = {field: value}

tab_timeline, tab_risk, tab_operations = st.tabs(["Timeline", "Risk profile", "Response workflow"])
with tab_timeline:
    if trend.empty:
        st.info("No incidents match the current filters.")
    else:
        chart = px.area(trend, x="incident_date", y="incident_count", color="severity", markers=True,
                        title="Detected incidents over time", category_orders={"severity": available_severities},
                        color_discrete_map={"critical": COLORS["violet"], "high": COLORS["red"], "medium": COLORS["amber"], "low": COLORS["cyan"]})
        st.plotly_chart(style_chart(chart, height=390), width="stretch")
with tab_risk:
    left, right = st.columns([.85, 1.15])
    if not severity.empty:
        donut = px.bar(severity, x="severity", y="incident_count", color="severity", title="Select a severity", custom_data=["severity"],
                       color_discrete_map={"critical": COLORS["violet"], "high": COLORS["red"], "medium": COLORS["amber"], "low": COLORS["cyan"]})
        donut.update_layout(showlegend=False)
        drill_from_chart(left.plotly_chart(style_chart(donut, height=380), width="stretch", on_select="rerun", key="severity_chart"), "severity_chart", "severity")
    if not categories.empty:
        bar = px.bar(categories.sort_values("incident_count"), x="incident_count", y="category_name", orientation="h",
                     title="Incident categories", color="incident_count", custom_data=["category_name"], color_continuous_scale=["#ccebe2", COLORS["mint"]])
        bar.update_layout(coloraxis_showscale=False)
        drill_from_chart(right.plotly_chart(style_chart(bar, height=380), width="stretch", on_select="rerun", key="category_chart"), "category_chart", "category_name")
with tab_operations:
    if not statuses.empty:
        workflow = px.bar(statuses, x="status", y="incident_count", color="status", text_auto=True, title="Cases by response state",
                          color_discrete_sequence=[COLORS["cyan"], COLORS["amber"], COLORS["violet"], COLORS["mint"]])
        workflow.update_layout(showlegend=False)
        st.plotly_chart(style_chart(workflow, height=360), width="stretch")
    workload = mysql_rows(f"""SELECT a.name analyst, COUNT(DISTINCT i.incident_id) active_cases,
        SUM(i.severity IN ('high','critical')) urgent_cases
        FROM analysts a JOIN assignments x ON x.analyst_id=a.analyst_id AND x.resolved_at IS NULL
        JOIN incidents i ON i.incident_id=x.incident_id
        WHERE {where_sql} AND i.status IN ('assigned','investigating')
        GROUP BY a.analyst_id,a.name ORDER BY active_cases DESC""", tuple(params))
    st.markdown("#### Analyst workload")
    display_table(workload, empty="No active assignments in this scope. Assign a case from Incident Response to see workload here.")
    st.caption("Resolution time starts when this app created the case, rather than the historical event date in an uploaded dataset.")

st.divider()
section_header("Priority incident queue", "Newest filtered cases. High-severity incident IDs are highlighted in red.", "Analyst workbench")
queue_where, queue_params = where_sql, list(params)
drill = st.session_state.get("queue_drill", {})
if drill:
    field, value = next(iter(drill.items()))
    if st.button(f"Clear chart filter: {field.replace('_', ' ')} = {value}"):
        st.session_state["queue_drill"] = {}
        st.rerun()
    if field == "severity":
        queue_where += " AND i.severity=%s"
        queue_params.append(value)
    elif field == "category_name":
        queue_where += " AND tc.category_name=%s"
        queue_params.append(value)
latest = mysql_rows(
    f"""
    SELECT i.incident_id, i.incident_time, tc.category_name, i.severity, i.status,
           COALESCE(u.username, 'Not linked') affected_user,
           COALESCE(s.hostname, 'Not linked') affected_system, i.description
    FROM incidents i
    JOIN threat_categories tc ON tc.category_id = i.category_id
    LEFT JOIN users u ON u.user_id=i.user_id LEFT JOIN systems s ON s.system_id=i.system_id
    WHERE {queue_where}
    ORDER BY FIELD(i.severity,'critical','high','medium','low'), i.incident_time DESC LIMIT 100
    """, tuple(queue_params)
)
latest_frame = pd.DataFrame(latest)
if latest_frame.empty:
    st.info("No incidents match these filters. Clear a filter or import events on Data Pipeline.")
else:
    incident_table(latest_frame, height=430)
    case_id = st.selectbox("Investigate an incident", [row["incident_id"] for row in latest])
    if st.button("Open incident details", type="primary"):
        st.session_state["investigate_incident_id"] = case_id
        st.switch_page("pages/3_Incident_Management.py")

st.caption("Model performance shown here is measured on the held-out supplied quickstart data; it is evidence for evaluation, not a guarantee of live-network performance.")
