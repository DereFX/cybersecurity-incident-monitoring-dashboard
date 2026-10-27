from __future__ import annotations

import re
import pandas as pd
import plotly.express as px
import streamlit as st

from analytics.mongo_aggregations import failed_logins_by_user
from ui.resources import get_mongo, mysql_rows
from ui.filters import render_scope
from ui.presentation import display_table
from ui.theme import COLORS, configure_page, section_header, style_chart

configure_page("User & Device Monitoring", "👤")
scope = render_scope("identity")
section_header("Identity and device risk", "Investigate authentication patterns, access origins and related incidents.", "Identity monitoring")

search_col, result_col = st.columns([1.2, .8])
search = search_col.text_input("Search user ID", placeholder="Example: USR00152")
result_filter = result_col.selectbox("Authentication result", ["All", "failure", "success"])
query: dict = {**scope.mongo(), "event_type": "authentication"}
if search:
    query["user_id"] = {"$regex": re.escape(search), "$options": "i"}
if result_filter != "All":
    query["authentication_result"] = result_filter

events = list(
    get_mongo().database.security_events.find(
        query,
        {"_id": 0, "event_id": 1, "timestamp": 1, "user_id": 1,
         "source_ip": 1, "device_id": 1, "authentication_result": 1},
    ).sort("timestamp", -1).limit(200)
)
events_frame = pd.DataFrame(events)
total_events = len(events_frame)
result_series = events_frame.get("authentication_result", pd.Series(dtype="object"))
failure_count = int((result_series == "failure").sum())
unique_users = int(events_frame["user_id"].nunique()) if not events_frame.empty and "user_id" in events_frame else 0
unique_origins = int(events_frame["source_ip"].nunique()) if not events_frame.empty and "source_ip" in events_frame else 0
metric_columns = st.columns(4)
metric_columns[0].metric("Visible events", total_events, "Latest 200")
metric_columns[1].metric("Failed attempts", failure_count)
metric_columns[2].metric("Identities", unique_users)
metric_columns[3].metric("Source IPs", unique_origins)

failed = pd.DataFrame(
    list(get_mongo().database.security_events.aggregate([{"$match": query}] + failed_logins_by_user()))
)
if not failed.empty:
    failed = failed.rename(columns={"_id": "user_id"})

activity_tab, failed_tab, origin_tab = st.tabs(["Authentication timeline", "Failed-login leaders", "Origins & devices"])
with activity_tab:
    if events_frame.empty:
        st.info("No authentication events match the filters.")
    else:
        events_frame["timestamp"] = pd.to_datetime(events_frame["timestamp"], errors="coerce")
        timeline = events_frame.dropna(subset=["timestamp"]).assign(hour=lambda frame: frame["timestamp"].dt.floor("h"))
        timeline = timeline.groupby(["hour", "authentication_result"], dropna=False).size().reset_index(name="events")
        chart = px.area(timeline, x="hour", y="events", color="authentication_result", markers=True,
                        title="Authentication outcomes over time",
                        color_discrete_map={"failure": COLORS["red"], "success": COLORS["mint"]})
        st.plotly_chart(style_chart(chart, height=350), width="stretch")
        display_table(events_frame, height=320)
with failed_tab:
    if failed.empty:
        st.info("No failed logins are stored.")
    else:
        chart = px.bar(failed.sort_values("failed_logins"), x="failed_logins", y="user_id", orientation="h",
                       title="Users with the most failed logins", color="failed_logins",
                       color_continuous_scale=["#f8d6db", COLORS["red"]])
        chart.update_layout(coloraxis_showscale=False)
        st.plotly_chart(style_chart(chart, height=440), width="stretch")
with origin_tab:
    if events_frame.empty:
        st.info("No origins or devices match the filters.")
    else:
        origin_counts = events_frame.groupby(["source_ip", "device_id"], dropna=False).size().reset_index(name="events").sort_values("events", ascending=False)
        display_table(origin_counts, height=420)

if search:
    scope_where, scope_params = scope.sql()
    incidents = mysql_rows(
        f"""
        SELECT i.incident_id, i.incident_time, i.severity, i.status, i.description
        FROM incidents i JOIN users u ON u.user_id = i.user_id
        WHERE u.external_user_id LIKE %s AND {scope_where} ORDER BY i.incident_time DESC
        """,
        (f"%{search}%",) + scope_params,
    )
    st.divider()
    section_header("Associated incidents", f"MySQL cases linked to identity search: {search}", "Cross-database view")
    if incidents:
        display_table(incidents)
    else:
        st.info("No MySQL incidents are linked to this identity.")
