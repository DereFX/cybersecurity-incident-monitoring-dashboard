from __future__ import annotations

import pandas as pd
import streamlit as st

from analytics.mongo_aggregations import failed_logins_by_user
from ui.resources import get_mongo, mysql_rows
from ui.theme import configure_page

configure_page("User & Device Monitoring", "👤")

search = st.text_input("Search user ID", placeholder="Example: USR00152")
query: dict = {"event_type": "authentication"}
if search:
    query["user_id"] = {"$regex": search, "$options": "i"}

events = list(
    get_mongo().database.security_events.find(
        query,
        {"_id": 0, "event_id": 1, "timestamp": 1, "user_id": 1,
         "source_ip": 1, "device_id": 1, "authentication_result": 1},
    ).sort("timestamp", -1).limit(200)
)
st.subheader("Recent authentication activity")
st.dataframe(events, width="stretch", hide_index=True)

st.subheader("Users with the most failed logins")
failed = pd.DataFrame(
    list(get_mongo().database.security_events.aggregate(failed_logins_by_user()))
)
if not failed.empty:
    failed = failed.rename(columns={"_id": "user_id"})
st.dataframe(failed, width="stretch", hide_index=True)

if search:
    incidents = mysql_rows(
        """
        SELECT i.incident_id, i.incident_time, i.severity, i.status, i.description
        FROM incidents i JOIN users u ON u.user_id = i.user_id
        WHERE u.external_user_id LIKE %s ORDER BY i.incident_time DESC
        """,
        (f"%{search}%",),
    )
    st.subheader("Associated incidents")
    st.dataframe(incidents, width="stretch", hide_index=True)
