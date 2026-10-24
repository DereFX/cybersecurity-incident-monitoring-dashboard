from __future__ import annotations

import streamlit as st

from incidents.assignment_service import AssignmentService, VALID_STATUSES
from ui.resources import get_mysql, mysql_rows
from ui.theme import configure_page

configure_page("Incident Management", "🚨")

status_filter = st.multiselect(
    "Status", sorted(VALID_STATUSES), default=["open", "assigned", "investigating"]
)
placeholders = ",".join(["%s"] * len(status_filter)) if status_filter else "NULL"
incidents = mysql_rows(
    f"""
    SELECT i.incident_id, i.incident_time, tc.category_name, i.severity,
           i.status, i.description
    FROM incidents i JOIN threat_categories tc ON tc.category_id = i.category_id
    WHERE i.status IN ({placeholders})
    ORDER BY FIELD(i.severity, 'critical','high','medium','low'), i.incident_time DESC
    LIMIT 500
    """,
    tuple(status_filter),
) if status_filter else []
st.dataframe(incidents, width="stretch", hide_index=True)

if not incidents:
    st.info("No incidents match the selected statuses.")
    st.stop()

incident_ids = [row["incident_id"] for row in incidents]
selected_id = st.selectbox("Select incident", incident_ids)
analysts = mysql_rows(
    "SELECT analyst_id, name, role, team FROM analysts WHERE active = TRUE ORDER BY name"
)
analyst_options = {f"{row['name']} — {row['team']}": row["analyst_id"] for row in analysts}
service = AssignmentService(get_mysql())

with st.form("assign_incident"):
    analyst_label = st.selectbox("Assign analyst", list(analyst_options))
    comments = st.text_area("Assignment comments")
    if st.form_submit_button("Assign"):
        try:
            service.assign(selected_id, analyst_options[analyst_label], comments)
            st.success("Incident assigned.")
            st.rerun()
        except Exception as error:
            st.error(str(error))

with st.form("update_status"):
    new_status = st.selectbox("New status", sorted(VALID_STATUSES))
    notes = st.text_area("Investigation notes")
    if st.form_submit_button("Update status"):
        try:
            service.change_status(selected_id, new_status, notes=notes)
            st.success("Incident updated.")
            st.rerun()
        except Exception as error:
            st.error(str(error))

history = mysql_rows(
    """
    SELECT created_at, action, old_status, new_status, notes
    FROM incident_audit_log WHERE incident_id = %s ORDER BY created_at DESC
    """,
    (selected_id,),
)
st.subheader("Incident history")
st.dataframe(history, width="stretch", hide_index=True)
