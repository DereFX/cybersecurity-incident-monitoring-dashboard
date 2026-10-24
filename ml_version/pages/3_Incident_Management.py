from __future__ import annotations

from html import escape

import pandas as pd
import streamlit as st

from incidents.assignment_service import AssignmentService, VALID_STATUSES
from ui.resources import get_mongo, get_mysql, mysql_rows
from ui.filters import render_scope
from ui.presentation import display_table, duration_text
from ui.visibility import DatasetVisibility
from ui.theme import configure_page, incident_table, section_header, severity_badge

configure_page("Incident Management", "🚨")
section_header("Incident response workbench", "Filter, assign, investigate, document and resolve persistent MySQL cases.", "Response operations")
scope = render_scope("response")
scope_where, scope_params = scope.sql()
requested_id = st.session_state.pop("investigate_incident_id", None)
if requested_id is not None:
    st.session_state["response_target"] = requested_id
target_id = st.session_state.get("response_target")
visibility_where, visibility_params = DatasetVisibility(scope.excluded).sql()
if target_id:
    st.info(f"Showing incident #{target_id} selected from the Command Center. List filters are bypassed while this case is open.")
    if st.button("Return to filtered incident list"):
        st.session_state.pop("response_target", None)
        st.rerun()

filter_a, filter_b = st.columns(2)
status_filter = filter_a.multiselect("Status", sorted(VALID_STATUSES), default=["open", "assigned", "investigating"])
severity_filter = filter_b.multiselect("Severity", ["critical", "high", "medium", "low"], default=["critical", "high", "medium", "low"])
status_placeholders = ",".join(["%s"] * len(status_filter)) if status_filter else "NULL"
severity_placeholders = ",".join(["%s"] * len(severity_filter)) if severity_filter else "NULL"
incidents = mysql_rows(
    f"""
    SELECT i.incident_id, i.incident_time, tc.category_name, i.severity,
           i.status, COALESCE(a.name, 'Unassigned') analyst, i.description
    FROM incidents i JOIN threat_categories tc ON tc.category_id = i.category_id
    LEFT JOIN assignments x ON x.assignment_id=(SELECT MAX(x2.assignment_id) FROM assignments x2 WHERE x2.incident_id=i.incident_id)
    LEFT JOIN analysts a ON a.analyst_id=x.analyst_id
    WHERE {(f'i.incident_id=%s AND {visibility_where}' if target_id else f'i.status IN ({status_placeholders}) AND i.severity IN ({severity_placeholders}) AND {scope_where}')}
    ORDER BY FIELD(i.severity, 'critical','high','medium','low'), i.incident_time DESC
    LIMIT 500
    """,
    (target_id,) + visibility_params if target_id else tuple(status_filter) + tuple(severity_filter) + scope_params,
) if target_id or (status_filter and severity_filter) else []

active_count = sum(row["status"] in {"open", "assigned", "investigating"} for row in incidents)
urgent_count = sum(row["severity"] in {"critical", "high"} for row in incidents)
unassigned_count = sum(row["analyst"] == "Unassigned" for row in incidents)
metric_a, metric_b, metric_c, metric_d = st.columns(4)
metric_a.metric("Matching cases", len(incidents))
metric_b.metric("Active", active_count)
metric_c.metric("High / critical", urgent_count)
metric_d.metric("Unassigned", unassigned_count)
if incidents:
    incident_table(pd.DataFrame(incidents))

if not incidents:
    st.info("No incidents match these filters. Choose different dates, dataset, severity or status.")
    st.stop()

incident_ids = [row["incident_id"] for row in incidents]
selected_id = st.selectbox("Select incident to work", incident_ids)
details = mysql_rows("SELECT * FROM incidents WHERE incident_id=%s", (selected_id,))[0]
created_at, resolved_at = details.get("created_at"), details.get("resolved_at")
if resolved_at and created_at:
    st.caption(f"Case resolution time: {duration_text((resolved_at-created_at).total_seconds())} · measured from case creation")
evidence_tab, assignments_tab = st.tabs(["Detection & source evidence", "Assignment history"])
with evidence_tab:
    st.caption(f"Source: {details['source_dataset']} · Detector: {details['detected_by']}")
    try:
        mongo = get_mongo().database
        alert = mongo.security_alerts.find_one(
            {"detection_key": details["detection_key"], "source_dataset": details["source_dataset"]}, {"_id": 0}
        )
        references = alert.get("event_references", []) if alert else []
        if not references and details.get("source_event_id"):
            references = [details["source_event_id"]]
        if alert:
            evidence = alert.get("evidence", {})
            if "attack_probability" in evidence:
                probability_col, threshold_col = st.columns(2)
                probability_col.metric("Model attack probability", f"{evidence['attack_probability']:.1%}")
                threshold_col.metric("Decision threshold", f"{evidence['decision_threshold']:.1%}")
            st.write(alert.get("description", ""))
            with st.expander("Detection evidence", expanded=True):
                st.json(evidence)
        else:
            st.info("The linked alert is unavailable. Showing the stored source-event reference where possible.")
        source_events = list(mongo.security_events.find(
            {"source_dataset": details["source_dataset"], "event_id": {"$in": references}},
            {"_id": 0},
        ).limit(100))
        st.caption(f"Source events: {len(source_events)} displayed, up to 100. Matching is restricted to this incident's dataset.")
        if source_events:
            st.json(source_events, expanded=False)
        else:
            st.info("No linked source documents were found.")
    except Exception:
        st.warning("MongoDB evidence is unavailable. MySQL response records can still be reviewed below.")
with assignments_tab:
    assignment_history = mysql_rows("""SELECT x.assigned_at, a.name analyst, x.resolved_at,
        x.response_action, x.comments FROM assignments x JOIN analysts a ON a.analyst_id=x.analyst_id
        WHERE x.incident_id=%s ORDER BY x.assigned_at DESC""", (selected_id,))
    display_table(assignment_history, empty="This incident has not been assigned yet.")
analysts = mysql_rows(
    "SELECT analyst_id, name, role, team FROM analysts WHERE active = TRUE ORDER BY name"
)
analyst_options = {f"{row['name']} — {row['team']}": row["analyst_id"] for row in analysts}
if not analyst_options:
    st.warning("No active analysts are configured. Run the database seed script before assigning or recording responses.")
    st.stop()
service = AssignmentService(get_mysql())
selected = next(row for row in incidents if row["incident_id"] == selected_id)
st.markdown(
    f'<div class="case-summary">{severity_badge(selected["severity"])} '
    f'<strong>Incident #{selected_id} · {escape(selected["category_name"])}</strong>'
    f'<p style="color:#627078;margin:.7rem 0 0">{escape(selected["description"])}</p></div>',
    unsafe_allow_html=True,
)

assign_tab, status_tab, response_tab = st.tabs(["Assign analyst", "Change status", "Record response"])
with assign_tab:
    with st.form("assign_incident"):
        analyst_label = st.selectbox("Assign analyst", list(analyst_options))
        comments = st.text_area("Assignment comments")
        if st.form_submit_button("Assign incident", type="primary"):
            try:
                service.assign(selected_id, analyst_options[analyst_label], comments)
                st.success("Incident assigned.")
                st.rerun()
            except Exception as error:
                st.error(str(error))
with status_tab:
    with st.form("update_status"):
        new_status = st.selectbox("New status", sorted(VALID_STATUSES), index=sorted(VALID_STATUSES).index(details["status"]))
        status_actor = st.selectbox("Analyst recording the update", list(analyst_options))
        notes = st.text_area("Investigation notes")
        if st.form_submit_button("Update status", type="primary"):
            try:
                service.change_status(selected_id, new_status, analyst_id=analyst_options[status_actor], notes=notes)
                st.success("Incident updated.")
                st.rerun()
            except Exception as error:
                st.error(str(error))
with response_tab:
    with st.form("record_response"):
        response_analyst = st.selectbox("Responding analyst", list(analyst_options), key="response_analyst")
        response_action = st.text_input("Response action", placeholder="Example: Disabled account and reset credentials")
        response_comments = st.text_area("Response notes")
        if st.form_submit_button("Save response action", type="primary"):
            try:
                service.add_response(selected_id, analyst_options[response_analyst], response_action, response_comments)
                st.success("Response action saved to the assignment and audit history.")
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
section_header("Incident history", "Immutable audit entries for the selected case.", "Audit trail")
display_table(history)
