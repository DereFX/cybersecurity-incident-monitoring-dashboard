"""Editable, scoped database query forms and downloadable results."""

import json

from bson import json_util
import pandas as pd
import streamlit as st

from analytics import custom_queries as queries
from ui import resources

SQL_EXAMPLE = """SELECT severity, COUNT(*) AS incident_count
FROM incidents
GROUP BY severity
ORDER BY incident_count DESC;"""
MONGO_EXAMPLE = json.dumps([
    {"$group": {"_id": "$event_type", "event_count": {"$sum": 1}}},
    {"$sort": {"event_count": -1}},
], indent=2)


def _results(kind, signature):
    saved = st.session_state.get(f"custom_{kind}_result")
    if not saved or saved[0] != signature:
        return
    result = saved[1]
    st.success(f"Returned {len(result.rows):,} rows in {result.elapsed_seconds:.2f}s.")
    if result.truncated:
        st.warning("Showing the first 500 rows. Narrow the query to see a smaller result.")
    if result.rows:
        # JSON-normalise BSON values and nested documents for a stable table display.
        rows = json.loads(json_util.dumps(result.rows, default=str))
        flat = [{key: json.dumps(value) if isinstance(value, (dict, list)) else value
                 for key, value in row.items()} for row in rows]
        frame = pd.DataFrame(flat)
        st.dataframe(frame, width="stretch", hide_index=True)
        st.download_button("Download CSV", frame.to_csv(index=False), f"custom_{kind}_results.csv",
                           "text/csv", key=f"custom_{kind}_csv")
        st.download_button("Download JSON", json_util.dumps(result.rows, indent=2, default=str),
                           f"custom_{kind}_results.json", "application/json", key=f"custom_{kind}_json")
    else:
        st.info("The query ran successfully but no records matched.")
    with st.expander("Executed query (including CSV inclusion filters)"):
        st.code(result.executed_query, language="sql" if kind == "sql" else "json")


def _run(kind, signature, operation):
    st.session_state.pop(f"custom_{kind}_result", None)
    try:
        with st.spinner("Running read-only query…"):
            result = operation()
        st.session_state[f"custom_{kind}_result"] = (signature, result)
    except queries.QueryInputError as error:
        st.error(str(error))
    except Exception as error:
        # Do not expose connection strings or server credentials in driver errors.
        code = getattr(error, "errno", None) or getattr(error, "code", None)
        if code in {1054, 1052, 1064, 1146}:
            st.error("Check your column names, aliases and query syntax. Expand the schema guide below for help.")
        elif code in {50, 3024}:
            st.error("Query exceeded the five-second execution limit. Add filters or simplify the query.")
        else:
            st.error("Query could not run. Check database connectivity, field names and supported query syntax.")


def render_custom_sql(visibility):
    st.subheader("Write your own SQL")
    st.caption("Read-only SELECT queries · 500-row display limit · 5-second server execution limit. CSV inclusion switches apply automatically.")
    with st.expander("SQL schema guide and examples"):
        st.write("Available tables: " + ", ".join(sorted(queries.SQL_TABLES)))
        st.code("""incidents: incident_id, incident_time, severity, status, category_id,
           user_id, system_id, source_dataset, description
users: user_id, username, email, department, role, status, source_dataset
systems: system_id, hostname, ip_address, os, system_type, source_dataset
analysts: analyst_id, name, role, team
threat_categories: category_id, category_name, default_severity
assignments: assignment_id, incident_id, analyst_id, assigned_at, resolved_at
incident_audit_log: incident_id (see database/schema.sql for full schema)""", language="text")
        st.code("""SELECT c.category_name, i.severity, COUNT(*) AS total
FROM incidents i JOIN threat_categories c ON c.category_id = i.category_id
GROUP BY c.category_name, i.severity
HAVING COUNT(*) >= 2
ORDER BY total DESC;""", language="sql")
        st.write("Joins, subqueries, non-recursive CTEs and common aggregate functions are supported. Use literal values in WHERE clauses, not %s placeholders. Database prefixes, writes, stored procedures and unapproved functions are blocked.")
    with st.form("custom_sql_form"):
        text = st.text_area("SQL query", SQL_EXAMPLE, height=210, key="custom_sql_text")
        submitted = st.form_submit_button("Run custom SQL", type="primary")
    signature = (text, visibility.excluded)
    if submitted:
        _run("sql", signature, lambda: queries.execute_sql(resources.get_mysql(), text, visibility))
    _results("sql", signature)


def render_custom_mongo(visibility):
    st.subheader("Write your own MongoDB query")
    st.caption("Read-only JSON filters or aggregation pipelines · 500-row display limit · 5-second server execution limit. CSV inclusion switches apply automatically.")
    with st.expander("MongoDB field guide and examples"):
        st.write("security_events: event_id, timestamp, source_dataset, event_type, user_id, source_ip, authentication_result, attack_category. Optional fields vary by dataset.")
        st.write("security_alerts: alert_id, rule_name, timestamp, severity, source_dataset, evidence, event_references. Inspect a result to confirm available fields.")
        st.code('{"event_type": "authentication", "authentication_result": "failure"}', language="json")
        st.code('[{"$group": {"_id": "$source_dataset", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}]', language="json")
        st.write('Use JSON, not db.collection.find() or JavaScript. Dates can use Extended JSON, e.g. {"timestamp": {"$gte": {"$date": "2026-01-01T00:00:00Z"}}}. Writes, JavaScript and collection joins are blocked.')
    with st.form("custom_mongo_form"):
        collection = st.selectbox("Collection", sorted(queries.MONGO_COLLECTIONS), index=1, key="custom_mongo_collection")
        text = st.text_area("JSON filter or aggregation pipeline", MONGO_EXAMPLE, height=260, key="custom_mongo_text")
        submitted = st.form_submit_button("Run custom MongoDB query", type="primary")
    signature = (collection, text, visibility.excluded)
    if submitted:
        _run("mongo", signature, lambda: queries.execute_mongo(resources.get_mongo().database, collection, text, visibility))
    _results("mongo", signature)
