"""Read-only, curated SQL and MongoDB query demonstrations."""

import json

import pandas as pd
import streamlit as st
from bson import json_util

from analytics import mongo_aggregations as mongo_queries
from analytics import sql_queries
from ui.resources import get_mongo, get_mysql, mysql_rows
from ui.theme import configure_page, section_header
from ui.visibility import dashboard_visibility
from ui.query_editor import render_custom_sql, render_custom_mongo


configure_page("Database Explorer", "🗄️")
visibility = dashboard_visibility()
section_header("Explore your databases", "Run saved analyses or write your own read-only SQL and MongoDB queries.", "SQL + NoSQL")
sql_tab, mongo_tab, procedure_tab, custom_sql_tab, custom_mongo_tab = st.tabs(
    ["MySQL analysis", "MongoDB pipelines", "Stored procedure", "Custom SQL", "Custom MongoDB"])

with custom_sql_tab:
    render_custom_sql(visibility)

with custom_mongo_tab:
    render_custom_mongo(visibility)

with sql_tab:
    query_names = [name for name in vars(sql_queries) if name.isupper()]
    selected = st.selectbox("SQL analysis", query_names, format_func=lambda name: name.replace("_", " ").title())
    query = getattr(sql_queries, selected)
    params = ()
    if selected == "INCIDENT_COUNTS_BY_CATEGORY_SEVERITY":
        minimum = st.number_input("Minimum incidents per group (HAVING)", min_value=1, value=1)
        params = (int(minimum),)
    query, params = visibility.report_sql(query, params)
    st.code(query.strip(), language="sql")
    st.caption("Predefined read-only query; display is limited to 500 rows.")
    if st.button("Run SQL analysis", type="primary"):
        try:
            rows = mysql_rows(query.rstrip().rstrip(";") + " LIMIT 500", params)
            st.success(f"Returned {len(rows):,} rows (maximum 500).")
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        except Exception:
            st.error("SQL analysis could not run. Check MySQL connectivity and initialise the schema.")

with mongo_tab:
    pipelines = {
        "Events by observed category": ("security_events", mongo_queries.events_by_category),
        "Daily event trend": ("security_events", mongo_queries.daily_event_trend),
        "Hourly event trend": ("security_events", mongo_queries.hourly_event_trend),
        "Top source IPs": ("security_events", mongo_queries.top_source_ips),
        "Failed logins by user": ("security_events", mongo_queries.failed_logins_by_user),
        "High-severity alerts by rule": ("security_alerts", mongo_queries.high_severity_alerts_by_rule),
    }
    selected_pipeline = st.selectbox("Aggregation", list(pipelines))
    collection, factory = pipelines[selected_pipeline]
    pipeline = [{"$match": visibility.mongo()}] + factory() + [{"$limit": 500}]
    st.caption(f"Collection: {collection}")
    st.code(json.dumps(pipeline, indent=2), language="json")
    if st.button("Run MongoDB aggregation", type="primary"):
        try:
            rows = list(get_mongo().database[collection].aggregate(pipeline, maxTimeMS=10000))
            st.success(f"Returned {len(rows):,} groups (maximum 500).")
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
            st.download_button("Download results as JSON", json_util.dumps(rows, indent=2), "aggregation_results.json", "application/json")
        except Exception:
            st.error("Aggregation could not run. Check MongoDB connectivity and supported server version.")

with procedure_tab:
    st.write("Summarise one MySQL user's security posture using the stored procedure.")
    user_id = st.number_input("MySQL user ID", min_value=1, value=1, step=1)
    st.code("CALL sp_user_security_summary(%s);", language="sql")
    if visibility.excluded:
        st.info("The installed stored procedure reads all stored datasets. Its demonstration is disabled while CSVs are excluded; the SQL analysis tab applies your inclusion settings.")
    if st.button("Run user security summary", type="primary", disabled=bool(visibility.excluded)):
        try:
            with get_mysql().connection() as connection:
                cursor = connection.cursor(dictionary=True)
                try:
                    cursor.callproc("sp_user_security_summary", (int(user_id),))
                    for result in cursor.stored_results():
                        st.dataframe(pd.DataFrame(result.fetchall()), width="stretch", hide_index=True)
                finally:
                    cursor.close()
        except Exception:
            st.error("Stored procedure could not run. Check the database and run database/procedures.sql.")
