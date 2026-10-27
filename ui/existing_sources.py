"""Connect existing dataset discovery to the Data Pipeline library."""

from pathlib import Path

import streamlit as st

from etl.existing_sources import collect_existing_sources, register_existing_sources


@st.cache_data(ttl=30, show_spinner=False)
def existing_source_counts() -> list[dict]:
    from ui.resources import get_mongo, mysql_rows

    database = get_mongo().database
    incidents = mysql_rows("SELECT source_dataset, COUNT(*) incident_count FROM incidents GROUP BY source_dataset")
    events = list(database.security_events.aggregate([{"$group": {
        "_id": "$source_dataset", "event_count": {"$sum": 1}, "event_types": {"$addToSet": "$event_type"}}}]))
    alerts = list(database.security_alerts.aggregate([{"$group": {
        "_id": "$source_dataset", "alert_count": {"$sum": 1}}}]))
    return collect_existing_sources(incidents, events, alerts)


def sync_existing_sources(database) -> None:
    register_existing_sources(database, existing_source_counts(), Path(__file__).resolve().parents[1])
