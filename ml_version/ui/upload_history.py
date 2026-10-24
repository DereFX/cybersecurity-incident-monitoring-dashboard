"""Per-file pipeline history and reversible visibility controls."""

import re
from hashlib import sha256
from pathlib import Path

import streamlit as st

from etl.upload_history import UploadHistory
from ui.presentation import display_table
from ui.theme import section_header


def render_upload_history() -> None:
    from ui.resources import get_mongo, mysql_rows

    section_header("Dataset & CSV library", "Manage data already in the databases alongside newly uploaded CSVs.", "Pipeline history")
    st.caption("Keep each CSV listed here and switch Include in dashboard off to exclude its events, alerts and incidents from dashboard counts, charts and lists. Switching it on includes the data again. Nothing is deleted.")
    try:
        database = get_mongo().database
        history = UploadHistory(database)
        from ui.existing_sources import sync_existing_sources
        sync_existing_sources(database)
        existing = list(history.files.find({"record_kind": "existing_dataset"}))
        if existing:
            total_incidents = sum(record.get("observed_counts", {}).get("incident_count", 0) for record in existing)
            included_count = sum(not record.get("hidden", False) for record in existing)
            summary_col, group_col = st.columns([3, 2])
            summary_col.markdown(f"**Existing loaded data · {total_incidents:,} stored incidents**")
            summary_col.caption(f"{included_count} of {len(existing)} existing sources included. Stored counts include excluded sources; dashboard counts do not.")
            version = sha256(repr(sorted((record["_id"], record.get("hidden", False)) for record in existing)).encode()).hexdigest()[:12]
            any_included = included_count > 0
            group_included = group_col.toggle("Include existing data", value=any_included, key=f"existing_group_{version}")
            if group_included != any_included:
                history.set_existing_included(group_included)
                from ui.filters import filter_catalog
                filter_catalog.clear()
                st.rerun()
            if 0 < included_count < len(existing):
                summary_col.caption("Some sources are excluded individually. Turn the group switch off to exclude all existing sources.")
        search = st.text_input("Find an uploaded CSV", placeholder="Search by filename")
        query = {}
        if search:
            query["filename"] = {"$regex": re.escape(search), "$options": "i"}
        count = history.files.count_documents(query)
        st.caption(f"{count:,} datasets / files · excluded data stays listed here")
        if not count:
            st.info("No datasets or CSVs match this search. Existing sources appear automatically when database data is available.")
            return
        page = st.number_input("Upload history page", min_value=1, max_value=max(1, (count + 9) // 10), value=1, step=1)
        records = list(history.files.find(query).sort("uploaded_at", -1).skip((page - 1) * 10).limit(10))
        for record in records:
            upload_id = record["_id"]
            title_col, action_col = st.columns([5, 1])
            title_col.write(f"**{record['filename']}**")
            excluded = record.get("hidden", False)
            is_existing = record.get("record_kind") == "existing_dataset"
            size = f" · {record['size_bytes'] / 1024:,.1f} KB" if record.get("size_bytes") is not None else ""
            title_col.caption(f"{record.get('dataset_type', 'Unclassified')} · {record['status'].replace('_', ' ').title()}{size} · " + ("Excluded from dashboard" if excluded else "Included in dashboard"))
            included = action_col.toggle("Include in dashboard", value=not excluded, key=f"include_{upload_id}")
            if included == excluded:
                history.set_included(upload_id, included)
                from ui.filters import filter_catalog
                filter_catalog.clear()
                st.rerun()
            with st.expander(f"Details & runs · {record['filename']} · {upload_id[:6]}"):
                if is_existing:
                    st.caption(f"Source: {record['source_dataset']}")
                    st.caption("Existing database data. Original upload time, file fingerprint and import settings were not recorded; no historical import run has been invented.")
                    counts = record.get("observed_counts", {})
                    metrics = st.columns(3)
                    metrics[0].metric("Stored MongoDB events", f"{counts.get('event_count', 0):,}")
                    metrics[1].metric("Stored MongoDB alerts", f"{counts.get('alert_count', 0):,}")
                    metrics[2].metric("Stored MySQL incidents", f"{counts.get('incident_count', 0):,}")
                    st.caption("Counts are observed from the databases, including data currently excluded from dashboard views.")
                    if record.get("related_csv_path"):
                        root = Path(__file__).resolve().parents[1]
                        related = (root / record["related_csv_path"]).resolve()
                        if related.is_relative_to(root) and related.suffix.lower() == ".csv" and related.is_file():
                            st.caption("Related CSV found in project data. Downloading it does not reimport or duplicate stored records.")
                            st.download_button("Download related CSV", related.read_bytes(), related.name, "text/csv", key=f"related_csv_{upload_id}")
                    if excluded:
                        st.info("This source's security data is excluded from dashboard views. Enable its switch to view it again.")
                    continue
                st.caption(f"Uploaded: {record['uploaded_at'].strftime('%d %b %Y, %H:%M:%S')} UTC · SHA-256: {record['content_sha256']}")
                if record.get("validation_error") and record["status"] == "validation_failed":
                    st.warning(record["validation_error"])
                runs = list(history.runs.find({"upload_id": upload_id}).sort("started_at", -1).limit(20))
                if not runs:
                    st.info("No import attempted for this file yet.")
                    continue
                choices = {run["_id"]: run for run in runs}
                selected_id = st.selectbox("Import attempt", list(choices), key=f"run_{upload_id}",
                    format_func=lambda value: f"{choices[value]['started_at'].strftime('%d %b %Y %H:%M:%S')} UTC · {choices[value]['status']} · {value[:6]}")
                run = choices[selected_id]
                summary = run.get("summary")
                if summary:
                    metrics = st.columns(4)
                    metrics[0].metric("Rows processed", summary["authentication_events"] + summary["network_events"])
                    metrics[1].metric("New MongoDB events", summary["mongo_events_inserted"])
                    metrics[2].metric("Alerts detected", summary["generated_alerts"])
                    metrics[3].metric("New MySQL incidents", summary["mysql_incidents_created"])
                    st.caption(f"Duplicate events: {summary['mongo_event_duplicates']:,} · duplicate incidents: {summary['mysql_incident_duplicates']:,}. These counts belong to this attempt.")
                if run.get("error"):
                    st.warning(run["error"])
                if run["status"] == "running":
                    st.warning("This attempt is running or was interrupted. Review its completed stages before retrying.")
                config_tab, stages_tab, evidence_tab = st.tabs(["Configuration", "Recorded progress", "Stored evidence"])
                config_tab.json(run["configuration"])
                stages_tab.json(run.get("stages", {}))
                with evidence_tab:
                    st.caption("Current records for this file's provenance, across all its import attempts. Evidence is read on demand.")
                    if excluded:
                        st.info("This CSV's security data is excluded. Enable Include in dashboard to view it. Import history remains available.")
                    if st.button("Load database evidence", key=f"evidence_{upload_id}_{selected_id}", disabled=excluded):
                        source = record.get("source_dataset")
                        if source:
                            events = list(database.security_events.find({"source_dataset": source},
                                {"_id": 0, "event_id": 1, "timestamp": 1, "event_type": 1, "user_id": 1, "source_ip": 1}).sort("timestamp", -1).limit(10))
                            st.markdown("**MongoDB events**")
                            display_table(events, empty="No events from this file are currently stored.")
                            st.markdown("**MySQL incidents**")
                            display_table(mysql_rows("""SELECT incident_id,incident_time,severity,status,description
                                FROM incidents WHERE source_dataset=%s ORDER BY incident_time DESC LIMIT 10""", (source,)), empty="No incidents from this file are currently stored.")
    except Exception:
        st.warning("Upload history is unavailable. Check MongoDB connectivity before uploading a new CSV.")
