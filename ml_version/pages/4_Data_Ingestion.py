from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from detection.ml_network import DEFAULT_MODEL_PATH, load_model_bundle
from etl.authentication_loader import load_authentication_csv
from etl.network_loader import load_network_csv
from etl.pipeline import process_events, run_pipeline
from etl.schema_detection import detect_dataset_type, safe_source_name
from etl.models import DatasetValidationError
from ui.resources import get_mongo, get_mysql, mysql_rows
from ui.theme import configure_page

configure_page("Data Ingestion & Detection Configuration", "📥")

st.markdown(
    """
    <div class="pipeline-flow">
      <div class="pipeline-step done"><strong>1 · CSV</strong><span>Upload and identify the supported schema</span></div>
      <div class="pipeline-step done"><strong>2 · Validate</strong><span>Check columns, IDs, timestamps and duplicates</span></div>
      <div class="pipeline-step done"><strong>3 · MongoDB</strong><span>Save normalized events in security_events</span></div>
      <div class="pipeline-step done"><strong>4 · Detect</strong><span>Run authentication rules or the trained network model</span></div>
      <div class="pipeline-step done"><strong>5 · MySQL</strong><span>Create deduplicated incidents and audit records</span></div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.write(
    "Run the inspected quickstart datasets through validation, MongoDB storage, "
    "rule/model detection, and MySQL incident creation. The operation is idempotent."
)

root = Path(__file__).resolve().parents[1]
with st.expander("Run bundled quickstart datasets", expanded=False):
    st.caption("Useful for resetting a classroom demonstration. Re-runs are duplicate-safe.")
    quickstart = st.button("Run quickstart ingestion", type="secondary")

if quickstart:
    with st.spinner("Validating, importing, detecting, and creating incidents..."):
        try:
            summary = run_pipeline(
                root / "data/raw/rba_authentication_events_quickstart.csv",
                root / "data/raw/unsw_nb15_network_events_quickstart.csv",
                mysql=get_mysql(),
                mongo=get_mongo(),
            )
            st.success("Pipeline completed successfully.")
            st.json(summary.to_dict())
        except Exception as error:
            st.error(f"Pipeline failed: {error}")

st.divider()
st.subheader("CSV upload")
st.write(
    "Upload an authentication or network CSV matching the inspected schemas. "
    "The file is validated in memory and is not saved to disk. Maximum size: 25 MB."
)

uploaded = st.file_uploader("Choose a CSV file", type=["csv"], accept_multiple_files=False)

if uploaded is not None:
    if uploaded.size > 25 * 1024 * 1024:
        st.error("The selected file is larger than 25 MB.")
        st.stop()
    try:
        columns = list(pd.read_csv(uploaded, nrows=0).columns)
        uploaded.seek(0)
        dataset_type = detect_dataset_type(columns)
        preview = pd.read_csv(uploaded, nrows=10)
        uploaded.seek(0)
    except Exception as error:
        st.error(f"CSV validation failed: {error}")
        st.stop()

    st.success(f"Detected supported {dataset_type} schema with {len(columns)} columns.")
    with st.expander("Preview first 10 rows", expanded=True):
        st.dataframe(preview, width="stretch", hide_index=True)

    source_name = safe_source_name(uploaded.name, dataset_type)
    st.caption(f"Provenance label: `{source_name}`")

    with st.form("upload_detection_configuration"):
        st.markdown("#### Detection configuration")
        if dataset_type == "authentication":
            first, second = st.columns(2)
            failed_threshold = first.number_input("Failed-login threshold", 2, 20, 5)
            failed_window = second.number_input("Failed-login window (minutes)", 1, 60, 5)
            third, fourth = st.columns(2)
            origin_threshold = third.number_input("Distinct IP/device threshold", 2, 10, 3)
            access_window = fourth.number_input("Suspicious-access window (minutes)", 1, 120, 10)
            network_probability_threshold = None
        else:
            model_bundle = load_model_bundle(str(DEFAULT_MODEL_PATH.resolve()))
            calibrated_threshold = float(model_bundle["threshold"])
            network_probability_threshold = st.number_input(
                "Model attack-probability threshold",
                min_value=0.01,
                max_value=0.99,
                value=calibrated_threshold,
                step=0.01,
                format="%.2f",
                help=(
                    "Lower values detect more attacks but may create more false positives. "
                    "The default was selected on the validation split."
                ),
            )
            st.caption(
                f"Model: {model_bundle['model_version']} · "
                f"calibrated threshold: {calibrated_threshold:.2f}"
            )
            failed_threshold = 5
            failed_window = 5
            origin_threshold = 3
            access_window = 10

        acknowledge = st.checkbox(
            "I understand source labels are stored for evaluation and do not automatically create alerts."
        )
        submit = st.form_submit_button(
            "Validate, import & detect",
            type="primary",
            help="Confirm the checkbox above, then start the database import and detection pipeline.",
        )

    if submit:
        if not acknowledge:
            st.warning(
                "Please confirm the source-label statement before running the import."
            )
            st.stop()
        with st.status("Processing uploaded security events...", expanded=True) as status:
            try:
                status.write("1/6 — Schema identified and upload size accepted")
                uploaded.seek(0)
                if dataset_type == "authentication":
                    loaded = load_authentication_csv(uploaded, source_dataset=source_name)
                    status.write(
                        f"2/6 — Validated and normalized {loaded.report.row_count:,} authentication events"
                    )
                    def show_progress(stage: str, details: dict) -> None:
                        messages = {
                            "mongo_indexes_ready": "3/6 — MongoDB indexes verified",
                            "events_stored": (
                                f"3/6 — MongoDB security_events: {details.get('inserted', 0):,} new, "
                                f"{details.get('duplicates', 0):,} duplicates"
                            ),
                            "detections_complete": (
                                f"4/6 — Python detection generated {details.get('alerts', 0):,} alerts"
                            ),
                            "alerts_stored": (
                                f"5/6 — MongoDB security_alerts: {details.get('inserted', 0):,} new, "
                                f"{details.get('duplicates', 0):,} duplicates"
                            ),
                            "incidents_stored": (
                                f"6/6 — MySQL incidents: {details.get('created', 0):,} new, "
                                f"{details.get('duplicates', 0):,} duplicates"
                            ),
                        }
                        if stage in messages:
                            status.write(messages[stage])
                    summary = process_events(
                        authentication_events=loaded.events,
                        mysql=get_mysql(), mongo=get_mongo(),
                        failed_login_threshold=int(failed_threshold),
                        failed_login_window_minutes=int(failed_window),
                        suspicious_origin_threshold=int(origin_threshold),
                        suspicious_window_minutes=int(access_window),
                        progress=show_progress,
                    )
                else:
                    loaded = load_network_csv(uploaded, source_dataset=source_name)
                    status.write(
                        f"2/6 — Validated and normalized {loaded.report.row_count:,} network events"
                    )
                    def show_progress(stage: str, details: dict) -> None:
                        messages = {
                            "mongo_indexes_ready": "3/6 — MongoDB indexes verified",
                            "events_stored": (
                                f"3/6 — MongoDB security_events: {details.get('inserted', 0):,} new, "
                                f"{details.get('duplicates', 0):,} duplicates"
                            ),
                            "detections_complete": (
                                f"4/6 — Python detection generated {details.get('alerts', 0):,} alerts"
                            ),
                            "alerts_stored": (
                                f"5/6 — MongoDB security_alerts: {details.get('inserted', 0):,} new, "
                                f"{details.get('duplicates', 0):,} duplicates"
                            ),
                            "incidents_stored": (
                                f"6/6 — MySQL incidents: {details.get('created', 0):,} new, "
                                f"{details.get('duplicates', 0):,} duplicates"
                            ),
                        }
                        if stage in messages:
                            status.write(messages[stage])
                    summary = process_events(
                        network_events=loaded.events,
                        mysql=get_mysql(), mongo=get_mongo(),
                        network_probability_threshold=float(network_probability_threshold),
                        progress=show_progress,
                    )
                status.update(label="Upload stored and analysed successfully", state="complete")
                result = summary.to_dict()
                st.markdown('<div class="storage-proof">Database persistence proof</div>', unsafe_allow_html=True)
                mongo_database = get_mongo().database
                mongo_event_count = mongo_database.security_events.count_documents(
                    {"source_dataset": source_name}
                )
                mongo_alert_count = mongo_database.security_alerts.count_documents(
                    {"source_dataset": source_name}
                )
                sql_count_rows = mysql_rows(
                    "SELECT COUNT(*) AS count FROM incidents WHERE source_dataset = %s",
                    (source_name,),
                )
                sql_incident_count = int(sql_count_rows[0]["count"])
                metric_columns = st.columns(4)
                metric_columns[0].metric("Rows accepted", loaded.report.row_count)
                metric_columns[1].metric("MongoDB events saved", mongo_event_count)
                metric_columns[2].metric("MongoDB alerts saved", mongo_alert_count)
                metric_columns[3].metric("MySQL incidents saved", sql_incident_count)
                if result["mongo_event_duplicates"]:
                    st.info(
                        f"Skipped {result['mongo_event_duplicates']} duplicate events and "
                        f"{result['mysql_incident_duplicates']} duplicate incidents."
                    )
                mongo_tab, sql_tab, summary_tab = st.tabs(
                    ["MongoDB evidence", "MySQL evidence", "Technical summary"]
                )
                mongo_samples = list(
                    mongo_database.security_events.find(
                        {"source_dataset": source_name},
                        {
                            "_id": 0, "event_id": 1, "timestamp": 1,
                            "event_type": 1, "user_id": 1, "source_ip": 1,
                            "destination_ip": 1, "authentication_result": 1,
                            "attack_category": 1,
                        },
                    ).sort("timestamp", -1).limit(10)
                )
                mongo_tab.caption(
                    "Latest documents read back from MongoDB collection `security_events`."
                )
                mongo_tab.dataframe(mongo_samples, width="stretch", hide_index=True)

                sql_samples = mysql_rows(
                    """
                    SELECT i.incident_id, i.incident_time, tc.category_name,
                           i.severity, i.status, i.source_event_id
                    FROM incidents i
                    JOIN threat_categories tc ON tc.category_id = i.category_id
                    WHERE i.source_dataset = %s
                    ORDER BY i.incident_time DESC LIMIT 10
                    """,
                    (source_name,),
                )
                sql_tab.caption(
                    "Latest rows read back from MySQL table `incidents` for this upload."
                )
                if sql_samples:
                    sql_tab.dataframe(sql_samples, width="stretch", hide_index=True)
                else:
                    sql_tab.info(
                        "No MySQL incident was created because no detection rule triggered. "
                        "The raw events are still stored in MongoDB."
                    )

                with summary_tab:
                    st.json(result)
            except DatasetValidationError as error:
                status.update(label="Dataset validation failed", state="error")
                st.error(f"Dataset validation failed: {error}")
            except Exception as error:
                status.update(label="Import failed safely", state="error")
                st.error(f"Import failed safely: {error}")
