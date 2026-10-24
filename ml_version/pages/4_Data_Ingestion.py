from __future__ import annotations

from pathlib import Path
from hashlib import sha256
from uuid import uuid4

import pandas as pd
import streamlit as st

from detection.ml_network import DEFAULT_MODEL_PATH, load_model_bundle
from etl.authentication_loader import load_authentication_csv
from etl.demo_data import authentication_demo_csv
from etl.upload_history import UploadHistory, namespace_upload_events
from etl.network_loader import load_network_csv
from etl.pipeline import process_events, run_pipeline
from etl.schema_detection import detect_dataset_type, safe_source_name
from etl.models import DatasetValidationError
from ui.resources import get_mongo, get_mysql
from ui.theme import configure_page
from ui.upload_history import render_upload_history

configure_page("Data Ingestion & Detection Configuration", "📥")

if notice := st.session_state.pop("last_import_notice", None):
    st.success(notice)
render_upload_history()
st.divider()

with st.expander("Guided synthetic demonstration", expanded=False):
    st.write("Create a small synthetic CSV and follow the complete import-to-response workflow.")
    st.markdown("""
    1. Download the synthetic CSV below and upload it using the uploader on this page.
    2. Keep defaults: 5 failed logins / 5 minutes and 3 access origins / 10 minutes.
    3. Validate, import and detect. On the first import, expect 12 events, 2 alerts and 2 incidents.
    4. Check the MongoDB and MySQL evidence tabs after import.
    5. In Incident Response, select this upload's dataset, assign a case, record a response, then resolve it.
    6. Return to Command Center to see resolution and analyst workload change. Reimporting the same file should create no duplicates.
    """)
    if "guided_demo_csv" not in st.session_state or st.button("Generate a fresh synthetic demo"):
        run_id = uuid4().hex[:12]
        st.session_state["guided_demo_csv"] = authentication_demo_csv(run_id)
        st.session_state["guided_demo_filename"] = f"synthetic_soc_demo_{run_id}.csv"
    st.download_button("Download synthetic demo CSV", st.session_state["guided_demo_csv"],
                       st.session_state["guided_demo_filename"], "text/csv", type="primary")
    st.caption("Synthetic users and documentation-only IP addresses. The control user has four failures and should generate no alert at the defaults.")

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
            from ui.existing_sources import existing_source_counts
            existing_source_counts.clear()
        except Exception as error:
            st.error(f"Pipeline failed: {error}")

st.divider()
st.subheader("CSV upload")
st.write(
    "Upload an authentication or network CSV matching the inspected schemas. "
    "The file is validated in memory and is not saved to disk. Maximum size: 25 MB."
)

uploaded = st.file_uploader("Choose a CSV file", type=["csv"], accept_multiple_files=False,
    key=f"csv_upload_{st.session_state.get('csv_upload_version', 0)}")

if uploaded is not None:
    try:
        history = UploadHistory(get_mongo().database)
        upload_record = history.register(uploaded.name, sha256(uploaded.getbuffer()).hexdigest(), uploaded.size)
        upload_id = upload_record["_id"]
        st.session_state["active_upload_id"] = upload_id
        if upload_record.get("hidden", False):
            st.info("This CSV is excluded from the dashboard. Enable Include in dashboard in the library to preview or import it again.")
            st.stop()
    except Exception:
        st.error("Could not register this CSV in upload history. Check MongoDB, then try again.")
        st.stop()
    if uploaded.size > 25 * 1024 * 1024:
        history.validation_failed(upload_id, "File exceeds the 25 MB upload limit.")
        st.error("The selected file is larger than 25 MB.")
        st.stop()
    try:
        columns = list(pd.read_csv(uploaded, nrows=0).columns)
        uploaded.seek(0)
        dataset_type = detect_dataset_type(columns)
        preview = pd.read_csv(uploaded, nrows=10)
        uploaded.seek(0)
    except Exception as error:
        history.validation_failed(upload_id, str(error))
        st.error(f"CSV validation failed: {error}")
        st.stop()

    st.success(f"Detected supported {dataset_type} schema with {len(columns)} columns.")
    with st.expander("Preview first 10 rows", expanded=True):
        st.dataframe(preview, width="stretch", hide_index=True)

    # Different content under the same filename receives separate provenance.
    # Identical reimports keep stable provenance and duplicate protection.
    source_name = safe_source_name(uploaded.name, dataset_type)[:80] + ":" + upload_id[:16]
    history.validated(upload_id, dataset_type, source_name, columns)
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
            run_id = None
            try:
                run_id = history.start_run(upload_id, {
                    "failed_login_threshold": int(failed_threshold),
                    "failed_login_window_minutes": int(failed_window),
                    "suspicious_origin_threshold": int(origin_threshold),
                    "suspicious_window_minutes": int(access_window),
                    "network_probability_threshold": network_probability_threshold,
                })
                status.write("1/6 — Schema identified and upload size accepted")
                uploaded.seek(0)
                if dataset_type == "authentication":
                    loaded = load_authentication_csv(uploaded, source_dataset=source_name)
                    namespace_upload_events(loaded.events, upload_id)
                    status.write(
                        f"2/6 — Validated and normalized {loaded.report.row_count:,} authentication events"
                    )
                    def show_progress(stage: str, details: dict) -> None:
                        history.progress(run_id, stage, details)
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
                    namespace_upload_events(loaded.events, upload_id)
                    status.write(
                        f"2/6 — Validated and normalized {loaded.report.row_count:,} network events"
                    )
                    def show_progress(stage: str, details: dict) -> None:
                        history.progress(run_id, stage, details)
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
                from ui.filters import filter_catalog
                from ui.existing_sources import existing_source_counts
                existing_source_counts.clear()
                filter_catalog.clear()
                result = summary.to_dict()
                history.finish(upload_id, run_id, summary=result)
                st.session_state["last_import_notice"] = f"{uploaded.name}: import completed. Its results are saved in Uploaded CSV library."
                st.session_state["csv_upload_version"] = st.session_state.get("csv_upload_version", 0) + 1
                st.session_state.pop("active_upload_id", None)
                st.rerun()
            except DatasetValidationError as error:
                if run_id:
                    history.finish(upload_id, run_id, error=str(error))
                status.update(label="Dataset validation failed", state="error")
                st.error(f"Dataset validation failed: {error}")
            except Exception as error:
                if run_id:
                    try:
                        history.finish(upload_id, run_id, error=f"{type(error).__name__}: import did not finish. Review the recorded stages; earlier database writes may have completed.")
                    except Exception:
                        pass
                status.update(label="Import failed safely", state="error")
                st.error(f"Import failed safely: {error}")
