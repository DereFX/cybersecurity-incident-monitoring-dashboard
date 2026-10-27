"""Presentation-ready rubric and project evidence page."""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from detection.ml_network import DEFAULT_MODEL_PATH, load_model_bundle
from ui.resources import get_mongo, mysql_rows
from ui.theme import configure_page, section_header
from ui.visibility import dashboard_visibility


configure_page("Rubric & Project Evidence", "🎓")

section_header(
    "Evaluation evidence center",
    "A transparent map from the marking rubric and project requirements to working application evidence.",
    "Assessment readiness",
)
st.info(
    "This page organises evidence for the evaluator. It does not self-award marks; "
    "the final score remains the evaluator's decision."
)

rubric = [
    ("Application Design & Functionality", "2 marks", "Five connected workflows: ingestion, monitoring, analytics, incident response and evidence. Modular services keep UI, ETL, detection and persistence separate."),
    ("Python Programming Implementation", "2 marks", "Typed functions and classes, file handling, validation, structured detection modules, exception handling and reusable services."),
    ("SQL & NoSQL Integration", "2 marks", "MySQL stores normalised entities, incidents, assignments and audit history. MongoDB stores raw/normalised events and generated alerts."),
    ("Advanced Database Querying", "2 marks", "Joins, nested queries, HAVING, grouping, response-time analysis, stored procedures and six MongoDB aggregation pipelines."),
    ("Code Quality, Documentation & UI", "1 mark", "Modular packages, environment-based secrets, setup documentation and a responsive multi-page Streamlit interface."),
    ("Testing, Validation & Error Handling", "1 mark", "Unit and integration test separation, malformed-input checks, idempotency, duplicate prevention and database-failure handling."),
]
for row in range(0, len(rubric), 3):
    columns = st.columns(3)
    for column, (name, score, evidence) in zip(columns, rubric[row:row + 3], strict=True):
        column.markdown(
            f'<div class="rubric-card"><span class="rubric-score">{score}</span>'
            f'<div class="rubric-name">{name}</div><div class="rubric-evidence">{evidence}</div></div>',
            unsafe_allow_html=True,
        )

st.divider()
section_header("Live implementation proof", "Counts are read from the databases now—not hard-coded presentation numbers.", "Database integration")
try:
    visibility = dashboard_visibility()
    count_query, count_params = visibility.report_sql(
        """SELECT
        (SELECT COUNT(*) FROM users) users,
        (SELECT COUNT(*) FROM systems) systems,
        (SELECT COUNT(*) FROM incidents) incidents,
        (SELECT COUNT(*) FROM assignments) assignments,
        (SELECT COUNT(*) FROM incident_audit_log) audit_entries"""
    )
    sql_counts = mysql_rows(count_query, count_params)[0]
    mongo = get_mongo().database
    mongo_events = mongo.security_events.count_documents(visibility.mongo())
    mongo_alerts = mongo.security_alerts.count_documents(visibility.mongo())
    st.caption("Live counts include only datasets enabled on Data Pipeline. Saved model/test evaluation is independent of these filters.")
    model = load_model_bundle(str(DEFAULT_MODEL_PATH.resolve()))
    model_metrics = model["metadata"]["test_metrics"]
    proof = [
        ("MySQL entities", f"{int(sql_counts['users'] or 0) + int(sql_counts['systems'] or 0):,}", "Users + systems"),
        ("MySQL incidents", f"{int(sql_counts['incidents'] or 0):,}", "Deduplicated cases"),
        ("Response records", f"{int(sql_counts['assignments'] or 0):,}", "Analyst assignments"),
        ("Audit entries", f"{int(sql_counts['audit_entries'] or 0):,}", "Persistent case history"),
        ("MongoDB events", f"{mongo_events:,}", "Raw + normalised evidence"),
        ("MongoDB alerts", f"{mongo_alerts:,}", "Detection results"),
        ("Model recall", f"{model_metrics['recall']:.1%}", "Held-out evaluation"),
        ("Model precision", f"{model_metrics['precision']:.1%}", "Held-out evaluation"),
    ]
    st.markdown(
        '<div class="status-grid">' + ''.join(
            f'<div class="status-item"><div class="status-label">{label}</div>'
            f'<div class="status-value">{value}</div><div class="status-detail">{detail}</div></div>'
            for label, value, detail in proof
        ) + '</div>',
        unsafe_allow_html=True,
    )
except Exception as error:
    st.warning(f"Live evidence is temporarily unavailable: {error}")

st.divider()
section_header("Functional requirement traceability", "Every requested capability has a visible implementation route.", "10 / 10 requirements mapped")
requirements = [
    ("Import and validate datasets", "Data Pipeline page: CSV schema detection, preview, validation and useful errors."),
    ("Normalise formats and timestamps", "Authentication and network ETL loaders create a shared NormalizedEvent format."),
    ("Load structured entities into MySQL", "Users, systems, categories, analysts, incidents, assignments and audit history."),
    ("Load events into MongoDB", "Batch, indexed, idempotent security_events and security_alerts collections."),
    ("Detect suspicious behaviour", "Failed-login and suspicious-access rules plus the trained network classifier."),
    ("Generate alerts and incidents", "Standardised alerts persist to MongoDB and create linked MySQL cases."),
    ("Prevent duplicate incidents", "Stable event IDs and unique detection keys make safe re-runs visible in ingestion summaries."),
    ("Support analyst response", "Assign, investigate, document, change status and resolve from Incident Response."),
    ("Present monitoring and analytics", "Command Center, Threat Analytics and Identity Monitoring provide interactive views."),
    ("Provide advanced queries", "Ten reusable SQL analyses, two stored procedures and six MongoDB aggregations."),
]
for number, (title, detail) in enumerate(requirements, 1):
    st.markdown(
        f'<div class="requirement-row"><div class="requirement-check">✓</div><div>'
        f'<div class="requirement-title">{number}. {title}</div>'
        f'<div class="requirement-detail">{detail}</div></div></div>',
        unsafe_allow_html=True,
    )

route_columns = st.columns(3)
route_columns[0].page_link("pages/4_Data_Ingestion.py", label="Demonstrate requirements 1–7", icon="📥")
route_columns[1].page_link("pages/3_Incident_Management.py", label="Demonstrate analyst response", icon="🚨")
route_columns[2].page_link("pages/6_Database_Explorer.py", label="Demonstrate advanced querying", icon="🗄️")

st.divider()
section_header("Technical evidence", "Use these tabs during the viva to explain how the system satisfies each technical area.", "Under the hood")
tab_flow, tab_queries, tab_testing, tab_sdg = st.tabs(["End-to-end flow", "Advanced queries", "Testing & safeguards", "SDG alignment"])
with tab_flow:
    st.markdown(
        """<div class="pipeline-flow">
        <div class="pipeline-step done"><strong>1 · CSV</strong><span>Authentication or network security data with source provenance.</span></div>
        <div class="pipeline-step done"><strong>2 · Validate</strong><span>Required columns, IDs, timestamps, empty data and field types.</span></div>
        <div class="pipeline-step done"><strong>3 · MongoDB</strong><span>Idempotent event storage and indexed alert evidence.</span></div>
        <div class="pipeline-step done"><strong>4 · Detect</strong><span>Explainable auth rules plus a versioned network model.</span></div>
        <div class="pipeline-step done"><strong>5 · MySQL</strong><span>Deduplicated incident, assignment and auditable response.</span></div>
        </div>""",
        unsafe_allow_html=True,
    )
    st.success("Demo route: Data Pipeline → Threat Analytics → Incident Response → Command Center")
with tab_queries:
    left, right = st.columns(2)
    with left:
        st.markdown("#### MySQL evidence")
        st.markdown("""
        - Incident joins across categories, users and systems
        - Category and severity grouping
        - Average incident response time
        - Incidents per user and per system
        - Analyst workload and unresolved critical cases
        - Above-average nested user query
        - Daily trends and source-dataset summaries
        - `sp_user_security_summary` and transactional `sp_resolve_incident`
        """)
    with right:
        st.markdown("#### MongoDB evidence")
        st.markdown("""
        - Events by observed category
        - Hourly and daily event trends
        - Top source IP addresses
        - Failed logins by user
        - High-severity alerts by detection rule
        - Indexed pagination and idempotent batch imports
        """)
with tab_testing:
    report_path = Path(__file__).resolve().parents[1] / "reports/verification.json"
    if report_path.exists():
        from scripts.verify_project import source_fingerprint

        report = json.loads(report_path.read_text(encoding="utf-8"))
        counts = report["counts"]
        passed = counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"]
        st.metric("Last saved unit test result", f"{passed} / {counts['tests']} passed")
        st.caption(f"Verified: {report['checked_at_utc']} · {report['scope']}")
        if report["source_sha256"] != source_fingerprint():
            st.warning("Source files have changed since this report. Run python scripts/verify_project.py to refresh it.")
        if report["exit_code"]:
            st.error("The saved verification run contains failures or errors.")
        st.download_button("Download test report", report_path.read_text(encoding="utf-8"), "verification.json", "application/json")
    else:
        st.info("No saved test report. Run python scripts/verify_project.py from the project folder.")
    integration_report = Path(__file__).resolve().parents[1] / "reports/response_integration.json"
    if integration_report.exists():
        from scripts.verify_project import source_fingerprint

        live = json.loads(integration_report.read_text(encoding="utf-8"))
        live_counts = live["counts"]
        live_passed = live_counts["tests"] - live_counts["failures"] - live_counts["errors"] - live_counts["skipped"]
        st.metric("Live response workflow checks", f"{live_passed} / {live_counts['tests']} passed")
        st.caption(f"Verified: {live['checked_at_utc']} · {live['scope']}")
        if live["source_sha256"] != source_fingerprint():
            st.warning("Integration evidence predates code changes. Refresh with python scripts/verify_project.py --integration.")
        st.download_button("Download integration evidence", integration_report.read_text(encoding="utf-8"), "response_integration.json", "application/json")
    st.markdown("""
    Covered scenarios include the exact five-failure boundary, four failures, outside-window events,
    multiple-IP access, malformed timestamps, missing optional fields, duplicate imports and incidents,
    invalid analyst/status values, connection failures, empty datasets, assignment/resolution and model inference.

    Integration tests are deliberately separate because they require running MySQL and MongoDB services.
    Credentials are loaded from `.env`; database passwords are never hard-coded in source control.
    """)
with tab_sdg:
    sdg_a, sdg_b = st.columns(2)
    sdg_a.markdown("""<div class="rubric-card"><div class="rubric-name">SDG 9 · Industry, Innovation & Infrastructure</div>
    <div class="rubric-evidence">Strengthens resilient digital infrastructure through automated event processing, data engineering, threat analytics and measurable detection performance.</div></div>""", unsafe_allow_html=True)
    sdg_b.markdown("""<div class="rubric-card"><div class="rubric-name">SDG 16 · Peace, Justice & Strong Institutions</div>
    <div class="rubric-evidence">Supports accountable institutions with auditable incident histories, traceable analyst actions, evidence preservation and transparent response workflows.</div></div>""", unsafe_allow_html=True)

st.caption("Dataset provenance is preserved. Authentication and network sources are not correlated unless an explicit mapping exists; synthetic demonstrations remain clearly labelled.")
