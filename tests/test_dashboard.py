"""Smoke-test dashboard rendering with explicitly empty, isolated database doubles."""

from datetime import date
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from streamlit.testing.v1 import AppTest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("page", [
    "app.py", "pages/1_Threat_Analytics.py", "pages/2_User_Device_Monitoring.py",
    "pages/3_Incident_Management.py", "pages/4_Data_Ingestion.py",
    "pages/5_Project_Evidence.py", "pages/6_Database_Explorer.py",
])
def test_pages_render_with_empty_databases(monkeypatch, page):
    from ui import filters, health, resources

    filters.filter_catalog.clear()
    from ui.existing_sources import existing_source_counts
    existing_source_counts.clear()

    mongo = MagicMock()
    for collection in (mongo.database.security_events, mongo.database.security_alerts, mongo.database.ingestion_uploads):
        collection.estimated_document_count.return_value = 0
        collection.count_documents.return_value = 0
        collection.aggregate.return_value = []
        collection.find.return_value.sort.return_value.limit.return_value = []

    def rows(query, params=()):
        if "SELECT DISTINCT source_dataset" in query:
            return [{"source_dataset": "synthetic_fixture"}]
        if "first_day" in query:
            return [{"first_day": date(2026, 1, 1), "last_day": date(2026, 1, 2)}]
        if "SELECT COUNT(*) total" in query:
            return [{"total": 0, "active_count": 0, "serious_count": 0, "resolved_count": 0, "affected_users": 0}]
        if "SELECT COUNT(*) FROM users" in query:
            return [{"users": 0, "systems": 0, "incidents": 0, "assignments": 0, "audit_entries": 0}]
        return []

    monkeypatch.setattr(resources, "get_mongo", lambda: mongo)
    monkeypatch.setattr(resources, "mysql_rows", rows)
    monkeypatch.setattr(health, "dependency_health", lambda: {
        "checks": {"MySQL": True, "MongoDB": True, "Network model": True},
        "checked_at": "2026-10-24T00:00:00+00:00",
    })
    app = AppTest.from_file(str(ROOT / "app.py")).run(timeout=15)
    if page != "app.py":
        app.switch_page(page).run(timeout=15)
    assert not app.exception
    if page == "app.py":
        app.selectbox[0].select("synthetic_fixture").run(timeout=15)
        app.switch_page("pages/1_Threat_Analytics.py").run(timeout=15)
        assert not app.exception
        assert app.selectbox[0].value == "synthetic_fixture"
    if page == "pages/6_Database_Explorer.py":
        from analytics import custom_queries
        from ui.visibility import DatasetVisibility

        calls = []

        def run_sql(database, text, visibility):
            custom_queries.compile_sql(text, visibility)
            calls.append((text, visibility))
            return custom_queries.QueryResult([{"incident_count": 7}], 0.01, False, "SELECT 7 AS incident_count")

        def run_mongo(database, collection, text, visibility):
            custom_queries.compile_mongo(text, visibility)
            return custom_queries.QueryResult([{"_id": "authentication", "count": 4}], 0.01, False, "[]")

        monkeypatch.setattr(resources, "get_mysql", MagicMock())
        monkeypatch.setattr(custom_queries, "execute_sql", run_sql)
        monkeypatch.setattr(custom_queries, "execute_mongo", run_mongo)
        next(button for button in app.button if button.label == "Run custom SQL").click().run(timeout=15)
        assert not app.exception
        assert calls[0][1] == DatasetVisibility()
        assert any("Returned 1 rows" in element.value for element in app.success)
        app.run(timeout=15)
        assert any("Returned 1 rows" in element.value for element in app.success)
        app.text_area(key="custom_sql_text").set_value("DELETE FROM incidents")
        next(button for button in app.button if button.label == "Run custom SQL").click().run(timeout=15)
        assert not app.exception
        assert any("SELECT" in element.value for element in app.error)
        assert "custom_sql_result" not in app.session_state
        next(button for button in app.button if button.label == "Run custom MongoDB query").click().run(timeout=15)
        assert not app.exception
        assert any("Returned 1 rows" in element.value for element in app.success)


def test_health_reports_failures_without_disclosing_credentials(monkeypatch):
    from ui import health, resources
    from detection import ml_network

    def fail():
        raise RuntimeError("secret connection details")

    monkeypatch.setattr(resources, "get_mysql", fail)
    monkeypatch.setattr(resources, "get_mongo", fail)
    monkeypatch.setattr(ml_network, "load_model_bundle", lambda _: {"model": "fixture"})
    health.dependency_health.clear()
    result = health.dependency_health()
    assert result["checks"] == {"MySQL": False, "MongoDB": False, "Network model": True}
    assert "secret" not in str(result)
    health.dependency_health.clear()


def test_csv_stays_listed_when_excluded_and_can_be_included_again(monkeypatch):
    from datetime import datetime, timezone
    from ui import filters, health, resources

    filters.filter_catalog.clear()
    mongo = MagicMock()
    record = {"_id": "synthetic-library-id", "filename": "synthetic_library_fixture.csv",
              "content_sha256": "a" * 64, "size_bytes": 1024,
              "uploaded_at": datetime(2026, 10, 1, tzinfo=timezone.utc), "hidden": False,
              "status": "completed", "dataset_type": "authentication", "source_dataset": "synthetic_library_fixture"}
    run = {"_id": "synthetic-run", "upload_id": record["_id"], "started_at": record["uploaded_at"],
           "status": "completed", "configuration": {"failed_login_threshold": 5}, "stages": {},
           "summary": {"authentication_events": 12, "network_events": 0, "mongo_events_inserted": 12,
                       "generated_alerts": 2, "mysql_incidents_created": 2, "mongo_event_duplicates": 0,
                       "mysql_incident_duplicates": 0}}
    files = mongo.database.ingestion_uploads

    def file_count(query):
        return 0 if record["hidden"] and "hidden" in query else 1

    def find_files(query, projection=None):
        cursor = MagicMock()
        cursor.__iter__.return_value = iter([record] if query.get("hidden") is True and record["hidden"] else [])
        cursor.sort.return_value.skip.return_value.limit.return_value = [record] if file_count(query) else []
        return cursor

    def update_visibility(query, update):
        record.update(update["$set"])
        return MagicMock(matched_count=1)

    files.count_documents.side_effect = file_count
    files.find.side_effect = find_files
    files.update_one.side_effect = update_visibility
    mongo.database.ingestion_runs.find.return_value.sort.return_value.limit.return_value = [run]
    mongo.database.security_events.count_documents.return_value = 0
    mongo.database.security_alerts.count_documents.return_value = 0
    mongo.database.security_events.aggregate.return_value = []
    monkeypatch.setattr(resources, "get_mongo", lambda: mongo)
    monkeypatch.setattr(resources, "mysql_rows", lambda query, params=(): [{"first_day": date(2026, 1, 1), "last_day": date(2026, 1, 2)}] if "first_day" in query else [{"total": 0, "active_count": 0, "serious_count": 0, "resolved_count": 0, "affected_users": 0}] if "SELECT COUNT(*) total" in query else [])
    monkeypatch.setattr(health, "dependency_health", lambda: {"checks": {"MySQL": True, "MongoDB": True}, "checked_at": "2026-10-24T00:00:00+00:00"})
    app = AppTest.from_file(str(ROOT / "app.py")).run(timeout=15)
    app.switch_page("pages/4_Data_Ingestion.py").run(timeout=15)
    assert not app.exception
    assert any("synthetic_library_fixture.csv" in element.value for element in app.markdown)
    app.toggle(key="include_synthetic-library-id").set_value(False).run(timeout=15)
    assert not app.exception
    assert record["hidden"] is True
    assert any("synthetic_library_fixture.csv" in element.value for element in app.markdown)
    assert app.button(key="evidence_synthetic-library-id_synthetic-run").disabled
    app.switch_page("app.py").run(timeout=15)
    assert not app.exception
    assert any("dataset source(s) excluded" in element.value for element in app.caption)
    app.switch_page("pages/6_Database_Explorer.py").run(timeout=15)
    assert not app.exception
    assert next(button for button in app.button if button.label == "Run user security summary").disabled
    app.switch_page("pages/4_Data_Ingestion.py").run(timeout=15)
    app.toggle(key="include_synthetic-library-id").set_value(True).run(timeout=15)
    assert record["hidden"] is False
    assert not app.exception
