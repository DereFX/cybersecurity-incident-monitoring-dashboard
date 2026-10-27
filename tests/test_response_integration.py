"""Opt-in live workflow test with synthetic documents and rolled-back SQL rows."""

from contextlib import contextmanager
from datetime import datetime, timezone
from io import BytesIO
from hashlib import sha256
import os
from uuid import uuid4

import pytest
import pandas as pd

from config.settings import Settings
from database.mongo_connection import MongoDatabase
from database.mysql_connection import MySQLDatabase
from etl.authentication_loader import load_authentication_csv
from etl.authentication_loader import load_authentication_frame
from etl.tabular_reader import read_security_table
from etl.demo_data import authentication_demo_csv
from etl.pipeline import process_events
from etl.upload_history import UploadHistory, namespace_upload_events
from incidents.assignment_service import AssignmentService
from analytics.sql_queries import AVERAGE_RESPONSE_TIME, ANALYST_WORKLOAD
from analytics import sql_queries
from ui.visibility import dashboard_visibility
from ui.filters import AnalyticsScope


@pytest.mark.integration
@pytest.mark.skipif(os.getenv("SOC_RUN_INTEGRATION") != "1", reason="Set SOC_RUN_INTEGRATION=1 for live database verification")
def test_custom_readonly_queries_and_dataset_visibility():
    from analytics.custom_queries import execute_sql, execute_mongo
    from ui.visibility import DatasetVisibility

    settings = Settings.from_env()
    mysql = MySQLDatabase(settings, pool_size=1)
    mongo = MongoDatabase(settings)
    all_data = DatasetVisibility()
    total = execute_sql(mysql, "SELECT COUNT(*) AS n FROM incidents", all_data).rows[0]["n"]
    sources = execute_sql(mysql, "SELECT source_dataset FROM incidents GROUP BY source_dataset", all_data).rows
    excluded = DatasetVisibility(tuple(row["source_dataset"] for row in sources))
    for query in (
        "SELECT COUNT(*) AS n FROM incidents",
        "WITH x AS (SELECT * FROM incidents) SELECT COUNT(*) AS n FROM x",
        "SELECT COUNT(*) AS n FROM incidents i, users u WHERE i.user_id=u.user_id",
        "SELECT COUNT(*) AS n FROM assignments",
        "SELECT COUNT(*) AS n FROM incident_audit_log",
    ):
        assert execute_sql(mysql, query, excluded).rows == [{"n": 0}]
    assert execute_sql(mysql, "SELECT COUNT(*) AS n FROM incidents", all_data).rows[0]["n"] == total
    event_total = mongo.database.security_events.count_documents({})
    mongo_result = execute_mongo(mongo.database, "security_events", '[{"$count":"n"}]', all_data)
    assert mongo_result.rows == ([{"n": event_total}] if event_total else [])
    source_names = mongo.database.security_events.distinct("source_dataset")
    result = execute_mongo(mongo.database, "security_events", '[{"$facet":{"counts":[{"$count":"n"}]}}]',
                           DatasetVisibility(tuple(source_names)))
    assert result.rows == [{"counts": []}]


@pytest.mark.integration
@pytest.mark.skipif(os.getenv("SOC_RUN_INTEGRATION") != "1", reason="Set SOC_RUN_INTEGRATION=1 for live database verification")
@pytest.mark.parametrize("file_format", ["csv", "xlsx"])
def test_import_assign_respond_resolve_and_analytics(monkeypatch, file_format):
    settings = Settings.from_env()
    mysql = MySQLDatabase(settings, pool_size=1)
    mongo = MongoDatabase(settings)
    run_id = uuid4().hex
    source = f"synthetic_integration_{run_id}"
    content = authentication_demo_csv(run_id, datetime.now(timezone.utc))
    sheet_name = None
    if file_format == "xlsx":
        sheet_name = "Synthetic events"
        workbook = BytesIO()
        pd.read_csv(BytesIO(content)).to_excel(workbook, index=False, sheet_name=sheet_name, engine="openpyxl")
        content = workbook.getvalue()
        frame = read_security_table(BytesIO(content), filename="fixture.xlsx", sheet_name=sheet_name)
        events = load_authentication_frame(frame, source_dataset=source).events
    else:
        events = load_authentication_csv(BytesIO(content), source_dataset=source).events
    library = UploadHistory(mongo.database)
    upload = library.register(f"synthetic_integration_{run_id}.{file_format}", sha256(content).hexdigest(), len(content), sheet_name=sheet_name)
    upload_id = upload["_id"]
    namespace_upload_events(events, upload_id)

    with mysql.connection() as connection:
        connection.start_transaction()

        class RollbackDatabase:
            @contextmanager
            def transaction(self):
                yield connection

        try:
            library.validated(upload_id, "authentication", source, list(events[0].raw_event))
            attempt = library.start_run(upload_id, {"failed_login_threshold": 5})
            result = process_events(authentication_events=events, mysql=RollbackDatabase(), mongo=mongo,
                                    progress=lambda stage, details: library.progress(attempt, stage, details))
            library.finish(upload_id, attempt, summary=result.to_dict())
            assert result.mongo_events_inserted == 12
            assert result.mongo_alerts_inserted == result.mysql_incidents_created == 2
            restarted_library = UploadHistory(mongo.database)
            assert restarted_library.files.find_one({"_id": upload_id})["status"] == "completed"
            assert restarted_library.runs.find_one({"_id": attempt})["summary"]["mongo_events_inserted"] == 12
            restarted_library.set_hidden(upload_id, True)
            assert restarted_library.files.find_one({"_id": upload_id}) is not None
            assert mongo.database.security_events.count_documents({"source_dataset": source}) == 12
            assert mongo.database.security_alerts.count_documents({"source_dataset": source}) == 2
            from ui import resources
            monkeypatch.setattr(resources, "get_mongo", lambda: mongo)
            visibility = dashboard_visibility()
            assert source in visibility.excluded
            excluded_scope = AnalyticsScope(dataset=source, excluded=visibility.excluded)
            assert mongo.database.security_events.count_documents(excluded_scope.mongo()) == 0
            assert mongo.database.security_alerts.count_documents(excluded_scope.mongo()) == 0
            check_cursor = connection.cursor(dictionary=True)
            clause, values = excluded_scope.sql()
            check_cursor.execute(f"SELECT COUNT(*) count FROM incidents i WHERE {clause}", values)
            assert check_cursor.fetchone()["count"] == 0
            for name in vars(sql_queries):
                if name.isupper():
                    query, values = visibility.report_sql(getattr(sql_queries, name), (1,) if name == "INCIDENT_COUNTS_BY_CATEGORY_SEVERITY" else ())
                    check_cursor.execute(query.strip() + " LIMIT 500", values)
                    rows = check_cursor.fetchall()
                    if name == "SOURCE_DATASET_SUMMARY":
                        assert all(row["source_dataset"] != source for row in rows)
            restarted_library.set_included(upload_id, True)
            assert restarted_library.files.find_one({"_id": upload_id})["hidden"] is False
            restored_scope = AnalyticsScope(dataset=source, excluded=dashboard_visibility().excluded)
            assert mongo.database.security_events.count_documents(restored_scope.mongo()) == 12
            clause, values = restored_scope.sql()
            check_cursor.execute(f"SELECT COUNT(*) count FROM incidents i WHERE {clause}", values)
            assert check_cursor.fetchone()["count"] == 2
            check_cursor.close()
            repeated = process_events(authentication_events=events, mysql=RollbackDatabase(), mongo=mongo)
            assert repeated.mongo_events_inserted == repeated.mysql_incidents_created == 0
            assert repeated.mongo_event_duplicates == 12
            assert repeated.mysql_incident_duplicates == 2
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT incident_id FROM incidents WHERE source_dataset=%s ORDER BY incident_id", (source,))
            incident_id = cursor.fetchall()[0]["incident_id"]
            cursor.execute("INSERT INTO analysts(name,role,team) VALUES(%s,'test','synthetic integration')", (f"SYN-{run_id}",))
            analyst_id = cursor.lastrowid
            service = AssignmentService(RollbackDatabase())
            assignment_id = service.assign(incident_id, analyst_id, "Synthetic integration assignment")
            assert service.assign(incident_id, analyst_id) == assignment_id
            service.change_status(incident_id, "investigating", analyst_id=analyst_id)
            service.add_response(incident_id, analyst_id, "Synthetic credential reset", "Test fixture only")
            service.change_status(incident_id, "resolved", analyst_id=analyst_id, notes="Synthetic resolution")
            cursor.execute("SELECT status,created_at,resolved_at FROM incidents WHERE incident_id=%s", (incident_id,))
            resolved = cursor.fetchone()
            assert resolved["status"] == "resolved"
            assert resolved["resolved_at"] >= resolved["created_at"]
            cursor.execute("SELECT resolved_at,response_action FROM assignments WHERE assignment_id=%s", (assignment_id,))
            assignment = cursor.fetchone()
            assert assignment["resolved_at"] is not None
            assert assignment["response_action"] == "Synthetic credential reset"
            cursor.execute(ANALYST_WORKLOAD)
            workload = next(row for row in cursor.fetchall() if row["analyst_id"] == analyst_id)
            assert workload["active_assignments"] == 0
            cursor.execute(AVERAGE_RESPONSE_TIME)
            assert any(float(row["avg_seconds"]) >= 0 for row in cursor.fetchall())
            service.change_status(incident_id, "resolved", analyst_id=analyst_id)
            cursor.execute("SELECT resolved_at FROM incidents WHERE incident_id=%s", (incident_id,))
            assert cursor.fetchone()["resolved_at"] == resolved["resolved_at"]
            with pytest.raises(ValueError, match="Reopen"):
                service.assign(incident_id, analyst_id)
            service.change_status(incident_id, "open", analyst_id=analyst_id)
            cursor.execute("SELECT resolved_at FROM incidents WHERE incident_id=%s", (incident_id,))
            assert cursor.fetchone()["resolved_at"] is None
            with pytest.raises(ValueError, match="Assign an analyst"):
                service.change_status(incident_id, "investigating")
            new_assignment_id = service.assign(incident_id, analyst_id)
            assert new_assignment_id != assignment_id
            cursor.execute("SELECT action FROM incident_audit_log WHERE incident_id=%s", (incident_id,))
            actions = [row["action"] for row in cursor.fetchall()]
            assert "response_recorded" in actions and "status_changed" in actions
            cursor.close()
        finally:
            connection.rollback()
            # Delete only the unique synthetic documents inserted by this test run.
            mongo.database.security_events.delete_many({"source_dataset": source})
            mongo.database.security_alerts.delete_many({"source_dataset": source})
            mongo.database.ingestion_runs.delete_many({"upload_id": upload_id})
            mongo.database.ingestion_uploads.delete_one({"_id": upload_id})
            mongo.close()
