from pathlib import Path
from unittest.mock import MagicMock

from etl.existing_sources import collect_existing_sources, register_existing_sources, related_csv_files
from etl.upload_history import UploadHistory


def test_discovery_includes_incident_only_event_only_and_alert_only_sources():
    rows = collect_existing_sources(
        [{"source_dataset": "sql_only", "incident_count": 3}, {"source_dataset": "shared", "incident_count": 2}],
        [{"_id": "events_only", "event_count": 4, "event_types": ["authentication"]},
         {"_id": "shared", "event_count": 12, "event_types": ["network_flow"]}],
        [{"_id": "alerts_only", "alert_count": 1}, {"_id": "shared", "alert_count": 2}],
    )
    found = {row["source_dataset"]: row for row in rows}
    assert set(found) == {"sql_only", "events_only", "alerts_only", "shared"}
    assert found["shared"]["event_count"] == 12
    assert found["shared"]["incident_count"] == found["shared"]["alert_count"] == 2
    assert found["events_only"]["incident_count"] == 0


def test_existing_registration_is_stable_and_never_reimports_records():
    database = MagicMock()
    database.ingestion_uploads.find.return_value = []
    source = {"source_dataset": "synthetic_existing", "event_count": 12,
              "incident_count": 2, "alert_count": 2, "event_types": ["authentication"]}
    root = Path(__file__).parent / "no_csv_fixtures_here"
    register_existing_sources(database, [source], root)
    first = database.ingestion_uploads.update_one.call_args
    assert first.kwargs["upsert"] is True
    assert first.args[1]["$setOnInsert"]["record_kind"] == "existing_dataset"
    assert first.args[1]["$setOnInsert"]["content_sha256"] is None
    assert "hidden" not in first.args[1]["$set"]
    assert "uploaded_at" not in first.args[1]["$set"]
    register_existing_sources(database, [source], root)
    assert database.ingestion_uploads.update_one.call_args.args[0] == first.args[0]
    database.security_events.insert_many.assert_not_called()
    database.security_alerts.insert_many.assert_not_called()
    database.ingestion_runs.insert_one.assert_not_called()


def test_already_tracked_upload_does_not_get_a_second_source_control():
    database = MagicMock()
    database.ingestion_uploads.find.return_value = [{"source_dataset": "tracked", "_id": "existing-upload-id"}]
    register_existing_sources(database, [{"source_dataset": "tracked", "event_count": 12,
        "incident_count": 2, "alert_count": 2, "event_types": ["authentication"]}], Path(__file__).parent)
    database.ingestion_uploads.update_one.assert_not_called()


def test_group_toggle_changes_only_existing_source_preferences():
    database = MagicMock()
    UploadHistory(database).set_existing_included(False)
    database.ingestion_uploads.update_many.assert_called_once_with(
        {"record_kind": "existing_dataset"}, {"$set": {"hidden": True}})
    database.security_events.delete_many.assert_not_called()
    database.security_alerts.delete_many.assert_not_called()


def test_related_csv_lookup_uses_real_project_files():
    root = Path(__file__).resolve().parents[1]
    match = related_csv_files(root)["uploaded_authentication:synthetic_authentication_demo_csv"]
    assert (root / match["related_csv_path"]).is_file()
    assert match["filename"] == "synthetic_authentication_demo.csv"
