from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
from unittest.mock import MagicMock

import pytest

from etl.authentication_loader import load_authentication_csv
from etl.demo_data import authentication_demo_csv
from etl.upload_history import UploadHistory, namespace_upload_events


def test_filename_and_content_determine_separate_upload_identities():
    database = MagicMock()
    history = UploadHistory(database)
    content_hash = sha256(b"synthetic CSV content").hexdigest()
    history.register("a.csv", content_hash, 21)
    first_id = database.ingestion_uploads.update_one.call_args.args[0]["_id"]
    history.register("a.csv", content_hash, 21)
    assert database.ingestion_uploads.update_one.call_args.args[0]["_id"] == first_id
    history.register("a.csv", sha256(b"changed synthetic CSV content").hexdigest(), 29)
    assert database.ingestion_uploads.update_one.call_args.args[0]["_id"] != first_id
    history.register("b.csv", content_hash, 21)
    assert database.ingestion_uploads.update_one.call_args.args[0]["_id"] != first_id


def test_hiding_and_restoring_are_metadata_updates_without_deletion():
    database = MagicMock()
    history = UploadHistory(database)
    history.set_hidden("synthetic-id", True)
    database.ingestion_uploads.update_one.assert_called_with({"_id": "synthetic-id"}, {"$set": {"hidden": True}})
    history.set_hidden("synthetic-id", False)
    database.ingestion_uploads.update_one.assert_called_with({"_id": "synthetic-id"}, {"$set": {"hidden": False}})
    database.security_events.delete_many.assert_not_called()
    database.security_alerts.delete_many.assert_not_called()
    database.ingestion_runs.delete_many.assert_not_called()


def test_unknown_upload_cannot_be_hidden():
    database = MagicMock()
    database.ingestion_uploads.update_one.return_value.matched_count = 0
    with pytest.raises(ValueError, match="Upload not found"):
        UploadHistory(database).set_hidden("missing", True)


def test_each_import_has_distinct_run_id_and_preserves_configuration():
    database = MagicMock()
    history = UploadHistory(database)
    first = history.start_run("synthetic-id", {"threshold": 5})
    second = history.start_run("synthetic-id", {"threshold": 6})
    assert first != second
    assert database.ingestion_runs.insert_one.call_args.args[0]["configuration"] == {"threshold": 6}
    history.finish("synthetic-id", first, summary={"generated_alerts": 2})
    assert database.ingestion_runs.update_one.call_args.args[1]["$set"]["status"] == "completed"
    assert database.ingestion_uploads.update_one.call_args.args[0] == {"_id": "synthetic-id", "last_run_id": first}


def test_failed_run_retains_a_status_and_stage_validation():
    database = MagicMock()
    history = UploadHistory(database)
    history.finish("synthetic-id", "run", error="Synthetic connection failure")
    assert database.ingestion_runs.update_one.call_args.args[1]["$set"]["status"] == "failed"
    with pytest.raises(ValueError, match="Unknown pipeline stage"):
        history.progress("run", "$invalid.stage", {})


def test_same_event_ids_in_different_files_are_isolated_and_reimports_stable():
    csv = authentication_demo_csv("synthetic-test", datetime(2026, 10, 1, tzinfo=timezone.utc))
    first = load_authentication_csv(BytesIO(csv)).events
    other = load_authentication_csv(BytesIO(csv)).events
    original_id = first[0].event_id
    namespace_upload_events(first, "a" * 64)
    namespace_upload_events(other, "b" * 64)
    assert first[0].event_id != other[0].event_id
    assert first[0].raw_event["event_id"] == original_id
    stable_id = first[0].event_id
    namespace_upload_events(first, "a" * 64)
    assert first[0].event_id == stable_id
