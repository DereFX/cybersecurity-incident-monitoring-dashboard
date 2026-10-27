"""Durable per-file upload tracking and per-attempt pipeline history in MongoDB."""

from datetime import datetime, timezone
from hashlib import sha256
from uuid import uuid4

from etl.models import NormalizedEvent


def namespace_upload_events(events: list[NormalizedEvent], upload_id: str) -> None:
    """Keep overlapping CSV event IDs isolated; original IDs remain in raw_event."""
    prefix = f"upload:{upload_id}:"
    for event in events:
        if not event.event_id.startswith(prefix):
            event.event_id = prefix + sha256(event.event_id.encode()).hexdigest()


class UploadHistory:
    def __init__(self, database):
        self.files = database.ingestion_uploads
        self.runs = database.ingestion_runs

    def register(self, filename: str, content_hash: str, size_bytes: int, *, sheet_name: str | None = None) -> dict:
        identity = f"{filename}\0{content_hash}"
        if sheet_name is not None:
            identity += f"\0worksheet:{sheet_name}"
        upload_id = sha256(identity.encode()).hexdigest()
        now = datetime.now(timezone.utc)
        self.files.update_one({"_id": upload_id}, {"$setOnInsert": {
            "filename": filename, "content_sha256": content_hash,
            "size_bytes": size_bytes, "uploaded_at": now, "hidden": False,
            "status": "uploaded",
            **({"sheet_name": sheet_name, "file_format": "xlsx"} if sheet_name is not None else {}),
        }}, upsert=True)
        return self.files.find_one({"_id": upload_id})

    def validated(self, upload_id: str, dataset_type: str, source_dataset: str, columns: list[str]) -> None:
        self.files.update_one({"_id": upload_id}, {"$set": {
            "dataset_type": dataset_type, "source_dataset": source_dataset, "columns": columns,
        }})

    def validation_failed(self, upload_id: str, message: str) -> None:
        self.files.update_one({"_id": upload_id, "last_run_id": {"$exists": False}}, {"$set": {
            "status": "validation_failed", "validation_error": message,
        }})

    def start_run(self, upload_id: str, configuration: dict) -> str:
        run_id = uuid4().hex
        now = datetime.now(timezone.utc)
        self.runs.insert_one({"_id": run_id, "upload_id": upload_id,
                              "started_at": now, "status": "running", "configuration": configuration, "stages": {}})
        self.files.update_one({"_id": upload_id}, {"$set": {"status": "running", "last_run_id": run_id, "last_run_at": now}})
        return run_id

    def progress(self, run_id: str, stage: str, details: dict) -> None:
        # Stage names come only from the application's pipeline callback.
        allowed = {"mongo_indexes_ready", "events_stored", "detections_complete", "alerts_stored", "incidents_stored"}
        if stage not in allowed:
            raise ValueError("Unknown pipeline stage")
        self.runs.update_one({"_id": run_id}, {"$set": {f"stages.{stage}": details}})

    def finish(self, upload_id: str, run_id: str, *, summary: dict | None = None, error: str | None = None) -> None:
        status = "failed" if error else "completed"
        values = {"status": status, "finished_at": datetime.now(timezone.utc)}
        if summary is not None:
            values["summary"] = summary
        if error:
            values["error"] = error
        self.runs.update_one({"_id": run_id, "upload_id": upload_id}, {"$set": values})
        self.files.update_one({"_id": upload_id, "last_run_id": run_id}, {"$set": {"status": status}})

    def set_hidden(self, upload_id: str, hidden: bool) -> None:
        """Legacy storage field: True excludes this file's data from dashboard views."""
        result = self.files.update_one({"_id": upload_id}, {"$set": {"hidden": bool(hidden)}})
        if not result.matched_count:
            raise ValueError("Upload not found")

    def set_included(self, upload_id: str, included: bool) -> None:
        self.set_hidden(upload_id, not included)

    def set_existing_included(self, included: bool) -> None:
        self.files.update_many({"record_kind": "existing_dataset"}, {"$set": {"hidden": not included}})
