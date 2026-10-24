"""MongoDB client and required collection indexes."""

from __future__ import annotations

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.database import Database

from config.settings import Settings


class MongoDatabase:
    def __init__(self, settings: Settings) -> None:
        self._client: MongoClient = MongoClient(
            settings.mongodb_uri,
            serverSelectionTimeoutMS=5_000,
            tz_aware=True,
        )
        self.database: Database = self._client[settings.mongodb_database]

    def ping(self) -> bool:
        try:
            self._client.admin.command("ping")
            return True
        except Exception:
            return False

    def ensure_indexes(self) -> None:
        events = self.database["security_events"]
        alerts = self.database["security_alerts"]
        events.create_index("event_id", unique=True, name="uq_event_id")
        events.create_index([("timestamp", DESCENDING)], name="ix_event_timestamp")
        events.create_index([("user_id", ASCENDING), ("timestamp", DESCENDING)], name="ix_user_time")
        events.create_index([("event_type", ASCENDING), ("timestamp", DESCENDING)], name="ix_type_time")
        events.create_index([("source_ip", ASCENDING), ("timestamp", DESCENDING)], name="ix_source_ip_time")
        events.create_index([("source_dataset", ASCENDING), ("event_id", ASCENDING)], name="ix_source_event")
        alerts.create_index("alert_id", unique=True, name="uq_alert_id")
        alerts.create_index("detection_key", unique=True, name="uq_detection_key")
        alerts.create_index([("timestamp", DESCENDING)], name="ix_alert_timestamp")
        alerts.create_index([("severity", ASCENDING), ("timestamp", DESCENDING)], name="ix_alert_severity_time")
        self.database.ingestion_uploads.create_index([("hidden", ASCENDING), ("uploaded_at", DESCENDING)], name="ix_upload_visibility_time")
        self.database.ingestion_runs.create_index([("upload_id", ASCENDING), ("started_at", DESCENDING)], name="ix_upload_runs")

    def close(self) -> None:
        self._client.close()

