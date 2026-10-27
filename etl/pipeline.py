"""End-to-end quickstart ingestion and detection orchestration."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from collections.abc import Callable
from typing import Any

from database.mongo_connection import MongoDatabase
from database.mongo_repository import SecurityEventRepository
from database.mysql_connection import MySQLDatabase
from detection.ml_network import DEFAULT_MODEL_PATH, detect_ml_network_activity
from detection.failed_login import detect_repeated_failed_logins
from detection.suspicious_access import detect_suspicious_access
from etl.authentication_loader import load_authentication_csv
from etl.network_loader import load_network_csv
from incidents.incident_service import IncidentService
from etl.models import NormalizedEvent

ProgressCallback = Callable[[str, dict[str, Any]], None]


@dataclass(slots=True)
class PipelineSummary:
    authentication_events: int
    network_events: int
    mongo_events_inserted: int
    mongo_event_duplicates: int
    generated_alerts: int
    mongo_alerts_inserted: int
    mongo_alert_duplicates: int
    mysql_incidents_created: int
    mysql_incident_duplicates: int

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


def process_events(
    *,
    authentication_events: list[NormalizedEvent] | None = None,
    network_events: list[NormalizedEvent] | None = None,
    mysql: MySQLDatabase,
    mongo: MongoDatabase,
    failed_login_threshold: int = 5,
    failed_login_window_minutes: int = 5,
    suspicious_origin_threshold: int = 3,
    suspicious_window_minutes: int = 10,
    network_model_path: str | Path = DEFAULT_MODEL_PATH,
    network_probability_threshold: float | None = None,
    progress: ProgressCallback | None = None,
) -> PipelineSummary:
    """Persist normalized events, run configured rules, and create incidents."""

    authentication_events = authentication_events or []
    network_events = network_events or []
    all_events = [*authentication_events, *network_events]

    def report(stage: str, **details: Any) -> None:
        if progress is not None:
            progress(stage, details)

    mongo.ensure_indexes()
    report("mongo_indexes_ready")
    repository = SecurityEventRepository(
        mongo.database["security_events"], mongo.database["security_alerts"]
    )
    event_write = repository.store_events(all_events)
    report(
        "events_stored",
        inserted=event_write.inserted,
        duplicates=event_write.duplicates,
        total=len(all_events),
    )
    alerts = [
        *detect_repeated_failed_logins(
            authentication_events,
            threshold=failed_login_threshold,
            window_minutes=failed_login_window_minutes,
        ),
        *detect_suspicious_access(
            authentication_events,
            minimum_distinct_origins=suspicious_origin_threshold,
            window_minutes=suspicious_window_minutes,
        ),
        *detect_ml_network_activity(
            network_events,
            model_path=network_model_path,
            probability_threshold=network_probability_threshold,
        ),
    ]
    report("detections_complete", alerts=len(alerts))
    alert_write = repository.store_alerts(alerts)
    report(
        "alerts_stored",
        inserted=alert_write.inserted,
        duplicates=alert_write.duplicates,
    )

    incident_service = IncidentService(mysql)
    created = 0
    duplicates = 0
    for alert in alerts:
        _, was_created = incident_service.create_from_alert(alert)
        created += int(was_created)
        duplicates += int(not was_created)
    report("incidents_stored", created=created, duplicates=duplicates)

    return PipelineSummary(
        authentication_events=len(authentication_events),
        network_events=len(network_events),
        mongo_events_inserted=event_write.inserted,
        mongo_event_duplicates=event_write.duplicates,
        generated_alerts=len(alerts),
        mongo_alerts_inserted=alert_write.inserted,
        mongo_alert_duplicates=alert_write.duplicates,
        mysql_incidents_created=created,
        mysql_incident_duplicates=duplicates,
    )


def run_pipeline(
    authentication_csv: str | Path,
    network_csv: str | Path,
    *,
    mysql: MySQLDatabase,
    mongo: MongoDatabase,
) -> PipelineSummary:
    authentication = load_authentication_csv(authentication_csv)
    network = load_network_csv(network_csv)
    return process_events(
        authentication_events=authentication.events,
        network_events=network.events,
        mysql=mysql,
        mongo=mongo,
    )
