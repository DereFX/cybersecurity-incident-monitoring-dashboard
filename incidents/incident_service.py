"""Transactional MySQL incident operations."""

from __future__ import annotations

from datetime import timezone

import mysql.connector

from database.mysql_connection import MySQLDatabase
from detection.models import DetectionAlert

RULE_CATEGORY = {
    "repeated_failed_login": "Repeated Failed Login",
    "suspicious_multi_origin_access": "Suspicious Access",
    "abnormal_network_activity": "Abnormal Network Activity",
}


class IncidentService:
    def __init__(self, database: MySQLDatabase) -> None:
        self.database = database

    @staticmethod
    def _ensure_user(cursor, alert: DetectionAlert) -> int | None:
        external_user_id = alert.evidence.get("user_id")
        if not external_user_id:
            return None
        cursor.execute(
            """
            INSERT INTO users
                (username, status, source_dataset, external_user_id)
            VALUES (%s, 'active', %s, %s)
            ON DUPLICATE KEY UPDATE user_id = LAST_INSERT_ID(user_id)
            """,
            (str(external_user_id), alert.source_dataset, str(external_user_id)),
        )
        return int(cursor.lastrowid)

    @staticmethod
    def _ensure_system(cursor, alert: DetectionAlert) -> int | None:
        address = alert.evidence.get("destination_ip") or alert.evidence.get("source_ip")
        if not address:
            return None
        external_id = str(address)
        cursor.execute(
            """
            INSERT INTO systems
                (hostname, ip_address, system_type, source_dataset, external_system_id)
            VALUES (NULL, %s, 'observed_network_endpoint', %s, %s)
            ON DUPLICATE KEY UPDATE system_id = LAST_INSERT_ID(system_id)
            """,
            (external_id, alert.source_dataset, external_id),
        )
        return int(cursor.lastrowid)

    def create_from_alert(self, alert: DetectionAlert) -> tuple[int, bool]:
        """Return ``(incident_id, created)`` using detection-key deduplication."""

        category_name = RULE_CATEGORY.get(alert.rule_name)
        if category_name is None:
            raise ValueError(f"No threat category mapping for rule {alert.rule_name!r}")

        with self.database.transaction() as connection:
            cursor = connection.cursor()
            try:
                cursor.execute(
                    "SELECT incident_id FROM incidents WHERE detection_key = %s",
                    (alert.detection_key,),
                )
                existing = cursor.fetchone()
                if existing:
                    return int(existing[0]), False

                cursor.execute(
                    "SELECT category_id FROM threat_categories WHERE category_name = %s",
                    (category_name,),
                )
                category = cursor.fetchone()
                if not category:
                    raise RuntimeError(
                        f"Threat category {category_name!r} is missing; run database/seed.sql."
                    )

                user_id = self._ensure_user(cursor, alert)
                system_id = self._ensure_system(cursor, alert)
                incident_time = alert.timestamp.astimezone(timezone.utc).replace(tzinfo=None)
                source_event_id = (
                    alert.event_references[0] if alert.event_references else None
                )
                cursor.execute(
                    """
                    INSERT INTO incidents
                        (user_id, system_id, category_id, incident_time, severity,
                         description, status, detected_by, source_dataset,
                         source_event_id, detection_key)
                    VALUES (%s, %s, %s, %s, %s, %s, 'open', %s, %s, %s, %s)
                    """,
                    (
                        user_id,
                        system_id,
                        int(category[0]),
                        incident_time,
                        alert.severity,
                        f"{alert.title}. {alert.description}",
                        alert.rule_name,
                        alert.source_dataset,
                        source_event_id,
                        alert.detection_key,
                    ),
                )
                incident_id = int(cursor.lastrowid)
                cursor.execute(
                    """
                    INSERT INTO incident_audit_log
                        (incident_id, action, new_status, notes)
                    VALUES (%s, 'created_from_alert', 'open', %s)
                    """,
                    (incident_id, f"Generated from alert {alert.alert_id}"),
                )
                return incident_id, True
            except mysql.connector.IntegrityError as error:
                if error.errno != 1062:
                    raise
                cursor.execute(
                    "SELECT incident_id FROM incidents WHERE detection_key = %s",
                    (alert.detection_key,),
                )
                existing = cursor.fetchone()
                if not existing:
                    raise
                return int(existing[0]), False
            finally:
                cursor.close()

    def counts(self) -> dict[str, int]:
        with self.database.connection() as connection:
            cursor = connection.cursor(dictionary=True)
            try:
                cursor.execute(
                    """
                    SELECT COUNT(*) AS total,
                           SUM(status IN ('open','assigned','investigating')) AS open_count,
                           SUM(status = 'resolved') AS resolved_count
                    FROM incidents
                    """
                )
                row = cursor.fetchone() or {}
                return {
                    "total": int(row.get("total") or 0),
                    "open": int(row.get("open_count") or 0),
                    "resolved": int(row.get("resolved_count") or 0),
                }
            finally:
                cursor.close()

