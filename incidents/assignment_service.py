"""Analyst assignment and incident lifecycle operations."""

from __future__ import annotations

from database.mysql_connection import MySQLDatabase

VALID_STATUSES = {"open", "assigned", "investigating", "resolved", "false_positive"}


class AssignmentService:
    def __init__(self, database: MySQLDatabase) -> None:
        self.database = database

    @staticmethod
    def validate_status(status: str) -> None:
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid incident status: {status}")

    def assign(self, incident_id: int, analyst_id: int, comments: str = "") -> int:
        with self.database.transaction() as connection:
            cursor = connection.cursor()
            try:
                cursor.execute(
                    "SELECT 1 FROM incidents WHERE incident_id = %s FOR UPDATE",
                    (incident_id,),
                )
                if cursor.fetchone() is None:
                    raise ValueError("Incident not found")
                cursor.execute(
                    "SELECT 1 FROM analysts WHERE analyst_id = %s AND active = TRUE",
                    (analyst_id,),
                )
                if cursor.fetchone() is None:
                    raise ValueError("Active analyst not found")
                cursor.execute(
                    """
                    INSERT INTO assignments (incident_id, analyst_id, comments)
                    VALUES (%s, %s, %s)
                    """,
                    (incident_id, analyst_id, comments or None),
                )
                assignment_id = int(cursor.lastrowid)
                cursor.execute(
                    "UPDATE incidents SET status = 'assigned' WHERE incident_id = %s",
                    (incident_id,),
                )
                cursor.execute(
                    """
                    INSERT INTO incident_audit_log
                        (incident_id, analyst_id, action, new_status, notes)
                    VALUES (%s, %s, 'assigned', 'assigned', %s)
                    """,
                    (incident_id, analyst_id, comments or None),
                )
                return assignment_id
            finally:
                cursor.close()

    def change_status(
        self,
        incident_id: int,
        new_status: str,
        *,
        analyst_id: int | None = None,
        notes: str = "",
    ) -> None:
        self.validate_status(new_status)
        with self.database.transaction() as connection:
            cursor = connection.cursor()
            try:
                cursor.execute(
                    "SELECT status FROM incidents WHERE incident_id = %s FOR UPDATE",
                    (incident_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise ValueError("Incident not found")
                old_status = str(row[0])
                cursor.execute(
                    """
                    UPDATE incidents
                    SET status = %s,
                        resolved_at = CASE
                            WHEN %s IN ('resolved', 'false_positive')
                            THEN CURRENT_TIMESTAMP(6)
                            ELSE NULL
                        END
                    WHERE incident_id = %s
                    """,
                    (new_status, new_status, incident_id),
                )
                cursor.execute(
                    """
                    INSERT INTO incident_audit_log
                        (incident_id, analyst_id, action, old_status, new_status, notes)
                    VALUES (%s, %s, 'status_changed', %s, %s, %s)
                    """,
                    (incident_id, analyst_id, old_status, new_status, notes or None),
                )
            finally:
                cursor.close()

    def add_response(
        self, incident_id: int, analyst_id: int, response_action: str, comments: str
    ) -> None:
        if not response_action.strip():
            raise ValueError("Response action is required")
        with self.database.transaction() as connection:
            cursor = connection.cursor()
            try:
                cursor.execute(
                    """
                    UPDATE assignments
                    SET response_action = %s, comments = %s
                    WHERE incident_id = %s AND analyst_id = %s AND resolved_at IS NULL
                    ORDER BY assignment_id DESC LIMIT 1
                    """,
                    (response_action, comments or None, incident_id, analyst_id),
                )
                if cursor.rowcount == 0:
                    raise ValueError("No active assignment found for this analyst")
                cursor.execute(
                    """
                    INSERT INTO incident_audit_log
                        (incident_id, analyst_id, action, notes)
                    VALUES (%s, %s, 'response_recorded', %s)
                    """,
                    (incident_id, analyst_id, f"{response_action}: {comments}"),
                )
            finally:
                cursor.close()

