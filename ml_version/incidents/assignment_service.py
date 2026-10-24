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
                    "SELECT status FROM incidents WHERE incident_id = %s FOR UPDATE",
                    (incident_id,),
                )
                incident = cursor.fetchone()
                if incident is None:
                    raise ValueError("Incident not found")
                old_status = str(incident[0])
                if old_status in {"resolved", "false_positive"}:
                    raise ValueError("Reopen this incident before assigning an analyst")
                cursor.execute(
                    "SELECT 1 FROM analysts WHERE analyst_id = %s AND active = TRUE",
                    (analyst_id,),
                )
                if cursor.fetchone() is None:
                    raise ValueError("Active analyst not found")
                cursor.execute("SELECT assignment_id, analyst_id FROM assignments WHERE incident_id=%s AND resolved_at IS NULL ORDER BY assignment_id DESC LIMIT 1", (incident_id,))
                current = cursor.fetchone()
                if current and int(current[1]) == analyst_id:
                    return int(current[0])
                cursor.execute("UPDATE assignments SET resolved_at=UTC_TIMESTAMP(6) WHERE incident_id=%s AND resolved_at IS NULL", (incident_id,))
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
                        (incident_id, analyst_id, action, old_status, new_status, notes)
                    VALUES (%s, %s, 'assigned', %s, 'assigned', %s)
                    """,
                    (incident_id, analyst_id, old_status, comments or None),
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
                if analyst_id is not None:
                    cursor.execute("SELECT 1 FROM analysts WHERE analyst_id=%s AND active=TRUE", (analyst_id,))
                    if cursor.fetchone() is None:
                        raise ValueError("Active analyst not found")
                if old_status == new_status:
                    return
                if new_status in {"assigned", "investigating"}:
                    cursor.execute("SELECT 1 FROM assignments WHERE incident_id=%s AND resolved_at IS NULL LIMIT 1", (incident_id,))
                    if cursor.fetchone() is None:
                        raise ValueError("Assign an analyst before starting investigation")
                cursor.execute(
                    """
                    UPDATE incidents
                    SET status = %s,
                        resolved_at = CASE
                            WHEN %s IN ('resolved', 'false_positive')
                            THEN UTC_TIMESTAMP(6)
                            ELSE NULL
                        END
                    WHERE incident_id = %s
                    """,
                    (new_status, new_status, incident_id),
                )
                if new_status in {"resolved", "false_positive", "open"}:
                    cursor.execute("UPDATE assignments SET resolved_at=UTC_TIMESTAMP(6) WHERE incident_id=%s AND resolved_at IS NULL", (incident_id,))
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
                cursor.execute("SELECT status FROM incidents WHERE incident_id=%s FOR UPDATE", (incident_id,))
                incident = cursor.fetchone()
                if incident is None:
                    raise ValueError("Incident not found")
                if incident[0] in {"resolved", "false_positive"}:
                    raise ValueError("Reopen this incident before recording a response")
                cursor.execute("SELECT 1 FROM analysts WHERE analyst_id=%s AND active=TRUE", (analyst_id,))
                if cursor.fetchone() is None:
                    raise ValueError("Active analyst not found")
                cursor.execute("SELECT assignment_id FROM assignments WHERE incident_id=%s AND analyst_id=%s AND resolved_at IS NULL ORDER BY assignment_id DESC LIMIT 1", (incident_id, analyst_id))
                assignment = cursor.fetchone()
                if assignment is None:
                    raise ValueError("No active assignment found for this analyst")
                cursor.execute(
                    """
                    UPDATE assignments
                    SET response_action = %s, comments = %s
                    WHERE assignment_id = %s
                    """,
                    (response_action, comments or None, int(assignment[0])),
                )
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

