from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from incidents.assignment_service import AssignmentService


def test_invalid_incident_status_is_rejected() -> None:
    with pytest.raises(ValueError, match="Invalid incident status"):
        AssignmentService.validate_status("deleted")


def service_with_rows(rows):
    database = MagicMock()
    cursor = database.transaction.return_value.__enter__.return_value.cursor.return_value
    cursor.fetchone.side_effect = rows
    return AssignmentService(database), cursor


def test_terminal_case_cannot_be_assigned_without_reopening():
    service, cursor = service_with_rows([("resolved",)])
    with pytest.raises(ValueError, match="Reopen"):
        service.assign(1, 2)
    assert cursor.execute.call_count == 1


def test_repeated_resolution_preserves_timestamp_and_audit():
    service, cursor = service_with_rows([("resolved",)])
    service.change_status(1, "resolved")
    assert cursor.execute.call_count == 1


def test_investigation_requires_an_open_assignment():
    service, cursor = service_with_rows([("open",), None])
    with pytest.raises(ValueError, match="Assign an analyst"):
        service.change_status(1, "investigating")
    assert not any("UPDATE incidents" in call.args[0] for call in cursor.execute.call_args_list)


def test_resolution_closes_assignments_in_the_same_transaction():
    service, cursor = service_with_rows([("investigating",)])
    service.change_status(1, "resolved", notes="Synthetic test")
    queries = [call.args[0] for call in cursor.execute.call_args_list]
    assert any("UPDATE assignments SET resolved_at" in query for query in queries)
    assert any("INSERT INTO incident_audit_log" in query for query in queries)


def test_invalid_status_actor_is_rejected_before_mutation():
    service, cursor = service_with_rows([("open",), None])
    with pytest.raises(ValueError, match="Active analyst not found"):
        service.change_status(1, "resolved", analyst_id=9999)
    assert not any("UPDATE incidents" in call.args[0] for call in cursor.execute.call_args_list)

