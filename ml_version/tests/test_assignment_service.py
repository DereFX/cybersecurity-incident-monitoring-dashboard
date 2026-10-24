from __future__ import annotations

import pytest

from incidents.assignment_service import AssignmentService


def test_invalid_incident_status_is_rejected() -> None:
    with pytest.raises(ValueError, match="Invalid incident status"):
        AssignmentService.validate_status("deleted")

