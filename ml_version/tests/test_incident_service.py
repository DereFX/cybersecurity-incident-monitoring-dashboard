from __future__ import annotations

from datetime import datetime, timezone

import pytest

from detection.models import DetectionAlert
from incidents.incident_service import IncidentService


def test_unknown_rule_is_rejected_before_database_access() -> None:
    alert = DetectionAlert(
        alert_id="ALT-SYNTHETIC",
        detection_key="0" * 64,
        rule_name="unknown_synthetic_rule",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        severity="medium",
        source_dataset="synthetic_test_fixture",
        title="Synthetic alert",
        description="Synthetic fixture only.",
        event_references=["SYN-1"],
    )
    service = IncidentService(database=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="No threat category mapping"):
        service.create_from_alert(alert)

