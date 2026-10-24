"""Detection tests use explicitly synthetic event fixtures."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from detection.failed_login import detect_repeated_failed_logins
from detection.suspicious_access import detect_suspicious_access
from etl.models import NormalizedEvent

START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def auth_event(
    number: int,
    minutes: float,
    *,
    successful: bool = False,
    user_id: str | None = "SYN-USER-1",
    source_ip: str = "192.0.2.1",
    device_id: str = "SYN-DEVICE-1",
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"SYN-AUTH-{number}",
        timestamp=START + timedelta(minutes=minutes),
        source_dataset="synthetic_test_fixture",
        event_type="authentication",
        source_ip=source_ip,
        user_id=user_id,
        device_id=device_id,
        authentication_result="success" if successful else "failure",
    )


def test_exactly_five_failures_within_five_minutes_alerts() -> None:
    events = [auth_event(index, index) for index in range(5)]
    alerts = detect_repeated_failed_logins(events)
    assert len(alerts) == 1
    assert alerts[0].evidence["attempt_count"] == 5
    assert alerts[0].severity == "high"


def test_four_failures_produce_no_alert() -> None:
    assert detect_repeated_failed_logins([auth_event(i, i) for i in range(4)]) == []


def test_failures_outside_window_produce_no_alert() -> None:
    events = [auth_event(index, index * 2) for index in range(5)]
    assert detect_repeated_failed_logins(events) == []


def test_missing_user_is_ignored_safely() -> None:
    events = [auth_event(index, index, user_id=None) for index in range(5)]
    assert detect_repeated_failed_logins(events) == []


def test_multiple_origin_access_is_suspicious_not_confirmed_attack() -> None:
    events = [
        auth_event(1, 0, successful=True, source_ip="192.0.2.1", device_id="SYN-D1"),
        auth_event(2, 1, successful=True, source_ip="192.0.2.2", device_id="SYN-D2"),
        auth_event(3, 2, successful=True, source_ip="192.0.2.3", device_id="SYN-D3"),
    ]
    alerts = detect_suspicious_access(events)
    assert len(alerts) == 1
    assert alerts[0].severity == "medium"
    assert "not proof" in alerts[0].description.lower()

