"""Repeated failed-login detection using a rolling time window."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta

from detection.common import alert_id_from_key, stable_detection_key
from detection.models import DetectionAlert
from etl.models import NormalizedEvent


def detect_repeated_failed_logins(
    events: list[NormalizedEvent],
    *,
    threshold: int = 5,
    window_minutes: int = 5,
) -> list[DetectionAlert]:
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if window_minutes <= 0:
        raise ValueError("window_minutes must be positive")

    failures = sorted(
        (
            event
            for event in events
            if event.event_type == "authentication"
            and event.authentication_result == "failure"
            and event.user_id
        ),
        key=lambda event: event.timestamp,
    )
    windows: dict[tuple[str, str], deque[NormalizedEvent]] = defaultdict(deque)
    suppressed_until: dict[tuple[str, str], datetime] = {}
    duration = timedelta(minutes=window_minutes)
    alerts: list[DetectionAlert] = []

    for event in failures:
        entity = (event.source_dataset, event.user_id or "")
        window = windows[entity]
        while window and event.timestamp - window[0].timestamp > duration:
            window.popleft()
        window.append(event)

        last_alert = suppressed_until.get(entity)
        if len(window) >= threshold and (
            last_alert is None or event.timestamp - last_alert > duration
        ):
            evidence_events = list(window)
            start = evidence_events[0].timestamp
            key = stable_detection_key(
                "repeated_failed_login", event.source_dataset, event.user_id or "", start
            )
            alerts.append(
                DetectionAlert(
                    alert_id=alert_id_from_key(key),
                    detection_key=key,
                    rule_name="repeated_failed_login",
                    timestamp=event.timestamp,
                    severity="high",
                    source_dataset=event.source_dataset,
                    title=f"Repeated failed logins for {event.user_id}",
                    description=(
                        f"Observed {len(evidence_events)} failed attempts within "
                        f"{window_minutes} minutes."
                    ),
                    event_references=[item.event_id for item in evidence_events],
                    evidence={
                        "user_id": event.user_id,
                        "attempt_count": len(evidence_events),
                        "source_ips": sorted(
                            {item.source_ip for item in evidence_events if item.source_ip}
                        ),
                        "window_start": start,
                        "window_end": event.timestamp,
                    },
                )
            )
            suppressed_until[entity] = event.timestamp
    return alerts
