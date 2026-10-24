"""Suspicious multi-origin access detection."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from detection.common import alert_id_from_key, stable_detection_key
from detection.models import DetectionAlert
from etl.models import NormalizedEvent


def detect_suspicious_access(
    events: list[NormalizedEvent],
    *,
    minimum_distinct_origins: int = 3,
    window_minutes: int = 10,
) -> list[DetectionAlert]:
    """Flag, but do not confirm, rapid access from distinct IPs/devices.

    Events without a user ID are skipped because they cannot be grouped safely.
    Shared IPs and legitimate device switching can cause false positives, which
    is why this rule emits medium-severity suspicious activity only.
    """

    if minimum_distinct_origins < 2:
        raise ValueError("minimum_distinct_origins must be at least 2")
    if window_minutes <= 0:
        raise ValueError("window_minutes must be positive")

    candidates = sorted(
        (
            event
            for event in events
            if event.event_type == "authentication"
            and event.authentication_result == "success"
            and event.user_id
            and (event.source_ip or event.device_id)
        ),
        key=lambda event: event.timestamp,
    )
    duration = timedelta(minutes=window_minutes)
    windows: dict[tuple[str, str], deque[NormalizedEvent]] = defaultdict(deque)
    alerted: set[tuple[str, str]] = set()
    alerts: list[DetectionAlert] = []

    for event in candidates:
        entity = (event.source_dataset, event.user_id or "")
        window = windows[entity]
        while window and event.timestamp - window[0].timestamp > duration:
            window.popleft()
        window.append(event)
        origins = {
            (item.source_ip or "missing-ip", item.device_id or "missing-device")
            for item in window
        }
        if len(origins) >= minimum_distinct_origins and entity not in alerted:
            start = window[0].timestamp
            key = stable_detection_key(
                "suspicious_multi_origin_access",
                event.source_dataset,
                event.user_id or "",
                start,
            )
            alerts.append(
                DetectionAlert(
                    alert_id=alert_id_from_key(key),
                    detection_key=key,
                    rule_name="suspicious_multi_origin_access",
                    timestamp=event.timestamp,
                    severity="medium",
                    source_dataset=event.source_dataset,
                    title=f"Multiple access origins for {event.user_id}",
                    description=(
                        f"Observed {len(origins)} distinct IP/device combinations "
                        f"within {window_minutes} minutes. This is suspicious, not "
                        "proof of account compromise."
                    ),
                    event_references=[item.event_id for item in window],
                    evidence={
                        "user_id": event.user_id,
                        "origins": sorted(origins),
                        "window_start": start,
                        "window_end": event.timestamp,
                        "limitations": "Shared IPs and legitimate device changes may trigger this rule.",
                    },
                )
            )
            alerted.add(entity)
    return alerts

