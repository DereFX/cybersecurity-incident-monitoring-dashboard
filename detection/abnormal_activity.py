"""Explainable network-flow anomaly detection without machine learning."""

from __future__ import annotations

from typing import Any

import numpy as np

from detection.common import alert_id_from_key, stable_detection_key
from detection.models import DetectionAlert
from etl.models import NormalizedEvent


def _upper_iqr(values: list[float], multiplier: float) -> float:
    q1, q3 = np.quantile(np.asarray(values, dtype=float), [0.25, 0.75])
    return float(q3 + multiplier * (q3 - q1))


def detect_abnormal_network_activity(
    events: list[NormalizedEvent],
    *,
    iqr_multiplier: float = 3.0,
    connection_count_threshold: int = 40,
) -> list[DetectionAlert]:
    """Detect extreme volumes/rates and connection concentration.

    Thresholds are calculated only from flow features. `label` and
    `attack_cat` remain available for later evaluation but never trigger an
    alert.
    """

    network_events = [event for event in events if event.event_type == "network_flow"]
    if not network_events:
        return []
    if iqr_multiplier <= 0 or connection_count_threshold <= 0:
        raise ValueError("network thresholds must be positive")

    def feature(event: NormalizedEvent, name: str) -> float:
        value = event.raw_event.get(name)
        return float(value) if value is not None else 0.0

    thresholds = {
        name: _upper_iqr([feature(event, name) for event in network_events], iqr_multiplier)
        for name in ("rate", "sbytes", "sload")
    }
    alerts: list[DetectionAlert] = []
    for event in network_events:
        reasons: dict[str, Any] = {}
        for name, upper in thresholds.items():
            value = feature(event, name)
            if value > upper:
                reasons[name] = {"observed": value, "threshold": upper}
        counts = {
            name: int(feature(event, name))
            for name in ("ct_src_dport_ltm", "ct_dst_ltm", "ct_srv_src")
        }
        for name, value in counts.items():
            if value >= connection_count_threshold:
                reasons[name] = {
                    "observed": value,
                    "threshold": connection_count_threshold,
                }
        if not reasons:
            continue

        key = stable_detection_key(
            "abnormal_network_activity",
            event.source_dataset,
            event.event_id,
            event.timestamp,
        )
        severity = "high" if len(reasons) >= 2 else "medium"
        alerts.append(
            DetectionAlert(
                alert_id=alert_id_from_key(key),
                detection_key=key,
                rule_name="abnormal_network_activity",
                timestamp=event.timestamp,
                severity=severity,
                source_dataset=event.source_dataset,
                title=f"Abnormal network flow from {event.source_ip or 'unknown source'}",
                description="One or more flow features exceeded explainable configured thresholds.",
                event_references=[event.event_id],
                evidence={
                    "source_ip": event.source_ip,
                    "destination_ip": event.destination_ip,
                    "triggered_features": reasons,
                },
            )
        )
    return alerts
