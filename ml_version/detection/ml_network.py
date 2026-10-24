"""Supervised network-event detection using a persisted trained model."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd

from detection.common import alert_id_from_key, stable_detection_key
from detection.models import DetectionAlert
from etl.models import NormalizedEvent
from ml.network_model import prepare_features

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[1] / "models/network_classifier.joblib"


@lru_cache(maxsize=4)
def load_model_bundle(model_path: str) -> dict:
    path = Path(model_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Trained model not found at {path}. Run: python scripts/train_network_model.py"
        )
    bundle = joblib.load(path)
    required = {"pipeline", "threshold", "model_version", "metadata"}
    if not required.issubset(bundle):
        raise ValueError("The trained model bundle is incomplete")
    return bundle


def detect_ml_network_activity(
    events: list[NormalizedEvent],
    *,
    model_path: str | Path = DEFAULT_MODEL_PATH,
    probability_threshold: float | None = None,
) -> list[DetectionAlert]:
    network_events = [event for event in events if event.event_type == "network_flow"]
    if not network_events:
        return []

    bundle = load_model_bundle(str(Path(model_path).resolve()))
    threshold = (
        float(bundle["threshold"])
        if probability_threshold is None
        else float(probability_threshold)
    )
    if not 0.0 < threshold < 1.0:
        raise ValueError("probability_threshold must be between 0 and 1")

    frame = pd.DataFrame([event.raw_event for event in network_events])
    probabilities = bundle["pipeline"].predict_proba(prepare_features(frame))[:, 1]
    alerts: list[DetectionAlert] = []
    for event, probability in zip(network_events, probabilities, strict=True):
        probability = float(probability)
        if probability < threshold:
            continue
        key = stable_detection_key(
            "ml_network_classifier", event.source_dataset, event.event_id, event.timestamp
        )
        severity = "high" if probability >= max(0.90, threshold + 0.15) else "medium"
        alerts.append(
            DetectionAlert(
                alert_id=alert_id_from_key(key),
                detection_key=key,
                rule_name="ml_network_classifier",
                timestamp=event.timestamp,
                severity=severity,
                source_dataset=event.source_dataset,
                title=f"Model-predicted malicious flow from {event.source_ip or 'unknown source'}",
                description=(
                    f"The trained network classifier produced attack probability "
                    f"{probability:.3f} at decision threshold {threshold:.3f}."
                ),
                event_references=[event.event_id],
                evidence={
                    "source_ip": event.source_ip,
                    "destination_ip": event.destination_ip,
                    "attack_probability": probability,
                    "decision_threshold": threshold,
                    "model_version": bundle["model_version"],
                    "important_flow_values": {
                        name: event.raw_event.get(name)
                        for name in ("rate", "sbytes", "dbytes", "sttl", "ct_srv_src")
                    },
                    "label_not_used_for_prediction": True,
                },
            )
        )
    return alerts

