from __future__ import annotations

import numpy as np
import pandas as pd

from detection.ml_network import detect_ml_network_activity
from etl.network_loader import load_network_csv
from ml.network_model import (
    EXCLUDED_IDENTITY_COLUMNS,
    EXCLUDED_LABEL_COLUMNS,
    MODEL_FEATURES,
    prepare_features,
    select_threshold,
)


def test_model_inputs_exclude_labels_and_identifiers() -> None:
    row = {feature: 1 for feature in MODEL_FEATURES}
    row.update({"label": 1, "attack_cat": "Exploits", "id": 99, "source_ip": "x"})
    prepared = prepare_features(pd.DataFrame([row]))

    assert list(prepared.columns) == MODEL_FEATURES
    assert not set(EXCLUDED_LABEL_COLUMNS).intersection(prepared.columns)
    assert not set(EXCLUDED_IDENTITY_COLUMNS).intersection(prepared.columns)


def test_threshold_selection_meets_recall_target() -> None:
    labels = np.asarray([1, 1, 1, 1, 0, 0])
    probabilities = np.asarray([0.95, 0.90, 0.70, 0.40, 0.35, 0.10])
    threshold = select_threshold(labels, probabilities, minimum_recall=0.75)
    predictions = (probabilities >= threshold).astype(int)
    recall = predictions[labels == 1].mean()

    assert recall >= 0.75


def test_saved_model_generates_standardized_alert() -> None:
    loaded = load_network_csv("data/raw/unsw_nb15_network_events_quickstart.csv")
    alerts = detect_ml_network_activity(loaded.events[:25], probability_threshold=0.01)

    assert alerts
    assert alerts[0].rule_name == "ml_network_classifier"
    assert 0.0 <= alerts[0].evidence["attack_probability"] <= 1.0
    assert alerts[0].evidence["label_not_used_for_prediction"] is True
