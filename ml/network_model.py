"""Train and evaluate a leakage-safe supervised UNSW-NB15 classifier."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

MODEL_VERSION = "network-random-forest-v1"

NUMERIC_FEATURES = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
    "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "tcprtt", "synack", "ackdat", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_srv_dst",
    "is_sm_ips_ports",
]
CATEGORICAL_FEATURES = ["proto", "service", "state"]
MODEL_FEATURES = [*NUMERIC_FEATURES, *CATEGORICAL_FEATURES]
EXCLUDED_LABEL_COLUMNS = ["label", "attack_cat"]
EXCLUDED_IDENTITY_COLUMNS = ["id", "event_timestamp", "source_ip", "destination_ip"]


@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    rows: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    accuracy: float
    precision: float
    recall: float
    f1: float


def prepare_features(frame: pd.DataFrame) -> pd.DataFrame:
    """Return model inputs and reject silently missing source features."""

    missing = sorted(set(MODEL_FEATURES) - set(frame.columns))
    if missing:
        raise ValueError(f"Missing model feature columns: {', '.join(missing)}")
    features = frame[MODEL_FEATURES].copy()
    features[NUMERIC_FEATURES] = features[NUMERIC_FEATURES].apply(
        pd.to_numeric, errors="coerce"
    )
    return features.replace([np.inf, -np.inf], np.nan)


def build_pipeline(random_state: int = 42) -> Pipeline:
    numeric = Pipeline([("imputer", SimpleImputer(strategy="median"))])
    categorical = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore")),
        ]
    )
    preprocessing = ColumnTransformer(
        [("numeric", numeric, NUMERIC_FEATURES),
         ("categorical", categorical, CATEGORICAL_FEATURES)]
    )
    classifier = RandomForestClassifier(
        n_estimators=400,
        max_depth=18,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=random_state,
    )
    return Pipeline([("preprocessing", preprocessing), ("classifier", classifier)])


def evaluate_predictions(labels: np.ndarray, predictions: np.ndarray) -> EvaluationMetrics:
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average="binary", zero_division=0
    )
    return EvaluationMetrics(
        rows=int(len(labels)),
        true_positives=int(tp),
        false_positives=int(fp),
        false_negatives=int(fn),
        true_negatives=int(tn),
        accuracy=float((tp + tn) / len(labels)),
        precision=float(precision),
        recall=float(recall),
        f1=float(f1),
    )


def select_threshold(
    labels: np.ndarray,
    probabilities: np.ndarray,
    *,
    minimum_recall: float = 0.95,
) -> float:
    """Choose the highest-precision validation threshold meeting recall target."""

    candidates: list[tuple[float, float, float]] = []
    for threshold in np.linspace(0.05, 0.95, 181):
        predictions = (probabilities >= threshold).astype(int)
        precision, recall, _, _ = precision_recall_fscore_support(
            labels, predictions, average="binary", zero_division=0
        )
        if recall >= minimum_recall:
            candidates.append((float(precision), float(recall), float(threshold)))
    if not candidates:
        return 0.05
    return max(candidates, key=lambda item: (item[0], item[2]))[2]


def rule_baseline_predictions(
    frame: pd.DataFrame,
    *,
    iqr_multiplier: float = 3.0,
    connection_count_threshold: int = 40,
) -> np.ndarray:
    """Reproduce the original rule detector for a like-for-like comparison."""

    numeric = frame.copy()
    watched = ["rate", "sbytes", "sload"]
    counts = ["ct_src_dport_ltm", "ct_dst_ltm", "ct_srv_src"]
    for column in [*watched, *counts]:
        numeric[column] = pd.to_numeric(numeric[column], errors="coerce").fillna(0)
    thresholds: dict[str, float] = {}
    for column in watched:
        q1, q3 = np.quantile(numeric[column].to_numpy(dtype=float), [0.25, 0.75])
        thresholds[column] = float(q3 + iqr_multiplier * (q3 - q1))
    predictions = pd.Series(False, index=numeric.index)
    for column, threshold in thresholds.items():
        predictions |= numeric[column] > threshold
    for column in counts:
        predictions |= numeric[column] >= connection_count_threshold
    return predictions.astype(int).to_numpy()


def _dataset_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def train_model(
    csv_path: str | Path,
    model_path: str | Path,
    metadata_path: str | Path,
    *,
    random_state: int = 42,
    minimum_recall: float = 0.95,
) -> dict[str, Any]:
    """Train on 60%, tune on 20%, and report once on untouched 20%."""

    csv_path = Path(csv_path)
    frame = pd.read_csv(csv_path)
    if "label" not in frame:
        raise ValueError("Training data must contain the observed binary label column")
    labels = pd.to_numeric(frame["label"], errors="raise").astype(int)
    if set(labels.unique()) - {0, 1}:
        raise ValueError("Training labels must contain only 0 and 1")

    development, test = train_test_split(
        frame, test_size=0.20, stratify=labels, random_state=random_state
    )
    train, validation = train_test_split(
        development,
        test_size=0.25,
        stratify=development["label"],
        random_state=random_state,
    )

    pipeline = build_pipeline(random_state)
    pipeline.fit(prepare_features(train), train["label"].astype(int))
    validation_probabilities = pipeline.predict_proba(prepare_features(validation))[:, 1]
    threshold = select_threshold(
        validation["label"].to_numpy(dtype=int),
        validation_probabilities,
        minimum_recall=minimum_recall,
    )
    test_probabilities = pipeline.predict_proba(prepare_features(test))[:, 1]
    test_predictions = (test_probabilities >= threshold).astype(int)
    metrics = evaluate_predictions(test["label"].to_numpy(dtype=int), test_predictions)
    baseline_metrics = evaluate_predictions(
        test["label"].to_numpy(dtype=int), rule_baseline_predictions(test)
    )

    classifier = pipeline.named_steps["classifier"]
    transformed_names = pipeline.named_steps["preprocessing"].get_feature_names_out()
    importance_pairs = sorted(
        zip(transformed_names, classifier.feature_importances_, strict=True),
        key=lambda pair: pair[1],
        reverse=True,
    )[:15]

    metadata: dict[str, Any] = {
        "model_version": MODEL_VERSION,
        "trained_at_utc": datetime.now(UTC).isoformat(),
        "training_source": csv_path.name,
        "training_source_sha256": _dataset_sha256(csv_path),
        "random_state": random_state,
        "split": {
            "training_rows": len(train),
            "validation_rows": len(validation),
            "test_rows": len(test),
        },
        "decision_threshold": threshold,
        "minimum_validation_recall_target": minimum_recall,
        "test_metrics": asdict(metrics),
        "rule_baseline_on_same_test_split": asdict(baseline_metrics),
        "model_features": MODEL_FEATURES,
        "excluded_label_columns": EXCLUDED_LABEL_COLUMNS,
        "excluded_identity_columns": EXCLUDED_IDENTITY_COLUMNS,
        "top_feature_importances": [
            {"feature": str(name), "importance": float(value)}
            for name, value in importance_pairs
        ],
        "limitations": [
            "Metrics apply only to the held-out portion of the supplied quickstart dataset.",
            "The supplied files are representative generated data, not verbatim official UNSW-NB15 records.",
            "A low classification threshold improves recall but can increase false positives.",
            "Performance on live organizational traffic requires separate validation and monitoring.",
        ],
    }
    bundle = {
        "pipeline": pipeline,
        "threshold": threshold,
        "model_version": MODEL_VERSION,
        "metadata": metadata,
    }
    model_path = Path(model_path)
    metadata_path = Path(metadata_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path)
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata
