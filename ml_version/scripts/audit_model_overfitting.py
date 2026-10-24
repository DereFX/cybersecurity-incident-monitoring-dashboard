"""Run repeatable overfitting and split-leakage checks for the network model."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, train_test_split

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.network_model import (
    build_pipeline,
    evaluate_predictions,
    prepare_features,
    select_threshold,
)


def metrics_for(pipeline, frame: pd.DataFrame, threshold: float) -> dict:
    probabilities = pipeline.predict_proba(prepare_features(frame))[:, 1]
    predictions = (probabilities >= threshold).astype(int)
    return asdict(
        evaluate_predictions(frame["label"].to_numpy(dtype=int), predictions)
    )


def exact_feature_hashes(frame: pd.DataFrame) -> set[int]:
    prepared = prepare_features(frame).fillna("<missing>")
    return set(pd.util.hash_pandas_object(prepared, index=False).astype("uint64"))


def main() -> None:
    data_path = ROOT / "data/raw/unsw_nb15_network_events_quickstart.csv"
    model_path = ROOT / "models/network_classifier.joblib"
    output_path = ROOT / "models/overfitting_audit.json"
    development_data_path = ROOT / "data/raw/unsw_nb15_network_events_dev.csv"
    frame = pd.read_csv(data_path)
    labels = frame["label"].astype(int)
    bundle = joblib.load(model_path)
    pipeline = bundle["pipeline"]
    threshold = float(bundle["threshold"])

    development, test = train_test_split(
        frame, test_size=0.20, stratify=labels, random_state=42
    )
    train, validation = train_test_split(
        development,
        test_size=0.25,
        stratify=development["label"],
        random_state=42,
    )
    split_metrics = {
        "training": metrics_for(pipeline, train, threshold),
        "validation": metrics_for(pipeline, validation, threshold),
        "test": metrics_for(pipeline, test, threshold),
    }
    duplicate_audit = {
        "exact_duplicate_feature_rows_in_full_dataset": int(
            prepare_features(frame).duplicated(keep=False).sum()
        ),
        "train_validation_feature_hash_overlap": len(
            exact_feature_hashes(train) & exact_feature_hashes(validation)
        ),
        "train_test_feature_hash_overlap": len(
            exact_feature_hashes(train) & exact_feature_hashes(test)
        ),
    }

    folds: list[dict] = []
    splitter = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for fold_number, (development_indexes, fold_test_indexes) in enumerate(
        splitter.split(frame, labels), start=1
    ):
        fold_development = frame.iloc[development_indexes]
        fold_test = frame.iloc[fold_test_indexes]
        fold_train, fold_validation = train_test_split(
            fold_development,
            test_size=0.25,
            stratify=fold_development["label"],
            random_state=42 + fold_number,
        )
        fold_pipeline = build_pipeline(42 + fold_number)
        fold_pipeline.fit(
            prepare_features(fold_train), fold_train["label"].astype(int)
        )
        validation_probabilities = fold_pipeline.predict_proba(
            prepare_features(fold_validation)
        )[:, 1]
        fold_threshold = select_threshold(
            fold_validation["label"].to_numpy(dtype=int),
            validation_probabilities,
            minimum_recall=0.95,
        )
        fold_metrics = metrics_for(fold_pipeline, fold_test, fold_threshold)
        folds.append(
            {"fold": fold_number, "threshold": fold_threshold, **fold_metrics}
        )

    ordered = frame.assign(
        _timestamp=pd.to_datetime(frame["event_timestamp"], utc=True)
    ).sort_values("_timestamp")
    first_cut = int(len(ordered) * 0.60)
    second_cut = int(len(ordered) * 0.80)
    chronological_train = ordered.iloc[:first_cut]
    chronological_validation = ordered.iloc[first_cut:second_cut]
    chronological_test = ordered.iloc[second_cut:]
    chronological_pipeline = build_pipeline(84)
    chronological_pipeline.fit(
        prepare_features(chronological_train), chronological_train["label"].astype(int)
    )
    chronological_validation_probabilities = chronological_pipeline.predict_proba(
        prepare_features(chronological_validation)
    )[:, 1]
    chronological_threshold = select_threshold(
        chronological_validation["label"].to_numpy(dtype=int),
        chronological_validation_probabilities,
        minimum_recall=0.95,
    )
    chronological_metrics = metrics_for(
        chronological_pipeline, chronological_test, chronological_threshold
    )

    external_development_evaluation = None
    if development_data_path.exists():
        external_frame = pd.read_csv(development_data_path)
        quickstart_ids = set(frame["id"].astype(str))
        development_only = external_frame.loc[
            ~external_frame["id"].astype(str).isin(quickstart_ids)
        ].copy()
        external_development_evaluation = {
            "full_file_rows": len(external_frame),
            "overlapping_rows_removed": len(external_frame) - len(development_only),
            "development_only_rows": len(development_only),
            "development_only_metrics": metrics_for(
                pipeline, development_only, threshold
            ),
            "exact_feature_hash_overlap_with_quickstart": len(
                exact_feature_hashes(frame) & exact_feature_hashes(external_frame)
            ),
            "event_id_overlap_with_quickstart": len(
                set(frame["id"].astype(str)) & set(external_frame["id"].astype(str))
            ),
            "provenance_warning": (
                "Metrics exclude all event IDs present in quickstart. The remaining rows "
                "were generated for the same prototype and are not the official "
                "UNSW-NB15 test set."
            ),
        }

    cv_summary = {
        metric: {
            "mean": float(np.mean([fold[metric] for fold in folds])),
            "standard_deviation": float(np.std([fold[metric] for fold in folds])),
            "minimum": float(np.min([fold[metric] for fold in folds])),
            "maximum": float(np.max([fold[metric] for fold in folds])),
        }
        for metric in ("accuracy", "precision", "recall", "f1")
    }
    train_test_f1_gap = split_metrics["training"]["f1"] - split_metrics["test"]["f1"]
    audit = {
        "model_version": bundle["model_version"],
        "decision_threshold": threshold,
        "random_split_metrics": split_metrics,
        "training_minus_test_f1_gap": train_test_f1_gap,
        "duplicate_audit": duplicate_audit,
        "nested_five_fold_results": folds,
        "nested_five_fold_summary": cv_summary,
        "chronological_holdout": {
            "training_rows": len(chronological_train),
            "validation_rows": len(chronological_validation),
            "test_rows": len(chronological_test),
            "threshold": chronological_threshold,
            "metrics": chronological_metrics,
        },
        "unseen_development_file": external_development_evaluation,
        "assessment": {
            "large_train_test_gap": bool(train_test_f1_gap > 0.05),
            "unstable_cross_validation": bool(cv_summary["f1"]["standard_deviation"] > 0.05),
            "exact_train_test_duplicate_leakage_detected": bool(
                duplicate_audit["train_test_feature_hash_overlap"] > 0
            ),
            "important_limitation": (
                "Random, chronological, cross-validation, and development-only checks "
                "all use representative data from the same prototype generator. Official "
                "UNSW-NB15 test data or real deployment traffic is still required to "
                "establish external generalization."
            ),
        },
    }
    output_path.write_text(json.dumps(audit, indent=2), encoding="utf-8")
    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    main()
