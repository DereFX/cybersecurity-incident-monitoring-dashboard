"""Unit tests use small, explicitly synthetic records."""

from __future__ import annotations

import pandas as pd

from etl.validation import validate_dataframe


def test_empty_dataset_is_rejected() -> None:
    frame = pd.DataFrame(columns=["event_id", "timestamp"])
    report = validate_dataframe(
        frame,
        source_dataset="synthetic_test_fixture",
        required_columns={"event_id", "timestamp"},
        timestamp_column="timestamp",
        id_column="event_id",
    )
    assert not report.is_valid
    assert "no rows" in report.errors[0]


def test_malformed_timestamp_is_rejected() -> None:
    frame = pd.DataFrame([{"event_id": "SYN-1", "timestamp": "not-a-date"}])
    report = validate_dataframe(
        frame,
        source_dataset="synthetic_test_fixture",
        required_columns={"event_id", "timestamp"},
        timestamp_column="timestamp",
        id_column="event_id",
    )
    assert not report.is_valid
    assert "malformed" in report.errors[0]


def test_missing_required_column_is_reported() -> None:
    frame = pd.DataFrame([{"event_id": "SYN-1"}])
    report = validate_dataframe(
        frame,
        source_dataset="synthetic_test_fixture",
        required_columns={"event_id", "timestamp"},
        timestamp_column="timestamp",
        id_column="event_id",
    )
    assert report.errors == ["Missing required columns: timestamp"]

