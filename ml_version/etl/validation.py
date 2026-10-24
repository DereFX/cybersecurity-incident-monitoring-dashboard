"""Reusable validation helpers for imported CSV datasets."""

from __future__ import annotations

from collections.abc import Iterable

import pandas as pd

from etl.models import ValidationReport


def validate_dataframe(
    frame: pd.DataFrame,
    *,
    source_dataset: str,
    required_columns: Iterable[str],
    timestamp_column: str,
    id_column: str,
) -> ValidationReport:
    """Validate structural requirements without silently dropping bad rows."""

    report = ValidationReport(source_dataset=source_dataset, row_count=len(frame))
    required = set(required_columns)
    missing = sorted(required - set(frame.columns))
    if missing:
        report.errors.append(f"Missing required columns: {', '.join(missing)}")
        return report

    if frame.empty:
        report.errors.append("Dataset contains no rows.")
        return report

    missing_ids = int(frame[id_column].isna().sum())
    if missing_ids:
        report.errors.append(f"{missing_ids} rows have a missing {id_column}.")

    duplicate_ids = int(frame[id_column].duplicated(keep=False).sum())
    if duplicate_ids:
        report.errors.append(f"{duplicate_ids} rows contain duplicate {id_column} values.")

    parsed = pd.to_datetime(frame[timestamp_column], errors="coerce", utc=True)
    malformed = int(parsed.isna().sum())
    if malformed:
        report.errors.append(
            f"{malformed} rows contain missing or malformed {timestamp_column} values."
        )

    return report


def clean_scalar(value: object) -> object | None:
    """Convert pandas missing/scalar values to serializable Python values."""

    if value is None or pd.isna(value):
        return None
    if hasattr(value, "item"):
        return value.item()  # NumPy scalar
    return value


def clean_record(record: dict[str, object]) -> dict[str, object | None]:
    return {key: clean_scalar(value) for key, value in record.items()}

