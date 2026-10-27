"""Loader for the inspected representative RBA authentication CSV schema."""

from __future__ import annotations

from pathlib import Path
from typing import IO

import pandas as pd

from config.dataset_mappings import (
    AUTH_REQUIRED_COLUMNS,
    AUTH_SOURCE_DATASET,
)
from etl.models import DatasetValidationError, LoadResult, NormalizedEvent
from etl.validation import clean_record, validate_dataframe


def load_authentication_csv(
    path: str | Path | IO[str], *, source_dataset: str = AUTH_SOURCE_DATASET
) -> LoadResult:
    """Validate and normalize authentication events from ``path``."""

    frame = pd.read_csv(path)
    return load_authentication_frame(frame, source_dataset=source_dataset)


def load_authentication_frame(
    frame: pd.DataFrame, *, source_dataset: str = AUTH_SOURCE_DATASET
) -> LoadResult:
    """Normalize a parsed CSV or Excel table through the same validation path."""
    report = validate_dataframe(
        frame,
        source_dataset=source_dataset,
        required_columns=AUTH_REQUIRED_COLUMNS,
        timestamp_column="login_timestamp",
        id_column="event_id",
    )
    if not report.is_valid:
        raise DatasetValidationError("; ".join(report.errors))

    frame = frame.copy()
    for column in ("login_successful", "is_attack_ip", "is_account_takeover"):
        def parse_boolean(value: object) -> bool:
            if isinstance(value, str):
                normalized = value.strip().lower()
                if normalized in {"true", "1"}:
                    return True
                if normalized in {"false", "0"}:
                    return False
            elif pd.notna(value) and value in (True, False, 0, 1):
                return bool(value)
            raise DatasetValidationError(f"{column} must contain true/false or 1/0 values.")
        frame[column] = frame[column].map(parse_boolean)

    timestamps = pd.to_datetime(frame["login_timestamp"], utc=True)
    events: list[NormalizedEvent] = []
    for position, raw in enumerate(frame.to_dict(orient="records")):
        record = clean_record(raw)
        successful = bool(record["login_successful"])
        events.append(
            NormalizedEvent(
                event_id=str(record["event_id"]),
                timestamp=timestamps.iloc[position].to_pydatetime(),
                source_dataset=source_dataset,
                event_type="authentication",
                source_ip=str(record["ip_address"]),
                user_id=str(record["user_id"]),
                device_id=str(record["device_id"]),
                authentication_result="success" if successful else "failure",
                original_labels={
                    "is_attack_ip": bool(record["is_attack_ip"]),
                    "is_account_takeover": bool(record["is_account_takeover"]),
                },
                raw_event=record,
            )
        )
    return LoadResult(events=events, report=report)
