"""Loader for the inspected representative UNSW-NB15 flow CSV schema."""

from __future__ import annotations

from pathlib import Path
from typing import IO

import pandas as pd

from config.dataset_mappings import NETWORK_REQUIRED_COLUMNS, NETWORK_SOURCE_DATASET
from etl.models import DatasetValidationError, LoadResult, NormalizedEvent
from etl.validation import clean_record, validate_dataframe


def load_network_csv(
    path: str | Path | IO[str], *, source_dataset: str = NETWORK_SOURCE_DATASET
) -> LoadResult:
    """Validate and normalize network flows without treating labels as detections."""

    frame = pd.read_csv(path)
    report = validate_dataframe(
        frame,
        source_dataset=source_dataset,
        required_columns=NETWORK_REQUIRED_COLUMNS,
        timestamp_column="event_timestamp",
        id_column="id",
    )
    if not report.is_valid:
        raise DatasetValidationError("; ".join(report.errors))

    timestamps = pd.to_datetime(frame["event_timestamp"], utc=True)
    events: list[NormalizedEvent] = []
    for position, raw in enumerate(frame.to_dict(orient="records")):
        record = clean_record(raw)
        source_id = str(record["id"])
        events.append(
            NormalizedEvent(
                event_id=f"unsw-nb15:{source_id}",
                timestamp=timestamps.iloc[position].to_pydatetime(),
                source_dataset=source_dataset,
                event_type="network_flow",
                source_ip=str(record["source_ip"]),
                destination_ip=str(record["destination_ip"]),
                protocol=str(record["proto"]),
                attack_category=str(record["attack_cat"]),
                original_labels={"label": int(record["label"])},
                raw_event=record,
            )
        )
    return LoadResult(events=events, report=report)
