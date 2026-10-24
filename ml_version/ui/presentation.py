"""Consistent human-readable tabular output and response durations."""

import pandas as pd
import streamlit as st


def duration_text(seconds: float | None) -> str:
    if seconds is None:
        return "No resolved cases"
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"


def display_table(data, *, height: int = 340, empty: str = "No records match these filters.") -> None:
    frame = data.copy() if isinstance(data, pd.DataFrame) else pd.DataFrame(data)
    if frame.empty:
        st.info(empty)
        return
    configs = {}
    for column in frame.columns:
        label = column.replace("_", " ").title().replace(" Id", " ID").replace(" Ip", " IP")
        if column.endswith(("_at", "_time")) or column in {"timestamp", "event_date", "hour", "incident_date"}:
            frame[column] = pd.to_datetime(frame[column], utc=True, errors="coerce").dt.tz_localize(None)
            configs[column] = st.column_config.DatetimeColumn(label + " (UTC)", format="DD MMM YYYY, HH:mm:ss")
        elif pd.api.types.is_integer_dtype(frame[column]):
            configs[column] = st.column_config.NumberColumn(label, format="localized")
        else:
            configs[column] = label
    st.dataframe(frame, hide_index=True, width="stretch", height=height, row_height=40, column_config=configs)
