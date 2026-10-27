"""Shared UTC date and provenance filters for operational views."""

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone

import streamlit as st
from ui.visibility import DatasetVisibility, dashboard_visibility

@dataclass(frozen=True)
class AnalyticsScope:
    start: date | None = None
    end: date | None = None
    dataset: str | None = None
    excluded: tuple[str, ...] = ()

    def sql(self, alias: str = "i") -> tuple[str, tuple]:
        clauses, params = [], []
        if self.start and self.end:
            clauses.extend([f"{alias}.incident_time >= %s", f"{alias}.incident_time < %s"])
            params.extend([datetime.combine(self.start, time.min), datetime.combine(self.end + timedelta(days=1), time.min)])
        if self.dataset:
            clauses.append(f"{alias}.source_dataset = %s")
            params.append(self.dataset)
        if self.excluded:
            visibility_sql, visibility_params = DatasetVisibility(self.excluded).sql(alias)
            clauses.append(visibility_sql)
            params.extend(visibility_params)
        return " AND ".join(clauses) or "1=1", tuple(params)

    def mongo(self) -> dict:
        match = {}
        if self.start and self.end:
            match["timestamp"] = {"$gte": datetime.combine(self.start, time.min, timezone.utc),
                                  "$lt": datetime.combine(self.end + timedelta(days=1), time.min, timezone.utc)}
        if self.dataset:
            match["source_dataset"] = self.dataset
        return DatasetVisibility(self.excluded).mongo(match)


@st.cache_data(ttl=30, show_spinner=False)
def filter_catalog(excluded: tuple[str, ...] = ()) -> dict:
    from ui.resources import get_mongo, mysql_rows

    visibility = DatasetVisibility(excluded)
    clause, params = visibility.sql("i")
    bounds = mysql_rows(f"SELECT MIN(DATE(incident_time)) first_day, MAX(DATE(incident_time)) last_day FROM incidents i WHERE {clause}", params)[0]
    sources = {row["source_dataset"] for row in mysql_rows(f"SELECT DISTINCT source_dataset FROM incidents i WHERE {clause}", params)}
    dates = [value for value in bounds.values() if isinstance(value, date)]
    try:
        collection = get_mongo().database.security_events
        sources.update(source for source in collection.distinct("source_dataset", visibility.mongo()) if isinstance(source, str))
        for summary in collection.aggregate([{"$match": visibility.mongo()}, {"$group": {"_id": None, "first": {"$min": "$timestamp"}, "last": {"$max": "$timestamp"}}}]):
            dates.extend(value.date() for name, value in summary.items() if name != "_id" and isinstance(value, datetime))
    except Exception:
        # MySQL dates remain usable when the event store is unavailable.
        pass
    return {"datasets": sorted(sources - set(excluded)), "first": min(dates) if dates else date.today(), "last": max(dates) if dates else date.today()}


def render_scope(page: str) -> AnalyticsScope:
    visibility = dashboard_visibility()
    catalog = filter_catalog(visibility.excluded)
    saved = st.session_state.get("analytics_scope", {})
    with st.expander("Date & dataset filters", expanded=False):
        left, right = st.columns(2)
        options = ["All datasets", *catalog["datasets"]]
        chosen = saved.get("dataset") if saved.get("dataset") in options else "All datasets"
        dataset = left.selectbox("Source dataset", options, index=options.index(chosen), key=f"{page}_source")
        limited = right.checkbox("Limit date range", value=saved.get("limited", False), key=f"{page}_limited")
        dates = st.date_input("Event / incident dates (UTC)", value=saved.get("dates", (catalog["first"], catalog["last"])), key=f"{page}_dates", disabled=not limited)
        st.caption("These filters follow you between operational pages. Model evaluation scores use their saved test split.")
    if limited and len(dates) != 2:
        st.info("Choose both a start and an end date.")
        st.stop()
    st.session_state["analytics_scope"] = {"dataset": dataset, "limited": limited, "dates": dates}
    scope = AnalyticsScope(dates[0], dates[1], None if dataset == "All datasets" else dataset, visibility.excluded) if limited else AnalyticsScope(dataset=None if dataset == "All datasets" else dataset, excluded=visibility.excluded)
    st.caption(f"Showing: {dataset} · {scope.start.isoformat() + ' to ' + scope.end.isoformat() if scope.start else 'all dates'} · timestamps in UTC")
    if visibility.excluded:
        st.caption(f"{len(visibility.excluded)} dataset source(s) excluded. Manage inclusion on Data Pipeline.")
    return scope
