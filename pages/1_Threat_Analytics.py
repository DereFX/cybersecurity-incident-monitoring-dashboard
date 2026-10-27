from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from analytics.mongo_aggregations import (
    daily_event_trend,
    events_by_category,
    high_severity_alerts_by_rule,
    top_source_ips,
)
from detection.ml_network import DEFAULT_MODEL_PATH, load_model_bundle
from ui.resources import get_mongo, mysql_rows
from ui.filters import render_scope
from ui.presentation import display_table
from ui.theme import COLORS, configure_page, section_header, style_chart

configure_page("Threat Analytics", "📊")
scope = render_scope("threat")
scope_where, scope_params = scope.sql()
section_header("Detection performance", "Held-out evaluation, model explainability and observed security telemetry.", "Threat intelligence")

bundle = load_model_bundle(str(DEFAULT_MODEL_PATH.resolve()))
metrics = bundle["metadata"]["test_metrics"]
baseline = bundle["metadata"]["rule_baseline_on_same_test_split"]
metric_columns = st.columns(5)
metric_columns[0].metric("Model recall", f"{metrics['recall']:.1%}")
metric_columns[1].metric("Model precision", f"{metrics['precision']:.1%}")
metric_columns[2].metric("Model F1", f"{metrics['f1']:.1%}")
metric_columns[3].metric("False negatives", metrics["false_negatives"], f"vs {baseline['false_negatives']} rules")
metric_columns[4].metric("False positives", metrics["false_positives"], f"vs {baseline['false_positives']} rules")
st.info(
    f"Same held-out split: the original rule detector recall was {baseline['recall']:.1%} "
    f"and the trained model recall is {metrics['recall']:.1%}. Source labels were excluded from model inputs."
)

mongo = get_mongo().database
st.divider()
model_tab, telemetry_tab, incidents_tab = st.tabs(["Model evidence", "MongoDB telemetry", "Generated incidents"])

with model_tab:
    left, right = st.columns(2)
    comparison = pd.DataFrame([
        {"detector": "Trained model", "recall": metrics["recall"], "precision": metrics["precision"], "f1": metrics["f1"]},
        {"detector": "Rule baseline", "recall": baseline["recall"], "precision": baseline["precision"], "f1": baseline["f1"]},
    ]).melt(id_vars="detector", var_name="metric", value_name="score")
    comparison_chart = px.bar(comparison, x="metric", y="score", color="detector", barmode="group",
                              title="Model vs rule baseline", range_y=[0, 1.05],
                              color_discrete_map={"Trained model": COLORS["mint"], "Rule baseline": COLORS["blue"]})
    left.plotly_chart(style_chart(comparison_chart, height=370), width="stretch")
    importances = pd.DataFrame(bundle["metadata"].get("top_feature_importances", [])[:10])
    if not importances.empty:
        importances["feature"] = importances["feature"].str.replace("numeric__", "", regex=False).str.replace("categorical__", "", regex=False)
        feature_chart = px.bar(importances.sort_values("importance"), x="importance", y="feature", orientation="h",
                               title="Top model feature importance", color="importance",
                               color_continuous_scale=["#ccebe2", COLORS["mint"]])
        feature_chart.update_layout(coloraxis_showscale=False)
        right.plotly_chart(style_chart(feature_chart, height=370), width="stretch")
    cm_a, cm_b, cm_c, cm_d = st.columns(4)
    cm_a.metric("True positives", metrics["true_positives"])
    cm_b.metric("True negatives", metrics["true_negatives"])
    cm_c.metric("False positives", metrics["false_positives"])
    cm_d.metric("False negatives", metrics["false_negatives"])
    with st.expander("Evaluation scope and limitations"):
        for limitation in bundle["metadata"].get("limitations", []):
            st.markdown(f"- {limitation}")
    audit_path = Path(__file__).resolve().parents[1] / "models/overfitting_audit.json"
    with st.expander("Overfitting audit and development-only evaluation", expanded=True):
        if audit_path.exists():
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            st.caption(f"Saved audit for {audit['model_version']}. These results were loaded from the existing audit file; this page does not rerun training.")
            if audit["model_version"] != bundle["model_version"]:
                st.warning("This saved audit belongs to a different model version.")
            audit_a, audit_b, audit_c = st.columns(3)
            audit_a.metric("Training − test F1 gap", f"{audit['training_minus_test_f1_gap']:.2%}")
            audit_b.metric("Cross-validation mean recall", f"{audit['nested_five_fold_summary']['recall']['mean']:.1%}")
            audit_c.metric("Chronological recall", f"{audit['chronological_holdout']['metrics']['recall']:.1%}")
            dev = audit.get("unseen_development_file")
            if dev:
                st.write(f"Development-only evaluation: {dev['development_only_rows']:,} records, after removing {dev['overlapping_rows_removed']:,} overlapping records.")
                st.dataframe(pd.DataFrame([dev["development_only_metrics"]]), hide_index=True, width="stretch")
            st.warning(audit["assessment"]["important_limitation"])
            with st.expander("Full saved audit"):
                st.json(audit)

with telemetry_tab:
    prefix = [{"$match": scope.mongo()}]
    categories = pd.DataFrame(list(mongo.security_events.aggregate(prefix + events_by_category())))
    trends = pd.DataFrame(list(mongo.security_events.aggregate(prefix + daily_event_trend())))
    sources = pd.DataFrame(list(mongo.security_events.aggregate(prefix + top_source_ips(15))))
    high_alerts = pd.DataFrame(list(mongo.security_alerts.aggregate(prefix + high_severity_alerts_by_rule())))
    if categories.empty and trends.empty:
        st.info("No security events match the selected dates and dataset.")
    left, right = st.columns(2)
    if not categories.empty:
        categories = categories.rename(columns={"_id": "observed_category"})
        category_chart = px.bar(categories.sort_values("event_count"), x="event_count", y="observed_category", orientation="h",
                                title="Observed dataset labels", color="event_count", color_continuous_scale=["#d1eaed", COLORS["cyan"]])
        category_chart.update_layout(coloraxis_showscale=False)
        left.plotly_chart(style_chart(category_chart), width="stretch")
    if not trends.empty:
        trends = trends.rename(columns={"_id": "event_date"})
        trend_chart = px.line(trends, x="event_date", y="event_count", markers=True, title="Daily event volume")
        trend_chart.update_traces(line_color=COLORS["mint"], fill="tozeroy", fillcolor="rgba(8,127,114,.08)")
        right.plotly_chart(style_chart(trend_chart), width="stretch")
    bottom_left, bottom_right = st.columns(2)
    if not sources.empty:
        sources = sources.rename(columns={"_id": "source_ip"})
        bottom_left.markdown("#### Top source IPs")
        with bottom_left:
            display_table(sources)
    if not high_alerts.empty:
        high_alerts = high_alerts.rename(columns={"_id": "detection_rule"})
        bottom_right.markdown("#### High-severity alerts by rule")
        with bottom_right:
            display_table(high_alerts)

with incidents_tab:
    rules = pd.DataFrame(mysql_rows(f"""SELECT i.detected_by AS rule_name, i.severity, COUNT(*) incident_count
        FROM incidents i WHERE {scope_where} GROUP BY i.detected_by, i.severity ORDER BY incident_count DESC""", scope_params))
    source_summary = pd.DataFrame(mysql_rows(f"""SELECT i.source_dataset, COUNT(*) incident_count,
        SUM(i.status IN ('open','assigned','investigating')) active_count
        FROM incidents i WHERE {scope_where} GROUP BY i.source_dataset ORDER BY incident_count DESC""", scope_params))
    left, right = st.columns([1.3, .7])
    if not rules.empty:
        rules_chart = px.bar(rules, x="rule_name", y="incident_count", color="severity", title="Rule/model-generated incidents",
                             color_discrete_map={"critical": COLORS["violet"], "high": COLORS["red"], "medium": COLORS["amber"], "low": COLORS["cyan"]})
        left.plotly_chart(style_chart(rules_chart, height=390), width="stretch")
    right.markdown("#### Dataset provenance")
    with right:
        display_table(source_summary, height=330)

st.warning("Observed dataset labels are ground truth for evaluation. They are displayed separately and never presented as independently generated alerts.")
