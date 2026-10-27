"""Small shared presentation helpers."""

from __future__ import annotations

from html import escape

import plotly.graph_objects as go
import streamlit as st

COLORS = {
    "panel": "#eff0eb", "text": "#202b32", "muted": "#56645d",
    "mint": "#087f72", "cyan": "#329aab", "blue": "#718593",
    "amber": "#b86a09", "red": "#c93648", "violet": "#8b456a",
}


def configure_page(title: str, icon: str = "🛡️") -> None:
    st.set_page_config(page_title=title, page_icon=icon, layout="wide")
    st.markdown(
        """
        <style>
        .stApp {
            background: #e3e7e3; color: #202b32;
        }
        [data-testid="stHeader"] { background: rgba(227,231,227,.95); }
        [data-testid="stSidebar"] {
            background: #d9e1db;
            border-right: 1px solid #e4ebe8;
        }
        [data-testid="stSidebarNav"] { display: none; }
        .block-container { max-width: 1560px; padding: 3.5rem 2.4rem 4rem; }
        .soc-header {
            display: flex; align-items: center; justify-content: space-between; gap:1rem;
            padding: .5rem 0 1.4rem; margin-bottom: 1.4rem;
            border-bottom: 1px solid #dfe7e3;
        }
        .soc-eyebrow { color: #087f72; font-size: .66rem; font-weight: 800;
            letter-spacing: .18em; text-transform: uppercase; margin-bottom: .35rem; }
        .soc-title { color: #202b32; font-size: 1.85rem; line-height: 1.15;
            font-weight: 750; letter-spacing: -.025em; }
        .soc-subtitle { color: #627078; margin-top: .45rem; font-size: .86rem; }
        .soc-live { color: #087f72; border: 1px solid #b9dfd5;
            background: #e9f5ef; padding: .5rem .8rem;
            border-radius: 999px; font-size: .72rem; font-weight: 800;
            letter-spacing: .08em; white-space: nowrap; }
        .soc-live:before { content:""; display:inline-block; width:7px; height:7px;
            margin-right:7px; border-radius:50%; background:#087f72; }
        .soc-live.degraded { color:#965500; background:#fff4df; border-color:#ecd2a1; }
        .soc-live.degraded:before { background:#b86a09; }
        .section-kicker { color:#087f72; text-transform:uppercase; letter-spacing:.14em;
            font-size:.65rem; font-weight:800; margin-bottom:.28rem; }
        .section-title { color:#202b32; font-size:1.2rem; font-weight:730; }
        .section-copy { color:#627078; font-size:.84rem; margin:.35rem 0 1.15rem; }
        .glass-card { border:1px solid #e2eae6; border-radius:14px;
            background:#eff0eb;
            padding:1.15rem; box-shadow:0 3px 12px rgba(32,43,50,.035); }
        .status-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:.7rem;
            margin:.2rem 0 1.15rem; }
        .status-item { border:1px solid #e2eae6; border-radius:12px;
            padding:.95rem 1rem; background:#eff0eb; }
        .status-label { color:#627078; font-size:.68rem; text-transform:uppercase;
            letter-spacing:.1em; }
        .status-value { color:#202b32; font-size:1.12rem; font-weight:730; margin-top:.35rem; }
        .status-detail { color:#627078; font-size:.75rem; margin-top:.2rem; }
        .rubric-card { min-height:170px; border:1px solid #e2eae6;
            border-radius:14px; background:#eff0eb; margin-bottom:.8rem;
            padding:1.2rem; }
        .rubric-score { float:right; color:#087f72; background:#e9f5ef; padding:.2rem .45rem;
            border-radius:6px; font-weight:800; font-size:.75rem; margin-left:.6rem; }
        .rubric-name { color:#202b32; font-weight:720; margin-bottom:.7rem; }
        .rubric-evidence { color:#627078; font-size:.83rem; line-height:1.6; }
        .requirement-row { display:flex; gap:.7rem; align-items:flex-start; padding:.68rem .1rem;
            border-bottom:1px solid #e2eae6; }
        .requirement-check { color:#087f72; font-weight:900; }
        .requirement-title { color:#202b32; font-weight:680; font-size:.88rem; }
        .requirement-detail { color:#627078; font-size:.81rem; margin-top:.25rem; }
        [data-testid="stMetric"] {
            background: #eff0eb; border:1px solid #cbd4cd;
            padding: 1.15rem 1.1rem; border-radius: 14px;
            box-shadow: 0 3px 12px rgba(32,43,50,.035);
        }
        [data-testid="stMetricLabel"] { color: #627078; font-size:.8rem; }
        [data-testid="stMetricValue"] { color: #202b32; font-size:2rem; font-weight:750; }
        [data-testid="stMetricDelta"] { color:#627078; font-size:.72rem; }
        [data-testid="stMetricDelta"] svg { display:none; }
        [data-testid="stDataFrame"], [data-testid="stFileUploader"] {
            border: 1px solid #e2eae6; border-radius: 12px;
            overflow: hidden;
        }
        div[data-testid="stForm"] {
            background: #eff0eb; border: 1px solid #cbd4cd;
            border-radius: 16px; padding: 1.15rem;
        }
        .stButton > button, .stFormSubmitButton > button {
            border: 1px solid #cddbd5; border-radius: 9px;
            font-weight: 700;
        }
        .stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {
            background: #087f72; color: white; border-color:#087f72;
        }
        h2, h3 { letter-spacing: -.015em; }
        hr { border-color: #e2eae6; margin:1.8rem 0; }
        div[data-baseweb="tab-list"], [data-testid="stTabs"] [role="tablist"] { gap:.4rem; background:#eaf0ed;
            border-radius:10px; padding:.3rem; }
        button[data-baseweb="tab"], [data-testid="stTabs"] [role="tab"] { border-radius:8px; padding:.42rem .8rem; }
        button[data-baseweb="tab"][aria-selected="true"], [data-testid="stTabs"] [role="tab"][aria-selected="true"] { background:#eff0eb; color:#087f72;
            box-shadow:0 2px 5px rgba(32,43,50,.07); }
        [data-testid="stPlotlyChart"] { background:#eff0eb; border:1px solid #cbd4cd;
            border-radius:14px; padding:.3rem; margin:.6rem 0; }
        [data-testid="stSidebar"] [data-testid="stPageLink-NavLink"] { border-radius:9px; padding:.6rem .75rem; }
        [data-testid="stSidebar"] [data-testid="stPageLink-NavLink"][aria-current="page"] {
            color:#087f72; background:#e9f5ef; font-weight:700; }
        .soc-brand { color:#202b32; font-size:1.3rem; font-weight:800; letter-spacing:-.04em; }
        .soc-brand span { color:#087f72; }
        .severity-badge { display:inline-block; padding:.25rem .65rem; border-radius:999px;
            font-size:.75rem; font-weight:750; border:1px solid currentColor; }
        .case-summary { background:#eff0eb; border:1px solid #cbd4cd; border-left:3px solid #087f72;
            border-radius:12px; padding:1.1rem 1.2rem; margin:1rem 0; color:#202b32; }
        .pipeline-flow { display: grid; grid-template-columns: repeat(5, 1fr);
            gap: .65rem; align-items: stretch; margin: 1rem 0 1.25rem; }
        .pipeline-step { background: #eff0eb;
            border: 1px solid #e2eae6; border-radius: 12px;
            padding: .85rem; min-height: 88px; }
        .pipeline-step strong { display: block; color: #202b32; margin-bottom: .45rem; }
        .pipeline-step span { color: #627078; font-size: .8rem; line-height: 1.5; }
        .pipeline-step.done { border-top: 2px solid #087f72; }
        .storage-proof { color: #087f72; font-size: .72rem; font-weight: 800;
            letter-spacing: .08em; text-transform: uppercase; margin-top: .5rem; }
        @media (max-width: 1200px) {
            .pipeline-flow, .status-grid { grid-template-columns: 1fr 1fr; }
        }
        @media (max-width: 900px) {
            .soc-live { display: none; }
            .block-container { padding: 3.5rem 1rem 2rem; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.sidebar.markdown('<div class="soc-brand">cyber<span>soc.</span></div>', unsafe_allow_html=True)
    st.sidebar.caption("Intelligence · Detection · Response")
    st.sidebar.markdown("#### Operations")
    st.sidebar.page_link("app.py", label="Command Center", icon="📡")
    st.sidebar.page_link("pages/1_Threat_Analytics.py", label="Threat Analytics", icon="📊")
    st.sidebar.page_link("pages/2_User_Device_Monitoring.py", label="Identity Monitoring", icon="👤")
    st.sidebar.page_link("pages/3_Incident_Management.py", label="Incident Response", icon="🚨")
    st.sidebar.markdown("#### Data & evidence")
    st.sidebar.page_link("pages/4_Data_Ingestion.py", label="Data Pipeline", icon="📥")
    st.sidebar.page_link("pages/5_Project_Evidence.py", label="Rubric & Evidence", icon="🎓")
    st.sidebar.page_link("pages/6_Database_Explorer.py", label="Database Explorer", icon="🗄️")
    from ui.health import dependency_health

    if st.sidebar.button("Refresh live data", width="stretch"):
        from ui.filters import filter_catalog
        from ui.existing_sources import existing_source_counts
        existing_source_counts.clear()
        filter_catalog.clear()
        dependency_health.clear()
        st.rerun()
    health = dependency_health()
    all_online = all(health["checks"].values())
    health_label = "SYSTEM ONLINE" if all_online else "SERVICE DEGRADED"
    for service, online in health["checks"].items():
        st.sidebar.caption(f"{'🟢' if online else '🔴'} {service}: {'available' if online else 'unavailable'}")
    st.sidebar.caption(f"Checked: {health['checked_at'][11:19]} UTC · cached for 30s")
    st.sidebar.divider()
    st.sidebar.caption("SDG 9 · Industry & Innovation")
    st.sidebar.caption("SDG 16 · Peace, Justice & Institutions")
    st.markdown(
        f"""
        <div class="soc-header">
          <div>
            <div class="soc-eyebrow">Security Operations Center</div>
            <div class="soc-title">{escape(title)}</div>
            <div class="soc-subtitle">Cybersecurity Incident Monitoring &amp; ML Threat Analytics</div>
          </div>
          <div class="soc-live {'degraded' if not all_online else ''}">{health_label}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_header(title: str, description: str = "", kicker: str = "Intelligence") -> None:
    st.markdown(
        f'<div class="section-kicker">{escape(kicker)}</div>'
        f'<div class="section-title">{escape(title)}</div>'
        f'<div class="section-copy">{escape(description)}</div>',
        unsafe_allow_html=True,
    )


def style_chart(figure: go.Figure, *, height: int = 350) -> go.Figure:
    figure.update_layout(
        template="plotly_white",
        height=height, margin=dict(l=20, r=20, t=48, b=20),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=COLORS["muted"], family="Inter, Segoe UI, sans-serif"),
        title_font=dict(color=COLORS["text"], size=15),
        legend=dict(bgcolor="rgba(0,0,0,0)", orientation="h", y=-.2, x=0),
        hoverlabel=dict(bgcolor="#eff0eb", bordercolor="#cbd4cd", font_color=COLORS["text"]),
        colorway=[COLORS["mint"], COLORS["cyan"], COLORS["blue"], COLORS["violet"], COLORS["amber"]],
        modebar=dict(bgcolor="rgba(0,0,0,0)", color="#84928b", activecolor=COLORS["mint"]),
    )
    figure.update_xaxes(gridcolor="#d9dfd8", zeroline=False, title_font_size=12)
    figure.update_yaxes(gridcolor="#d9dfd8", zeroline=False, title_font_size=12)
    figure.for_each_trace(lambda trace: trace.update(marker_line_width=0) if trace.type == "bar" else None)
    for axis in (figure.layout.xaxis, figure.layout.yaxis):
        if axis.title.text:
            axis.title.text = axis.title.text.replace("_", " ").capitalize()
    return figure


def incident_table(frame, *, height: int = 360) -> None:
    """Readable incident table with consistent severity chips and red priority IDs."""
    severity_colors = {
        "critical": ("#8b2046", "#fce7ef"), "high": ("#b42538", "#fdecef"),
        "medium": ("#8c5206", "#fff3dc"), "low": ("#087065", "#e8f5ef"),
    }

    def style_row(row):
        foreground, background = severity_colors.get(str(row.get("severity", "")).lower(), ("#627078", "#f4f7f6"))
        return [f"color:{foreground};background-color:{background};font-weight:700" if column == "severity"
                else "color:#b42538;font-weight:750" if column == "incident_id" and str(row.get("severity", "")).lower() in {"high", "critical"}
                else "" for column in frame.columns]

    labels = {name: name.replace("_", " ").title().replace(" Id", " ID") for name in frame.columns}
    for name in frame.columns:
        if name.endswith(("_time", "_at")):
            labels[name] = st.column_config.DatetimeColumn(labels[name] + " (UTC)", format="DD MMM YYYY, HH:mm:ss")
    st.dataframe(frame.style.apply(style_row, axis=1), width="stretch", hide_index=True,
                 height=height, row_height=42, column_config=labels)


def severity_badge(severity: str) -> str:
    """Escaped HTML badge for the incident details header."""
    colors = {"critical": ("#8b2046", "#fce7ef"), "high": ("#b42538", "#fdecef"),
              "medium": ("#8c5206", "#fff3dc"), "low": ("#087065", "#e8f5ef")}
    foreground, background = colors.get(severity.lower(), ("#627078", "#f4f7f6"))
    return f'<span class="severity-badge" style="color:{foreground};background:{background}">{escape(severity.title())}</span>'
