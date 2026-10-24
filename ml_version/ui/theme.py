"""Small shared presentation helpers."""

from __future__ import annotations

import streamlit as st


def configure_page(title: str, icon: str = "🛡️") -> None:
    st.set_page_config(page_title=title, page_icon=icon, layout="wide")
    st.markdown(
        """
        <style>
        .stApp {
            background:
                radial-gradient(circle at 85% -10%, rgba(34,211,167,.13), transparent 34rem),
                radial-gradient(circle at 5% 15%, rgba(56,189,248,.08), transparent 28rem),
                #07111f;
        }
        [data-testid="stHeader"] { background: rgba(7,17,31,.72); }
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #091727 0%, #07111f 100%);
            border-right: 1px solid rgba(148,163,184,.14);
        }
        .block-container { max-width: 1450px; padding-top: 2rem; padding-bottom: 4rem; }
        .soc-header {
            display: flex; align-items: flex-end; justify-content: space-between;
            padding: 1.15rem 1.35rem; margin-bottom: 1.5rem;
            border: 1px solid rgba(148,163,184,.16); border-radius: 18px;
            background: linear-gradient(135deg, rgba(13,27,45,.96), rgba(9,23,39,.78));
            box-shadow: 0 18px 50px rgba(0,0,0,.20);
        }
        .soc-eyebrow { color: #22d3a7; font-size: .72rem; font-weight: 800;
            letter-spacing: .18em; text-transform: uppercase; margin-bottom: .35rem; }
        .soc-title { color: #f5f8fb; font-size: 2rem; line-height: 1.1;
            font-weight: 750; letter-spacing: -.025em; }
        .soc-subtitle { color: #91a4b7; margin-top: .45rem; font-size: .92rem; }
        .soc-live { color: #79f2c8; border: 1px solid rgba(34,211,167,.35);
            background: rgba(34,211,167,.08); padding: .42rem .72rem;
            border-radius: 999px; font-size: .72rem; font-weight: 800;
            letter-spacing: .08em; white-space: nowrap; }
        [data-testid="stMetric"] {
            background: linear-gradient(160deg, rgba(15,32,52,.96), rgba(10,24,40,.92));
            border: 1px solid rgba(148,163,184,.14); border-top: 2px solid #22d3a7;
            padding: 1rem 1.05rem; border-radius: 14px;
            box-shadow: 0 12px 30px rgba(0,0,0,.16);
        }
        [data-testid="stMetricLabel"] { color: #93a7bb; }
        [data-testid="stMetricValue"] { color: #f4f8fb; }
        [data-testid="stDataFrame"], [data-testid="stFileUploader"] {
            border: 1px solid rgba(148,163,184,.14); border-radius: 14px;
            overflow: hidden;
        }
        div[data-testid="stForm"] {
            background: rgba(13,27,45,.62); border: 1px solid rgba(148,163,184,.14);
            border-radius: 16px; padding: 1.15rem;
        }
        .stButton > button, .stFormSubmitButton > button {
            border: 1px solid rgba(34,211,167,.55); border-radius: 10px;
            font-weight: 700;
        }
        .stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {
            background: linear-gradient(90deg, #0d9f82, #16b79a); color: white;
        }
        h2, h3 { letter-spacing: -.015em; }
        hr { border-color: rgba(148,163,184,.12); }
        .pipeline-flow { display: grid; grid-template-columns: repeat(5, 1fr);
            gap: .65rem; align-items: stretch; margin: 1rem 0 1.25rem; }
        .pipeline-step { background: rgba(13,27,45,.72);
            border: 1px solid rgba(148,163,184,.14); border-radius: 12px;
            padding: .85rem; min-height: 88px; }
        .pipeline-step strong { display: block; color: #eaf4f8; margin-bottom: .3rem; }
        .pipeline-step span { color: #8fa5b8; font-size: .8rem; line-height: 1.3; }
        .pipeline-step.done { border-top: 2px solid #22d3a7; }
        .storage-proof { color: #79f2c8; font-size: .72rem; font-weight: 800;
            letter-spacing: .08em; text-transform: uppercase; margin-top: .5rem; }
        @media (max-width: 900px) {
            .pipeline-flow { grid-template-columns: 1fr; }
            .soc-live { display: none; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.sidebar.markdown("### 🛡️ CYBER SOC")
    st.sidebar.caption("Monitor · Detect · Respond")
    st.sidebar.divider()
    st.markdown(
        f"""
        <div class="soc-header">
          <div>
            <div class="soc-eyebrow">Security Operations Center</div>
            <div class="soc-title">{title}</div>
            <div class="soc-subtitle">Cybersecurity Incident Monitoring &amp; ML Threat Analytics</div>
          </div>
          <div class="soc-live">● SYSTEM ONLINE</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
