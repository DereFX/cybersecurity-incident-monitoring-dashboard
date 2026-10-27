"""Live dependency checks without exposing connection credentials."""

from datetime import datetime, timezone

import streamlit as st


@st.cache_data(ttl=30, show_spinner=False)
def dependency_health() -> dict:
    from detection.ml_network import DEFAULT_MODEL_PATH, load_model_bundle
    from ui.resources import get_mongo, get_mysql

    checks = {}
    for name, check in (
        ("MySQL", lambda: get_mysql().ping()),
        ("MongoDB", lambda: get_mongo().ping()),
        ("Network model", lambda: bool(load_model_bundle(str(DEFAULT_MODEL_PATH.resolve())))),
    ):
        try:
            checks[name] = bool(check())
        except Exception:
            checks[name] = False
    return {"checks": checks, "checked_at": datetime.now(timezone.utc).isoformat()}
