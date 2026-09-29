from __future__ import annotations

import pytest

from analytics.mongo_aggregations import failed_logins_by_user, top_source_ips


def test_top_source_ip_pipeline_has_requested_limit() -> None:
    assert top_source_ips(7)[-1] == {"$limit": 7}


def test_failed_login_pipeline_filters_generated_canonical_fields() -> None:
    match = failed_logins_by_user()[0]["$match"]
    assert match["authentication_result"] == "failure"
    assert match["event_type"] == "authentication"


def test_pipeline_rejects_invalid_limit() -> None:
    with pytest.raises(ValueError):
        top_source_ips(0)

