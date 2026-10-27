from datetime import date, datetime, timezone
from io import BytesIO

from detection.failed_login import detect_repeated_failed_logins
from detection.suspicious_access import detect_suspicious_access
from etl.authentication_loader import load_authentication_csv
from etl.demo_data import authentication_demo_csv
from ui.filters import AnalyticsScope
from ui.presentation import duration_text
from scripts.update_procedures import procedure_statements
from pathlib import Path


def test_scope_uses_same_exclusive_utc_end_and_provenance():
    scope = AnalyticsScope(date(2026, 10, 1), date(2026, 10, 2), "source'with quote")
    clause, params = scope.sql()
    assert "source'with quote" not in clause
    assert params == (datetime(2026, 10, 1), datetime(2026, 10, 3), "source'with quote")
    assert scope.mongo() == {"source_dataset": "source'with quote", "timestamp": {
        "$gte": datetime(2026, 10, 1, tzinfo=timezone.utc), "$lt": datetime(2026, 10, 3, tzinfo=timezone.utc)}}
    assert AnalyticsScope().sql() == ("1=1", ())
    assert AnalyticsScope().mongo() == {}


def test_guided_demo_has_two_predictable_alerts_and_a_negative_control():
    csv = authentication_demo_csv("unitfixture", datetime(2026, 10, 1, tzinfo=timezone.utc))
    events = load_authentication_csv(BytesIO(csv), source_dataset="synthetic_unit_fixture").events
    assert len(events) == 12
    alerts = detect_repeated_failed_logins(events) + detect_suspicious_access(events)
    assert len(alerts) == 2
    assert {alert.rule_name for alert in alerts} == {"repeated_failed_login", "suspicious_multi_origin_access"}
    assert not any("CONTROL" in alert.evidence.get("user_id", "") for alert in alerts)
    assert all(event.source_dataset == "synthetic_unit_fixture" for event in events)


def test_response_duration_formatting_handles_empty_zero_and_days():
    assert duration_text(None) == "No resolved cases"
    assert duration_text(0) == "0s"
    assert duration_text(3661) == "1h 1m"
    assert duration_text(90061) == "1d 1h"


def test_procedure_installer_handles_delimiters_without_changing_database():
    source = (Path(__file__).resolve().parents[1] / "database/procedures.sql").read_text(encoding="utf-8")
    statements = procedure_statements(source)
    assert len(statements) == 4
    assert sum(statement.startswith("CREATE PROCEDURE") for statement in statements) == 2
    assert all(not statement.startswith("USE ") for statement in statements)
