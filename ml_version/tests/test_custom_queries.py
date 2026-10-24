"""Read-only query parsing, dataset scope and execution limits."""

from unittest.mock import MagicMock

import pytest

from analytics.custom_queries import (
    QueryInputError, compile_sql, compile_mongo, execute_sql, execute_mongo,
)
from ui.visibility import DatasetVisibility


@pytest.mark.parametrize("query", [
    "SELECT severity, COUNT(*) AS total FROM incidents GROUP BY severity",
    "SELECT incidents.incident_id FROM `incidents`",
    "SELECT i.incident_id FROM incidents i, users u WHERE i.user_id=u.user_id",
    "WITH counts AS (SELECT COUNT(*) AS n FROM incidents) SELECT * FROM counts",
    "SELECT * FROM incidents WHERE EXISTS (SELECT 1 FROM users)",
    "SELECT CASE WHEN severity='high' THEN 1 ELSE 0 END FROM incidents",
    "SELECT incident_id FROM incidents UNION ALL SELECT incident_id FROM incidents",
    "SELECT * FROM assignments a JOIN incident_audit_log l ON a.incident_id=l.incident_id",
])
def test_selects_structurally_filter_every_dataset_table(query):
    compiled, params = compile_sql(query, DatasetVisibility(("excluded_csv",)))
    assert "__soc_incidents" in compiled
    assert "__soc_users" in compiled
    assert "__soc_assignments" in compiled
    assert "__soc_incident_audit_log" in compiled
    assert params == {"__soc_excluded_0": "excluded_csv"}
    assert "LIMIT 501" in compiled
    assert "excluded_csv" not in compiled


@pytest.mark.parametrize("query", [
    "DELETE FROM incidents", "SELECT 1; SELECT 2", "SELECT * FROM other_table",
    "SELECT * FROM mysql.user", "SELECT * FROM incidents INTO OUTFILE 'x'",
    "SELECT * FROM incidents FOR UPDATE", "SELECT SLEEP(10)", "SELECT LOAD_FILE('x')",
    "SELECT unknown_udf(1)", "SELECT @variable", "SELECT @@version", "SELECT 1 INTO @x",
    "WITH RECURSIVE x AS (SELECT 1 UNION ALL SELECT 1 FROM x) SELECT * FROM x",
    "WITH incidents AS (SELECT 1) SELECT * FROM incidents",
    "SELECT * FROM __soc_incidents", "SELECT /*!50000 SLEEP(1) */ 1",
    "SELECT * FROM incidents LIMIT ?", "SELECT other.incidents.incident_id FROM incidents",
    "SELECT * FROM incidents i JOIN users i ON 1=1",
])
def test_unsafe_or_unsupported_sql_is_rejected(query):
    with pytest.raises(QueryInputError):
        compile_sql(query, DatasetVisibility(("excluded",)))


def test_sql_limits_and_parameter_binding():
    query, params = compile_sql("SELECT * FROM incidents LIMIT 9999", DatasetVisibility(("quote's", "two")))
    assert query.endswith("LIMIT 501")
    assert params["__soc_excluded_0"] == "quote's"
    assert "quote's" not in query
    assert compile_sql("SELECT * FROM incidents LIMIT 3", DatasetVisibility())[0].endswith("LIMIT 3")


def test_mongo_filter_and_pipeline_are_scoped_before_aggregation():
    visibility = DatasetVisibility(("hidden",))
    filtered = compile_mongo('{"authentication_result":"failure"}', visibility)
    assert filtered[0] == {"$match": visibility.mongo()}
    assert filtered[1] == {"$match": {"authentication_result": "failure"}}
    pipeline = compile_mongo('[{"$group":{"_id":"$severity","total":{"$sum":1}}}]', visibility)
    assert pipeline[0] == filtered[0]
    assert pipeline[-1] == {"$limit": 501}
    dated = compile_mongo('{"timestamp":{"$gte":{"$date":"2026-01-01T00:00:00Z"}}}', visibility)
    assert dated[1]["$match"]["timestamp"]["$gte"].year == 2026


@pytest.mark.parametrize("text", [
    "bad json", "42", '[{"$out":"incidents"}]', '[{"$merge":"incidents"}]',
    '[{"$lookup":{"from":"security_events"}}]', '[{"$unionWith":"security_events"}]',
    '{"$where":"return true"}', '[{"$project":{"x":{"$function":{}}}}]',
    '[{"$facet":{"bypass":[{"$unionWith":"security_events"}]}}]',
    '[{"$documents":[{}]}]', '[{"$match":{},"$sort":{}}]',
])
def test_mongo_rejects_writes_external_sources_and_javascript(text):
    with pytest.raises(QueryInputError):
        compile_mongo(text, DatasetVisibility())


def test_sql_execution_uses_readonly_transaction_and_restores_timeout():
    database = MagicMock()
    connection = database.connection.return_value.__enter__.return_value
    cursor = connection.cursor.return_value
    cursor.fetchone.return_value = {"timeout_ms": 1234}
    cursor.fetchall.return_value = [{"n": 1}]
    cursor.column_names = ("n",)
    result = execute_sql(database, "SELECT COUNT(*) AS n FROM incidents", DatasetVisibility())
    connection.start_transaction.assert_called_once_with(readonly=True)
    assert result.rows == [{"n": 1}]
    assert cursor.execute.call_args_list[-1].args == ("SET SESSION max_execution_time = %s", (1234,))
    cursor.close.assert_called_once()


def test_mongo_execution_limits_and_rejects_unknown_collection():
    database = MagicMock()
    cursor = database["security_events"].aggregate.return_value
    cursor.__enter__.return_value = iter([{"n": 1} for _ in range(501)])
    result = execute_mongo(database, "security_events", "{}", DatasetVisibility())
    assert len(result.rows) == 500 and result.truncated
    assert database["security_events"].aggregate.call_args.kwargs["maxTimeMS"] == 5000
    with pytest.raises(QueryInputError):
        execute_mongo(database, "ingestion_uploads", "{}", DatasetVisibility())
