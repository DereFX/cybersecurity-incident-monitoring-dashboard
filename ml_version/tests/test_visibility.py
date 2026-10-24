from analytics import sql_queries
from ui.filters import AnalyticsScope
from ui.visibility import DatasetVisibility


def test_exclusion_overrides_an_explicit_dataset_selection():
    scope = AnalyticsScope(dataset="excluded_csv", excluded=("excluded_csv",))
    clause, params = scope.sql()
    assert "source_dataset = %s" in clause and "source_dataset NOT IN (%s)" in clause
    assert params == ("excluded_csv", "excluded_csv")
    assert scope.mongo() == {"source_dataset": "excluded_csv", "$and": [{"source_dataset": {"$nin": ["excluded_csv"]}}]}


def test_mongo_visibility_preserves_existing_filters():
    base = {"event_type": "authentication", "$and": [{"user_id": "SYNTHETIC"}]}
    match = DatasetVisibility(("excluded_csv",)).mongo(base)
    assert len(match["$and"]) == 2
    assert len(base["$and"]) == 1
    assert match["event_type"] == "authentication"


def test_curated_sql_is_filtered_before_nested_aggregations():
    policy = DatasetVisibility(("synthetic'quoted",))
    query, params = policy.report_sql(sql_queries.USERS_ABOVE_AVERAGE_INCIDENT_COUNT)
    assert "FROM visible_incidents" in query
    assert "JOIN visible_incidents" in query
    assert "synthetic'quoted" not in query
    assert params == ("synthetic'quoted",) * 3
    count_query, _ = policy.report_sql("SELECT (SELECT COUNT(*) FROM users) users")
    assert "FROM visible_users) users" in count_query


def test_unrestricted_queries_remain_unchanged():
    query = sql_queries.INCIDENT_COUNTS_BY_CATEGORY_SEVERITY
    assert DatasetVisibility().report_sql(query, (2,)) == (query, (2,))
