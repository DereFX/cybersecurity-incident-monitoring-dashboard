"""Parsed read-only query execution over the dashboard's included datasets."""

from dataclasses import dataclass
import json
import re
from time import perf_counter

from bson import json_util
import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import traverse_scope

from ui.visibility import DatasetVisibility

MAX_ROWS = 500
MAX_QUERY_CHARS = 20000
MAX_RESULT_BYTES = 5 * 1024 * 1024
TIMEOUT_MS = 5000
SQL_TABLES = {"incidents", "users", "systems", "analysts", "threat_categories", "assignments", "incident_audit_log"}
MONGO_COLLECTIONS = {"security_events", "security_alerts"}
SAFE_FUNCTIONS = set("""EXISTS CASE COUNT SUM AVG MIN MAX COALESCE NULLIF IF IFNULL ROUND ABS CEIL FLOOR CAST TRY_CAST
CONCAT CONCAT_WS LOWER UPPER LENGTH CHAR_LENGTH TRIM LTRIM RTRIM SUBSTRING STR_POSITION REPLACE
ROW_NUMBER RANK DENSE_RANK LAG LEAD FIRST_VALUE LAST_VALUE NTILE PERCENT_RANK CUME_DIST
DATE TS_OR_DS_TO_DATE DATE_FORMAT TIME_TO_STR YEAR MONTH DAY DAY_OF_MONTH HOUR MINUTE SECOND
DATE_DIFF TIMESTAMP_DIFF DATEDIFF TIMESTAMPDIFF CURRENT_TIMESTAMP CURRENT_DATE CURRENT_TIME EXTRACT
GROUP_CONCAT FIELD JSON_EXTRACT JSON_EXTRACT_SCALAR JSON_LENGTH JSON_OBJECT JSON_ARRAY
STR_TO_TIME TIME_TO_UNIX UNIX_TO_TIME DATE_ADD DATE_SUB TIME_STR_TO_TIME
GREATEST LEAST POW POWER SQRT MOD STDDEV STDDEV_POP STDDEV_SAMP VAR_POP VAR_SAMP
ISNULL LOG LOG10 LOG2 EXP SIGN LEFT RIGHT REPEAT REVERSE LPAD RPAD
""".split())
SAFE_STAGES = {"$match", "$group", "$sort", "$project", "$limit", "$skip", "$count", "$unwind",
               "$addFields", "$set", "$unset", "$replaceRoot", "$replaceWith", "$bucket", "$bucketAuto",
               "$sortByCount", "$sample", "$facet"}
FORBIDDEN_EXPRESSIONS = {"$where", "$function", "$accumulator"}


class QueryInputError(ValueError):
    """A query cannot run under this editor's supported read-only scope."""


@dataclass
class QueryResult:
    rows: list[dict]
    elapsed_seconds: float
    truncated: bool
    executed_query: str


def compile_sql(text: str, visibility: DatasetVisibility) -> tuple[str, dict]:
    if not text.strip() or len(text) > MAX_QUERY_CHARS:
        raise QueryInputError("Enter a SQL query of 1–20,000 characters.")
    if "__soc_" in text.lower() or "/*!" in text:
        raise QueryInputError("Internal __soc_ names and executable SQL comments are not supported.")
    try:
        statements = sqlglot.parse(text, read="mysql")
    except (sqlglot.errors.ParseError, RecursionError) as error:
        raise QueryInputError("SQL could not be parsed. Check its syntax and parentheses.") from error
    if len(statements) != 1 or not isinstance(statements[0], (exp.Select, exp.Union)):
        raise QueryInputError("Enter one SELECT query. Multiple statements and data changes are not allowed.")
    tree = statements[0]
    forbidden = {"Insert", "Update", "Delete", "Create", "Drop", "Alter", "Merge", "Command", "Execute",
                 "Transaction", "Set", "Grant", "Revoke", "Use", "Into", "Lock", "Parameter", "SessionParameter",
                 "PropertyEQ", "Placeholder", "Hint"}
    nodes = list(tree.walk())
    if len(nodes) > 2000:
        raise QueryInputError("Query is too complex. Use fewer expressions or subqueries.")
    for node in nodes:
        if type(node).__name__ in forbidden:
            raise QueryInputError("Only read-only SELECT expressions are supported; variables, locks and file output are not allowed.")
        if isinstance(node, exp.With) and node.args.get("recursive"):
            raise QueryInputError("Recursive CTEs are not supported in this editor.")
        if isinstance(node, exp.CTE) and (node.alias_or_name.lower() in SQL_TABLES or node.alias_or_name.lower().startswith("__soc_")):
            raise QueryInputError("CTE names must differ from the project table names.")
        if isinstance(node, exp.Column) and (node.db or node.catalog):
            raise QueryInputError("Use table aliases, not database-qualified columns.")
        if isinstance(node, exp.Func):
            name = node.name.upper() if isinstance(node, exp.Anonymous) else node.sql_name()
            if name not in SAFE_FUNCTIONS:
                raise QueryInputError(f"Function {name} is not supported by the read-only editor.")
        node.comments = None

    base_tables = {}
    try:
        for scope in traverse_scope(tree):
            # Resolve this property explicitly: duplicate aliases otherwise overwrite
            # entries in scope.sources before table validation can see them.
            scope.selected_sources
            for source in scope.sources.values():
                if isinstance(source, exp.Table):
                    if source.db or source.catalog or source.name.lower() not in SQL_TABLES:
                        raise QueryInputError("Query only the listed project tables, without database prefixes.")
                    base_tables[id(source)] = source
    except sqlglot.errors.OptimizeError as error:
        raise QueryInputError("Table aliases could not be resolved. Check your FROM and JOIN clauses.") from error

    params = {f"__soc_excluded_{index}": source for index, source in enumerate(visibility.excluded)}
    if visibility.excluded:
        # These fixed CTEs are parsed independently. User table nodes are rewritten
        # structurally, so quoted tables, comma joins, nested queries and CTEs keep scope.
        markers = ",".join(":" + name for name in params)
        protected = sqlglot.parse_one(f"""WITH
        __soc_incidents AS (SELECT * FROM incidents WHERE source_dataset NOT IN ({markers})),
        __soc_users AS (SELECT * FROM users WHERE source_dataset NOT IN ({markers})),
        __soc_systems AS (SELECT * FROM systems WHERE source_dataset NOT IN ({markers})),
        __soc_assignments AS (SELECT a.* FROM assignments a JOIN __soc_incidents i ON i.incident_id=a.incident_id),
        __soc_incident_audit_log AS (SELECT a.* FROM incident_audit_log a JOIN __soc_incidents i ON i.incident_id=a.incident_id)
        SELECT 1""", read="mysql").args["with_"]
        for table in base_tables.values():
            original = table.name.lower()
            if original in {"analysts", "threat_categories"}:
                continue
            if not table.alias:
                table.set("alias", exp.TableAlias(this=exp.to_identifier(table.name)))
            table.set("this", exp.to_identifier("__soc_" + original))
        existing = tree.args.get("with_")
        if existing:
            protected.set("expressions", [*protected.expressions, *existing.expressions])
        tree.set("with_", protected)

    limit = tree.args.get("limit")
    if limit is not None:
        value = limit.expression
        if not isinstance(value, exp.Literal) or not value.is_int or int(value.this) < 0:
            raise QueryInputError("LIMIT must be a non-negative integer.")
        count = min(int(value.this), MAX_ROWS + 1)
    else:
        count = MAX_ROWS + 1
    tree = tree.limit(count)
    rendered = tree.sql(dialect="mysql", comments=False)
    rendered = re.sub(r":(__soc_excluded_\d+)\b", r"%(\1)s", rendered)
    return rendered, params


def execute_sql(database, text: str, visibility: DatasetVisibility) -> QueryResult:
    query, params = compile_sql(text, visibility)
    started = perf_counter()
    with database.connection() as connection:
        cursor = connection.cursor(dictionary=True)
        old_timeout = None
        try:
            cursor.execute("SELECT @@SESSION.max_execution_time AS timeout_ms")
            old_timeout = cursor.fetchone()["timeout_ms"]
            connection.rollback()
            cursor.execute(f"SET SESSION max_execution_time = {TIMEOUT_MS}")
            connection.start_transaction(readonly=True)
            cursor.execute(query, params or None)
            rows = list(cursor.fetchall())
            if len(set(cursor.column_names)) != len(cursor.column_names):
                raise QueryInputError("Result columns need unique names. Use AS aliases for duplicate column names.")
        finally:
            connection.rollback()
            if old_timeout is not None:
                cursor.execute("SET SESSION max_execution_time = %s", (old_timeout,))
            cursor.close()
    if len(json.dumps(rows, default=str).encode()) > MAX_RESULT_BYTES:
        raise QueryInputError("Results exceed 5 MB. Select fewer columns or use a narrower WHERE clause.")
    return QueryResult(rows[:MAX_ROWS], perf_counter() - started, len(rows) > MAX_ROWS, query)


def _validate_expressions(value, depth: int = 0) -> None:
    if depth > 30:
        raise QueryInputError("JSON nesting is too deep.")
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_EXPRESSIONS:
                raise QueryInputError(f"{key} is not allowed in the read-only editor.")
            _validate_expressions(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_expressions(child, depth + 1)


def _validate_stages(stages: list) -> None:
    if len(stages) > 30:
        raise QueryInputError("Use at most 30 aggregation stages per pipeline.")
    for stage in stages:
        if not isinstance(stage, dict) or len(stage) != 1:
            raise QueryInputError("Each aggregation stage must be an object with one stage name.")
        name, value = next(iter(stage.items()))
        if name not in SAFE_STAGES:
            raise QueryInputError(f"Stage {name} is not supported. Writes, collection joins and external data sources are not allowed.")
        if name == "$facet":
            if not isinstance(value, dict) or not all(isinstance(branch, list) for branch in value.values()):
                raise QueryInputError("$facet must contain named pipeline arrays.")
            for branch in value.values():
                _validate_stages(branch)


def compile_mongo(text: str, visibility: DatasetVisibility) -> list[dict]:
    if not text.strip() or len(text) > MAX_QUERY_CHARS:
        raise QueryInputError("Enter a JSON filter or pipeline of 1–20,000 characters.")
    try:
        parsed = json_util.loads(text)
    except (ValueError, TypeError, RecursionError) as error:
        raise QueryInputError("Invalid JSON. Use double-quoted keys and values; dates may use Extended JSON.") from error
    _validate_expressions(parsed)
    if isinstance(parsed, dict):
        stages = [{"$match": parsed}, {"$project": {"_id": 0, "raw_event": 0}}]
    elif isinstance(parsed, list):
        stages = parsed
    else:
        raise QueryInputError("Use a JSON object for a filter or an array for an aggregation pipeline.")
    _validate_stages(stages)
    return [{"$match": visibility.mongo()}, *stages, {"$limit": MAX_ROWS + 1}]


def execute_mongo(database, collection: str, text: str, visibility: DatasetVisibility) -> QueryResult:
    if collection not in MONGO_COLLECTIONS:
        raise QueryInputError("Choose security_events or security_alerts.")
    pipeline = compile_mongo(text, visibility)
    started = perf_counter()
    rows, size = [], 0
    with database[collection].aggregate(pipeline, maxTimeMS=TIMEOUT_MS, allowDiskUse=False, batchSize=50) as cursor:
        for document in cursor:
            size += len(json_util.dumps(document).encode())
            if size > MAX_RESULT_BYTES:
                raise QueryInputError("Results exceed 5 MB. Project fewer fields or narrow your filter.")
            rows.append(document)
    return QueryResult(rows[:MAX_ROWS], perf_counter() - started, len(rows) > MAX_ROWS,
                       json_util.dumps(pipeline, indent=2))
