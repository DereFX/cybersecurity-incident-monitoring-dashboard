"""Apply CSV inclusion preferences consistently to MongoDB and SQL reports."""

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class DatasetVisibility:
    excluded: tuple[str, ...] = ()

    def sql(self, alias: str = "i") -> tuple[str, tuple]:
        if not self.excluded:
            return "1=1", ()
        return f"{alias}.source_dataset NOT IN ({','.join(['%s'] * len(self.excluded))})", self.excluded

    def mongo(self, query: dict | None = None) -> dict:
        result = dict(query or {})
        if self.excluded:
            result["$and"] = [*result.get("$and", []), {"source_dataset": {"$nin": list(self.excluded)}}]
        return result

    def report_sql(self, query: str, params: tuple = ()) -> tuple[str, tuple]:
        """Scope only the application's curated queries before aggregating/joining."""
        if not self.excluded:
            return query, params
        placeholders = ",".join(["%s"] * len(self.excluded))
        ctes = [f"visible_{table} AS (SELECT * FROM {table} WHERE source_dataset NOT IN ({placeholders}))"
                for table in ("incidents", "users", "systems")]
        ctes.extend([
            "visible_assignments AS (SELECT a.* FROM assignments a JOIN visible_incidents i ON i.incident_id=a.incident_id)",
            "visible_incident_audit_log AS (SELECT a.* FROM incident_audit_log a JOIN visible_incidents i ON i.incident_id=a.incident_id)",
        ])
        # Input consists exclusively of the saved SQL constants in this project.
        scoped = re.sub(r"\b(FROM|JOIN)\s+(incidents|users|systems|assignments|incident_audit_log)\b",
                        lambda match: match[1] + " visible_" + match[2].lower(), query, flags=re.IGNORECASE)
        return "WITH " + ",\n".join(ctes) + "\n" + scoped, self.excluded * 3 + params


def dashboard_visibility() -> DatasetVisibility:
    from ui.resources import get_mongo

    records = get_mongo().database.ingestion_uploads.find(
        {"hidden": True}, {"source_dataset": 1, "_id": 0})
    excluded = tuple(sorted({record["source_dataset"] for record in records if record.get("source_dataset")}))
    return DatasetVisibility(excluded)
