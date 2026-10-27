"""Discover already-stored datasets without reimporting or inventing upload history."""

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from config.dataset_mappings import AUTH_SOURCE_DATASET, NETWORK_SOURCE_DATASET
from etl.schema_detection import safe_source_name


def collect_existing_sources(incident_rows: list[dict], event_rows: list[dict], alert_rows: list[dict]) -> list[dict]:
    sources: dict[str, dict] = {}

    def entry(source):
        if not isinstance(source, str) or not source:
            return None
        return sources.setdefault(source, {"source_dataset": source, "event_count": 0,
                                           "alert_count": 0, "incident_count": 0, "event_types": []})

    for row in incident_rows:
        if (record := entry(row.get("source_dataset"))) is not None:
            record["incident_count"] = int(row["incident_count"])
    for row in event_rows:
        if (record := entry(row.get("_id"))) is not None:
            record["event_count"] = int(row["event_count"])
            record["event_types"] = row.get("event_types", [])
    for row in alert_rows:
        if (record := entry(row.get("_id"))) is not None:
            record["alert_count"] = int(row["alert_count"])
    return [sources[source] for source in sorted(sources)]


def related_csv_files(root: Path) -> dict[str, dict]:
    """Resolve only known project data folders; filenames are not original-upload claims."""
    matches = {}
    for folder in (root / "data/raw", root / "data/synthetic", root / "data/evaluation"):
        for path in sorted(folder.glob("*.csv")):
            for dataset_type in ("authentication", "network"):
                matches[safe_source_name(path.name, dataset_type)] = {
                    "filename": path.name, "related_csv_path": path.relative_to(root).as_posix(),
                    "related_csv_size": path.stat().st_size,
                }
    configured = {
        AUTH_SOURCE_DATASET: root / "data/raw/rba_authentication_events_quickstart.csv",
        NETWORK_SOURCE_DATASET: root / "data/raw/unsw_nb15_network_events_quickstart.csv",
    }
    for source, path in configured.items():
        if path.is_file():
            matches[source] = {"filename": path.name, "related_csv_path": path.relative_to(root).as_posix(),
                               "related_csv_size": path.stat().st_size}
    return matches


def register_existing_sources(database, sources: list[dict], root: Path) -> int:
    """Add source controls once, preserve preferences, and refresh observed counts."""
    collection = database.ingestion_uploads
    known_sources = {record["source_dataset"]: record for record in collection.find(
        {"source_dataset": {"$in": [source["source_dataset"] for source in sources]}},
        {"source_dataset": 1, "record_kind": 1},
    )}
    files = related_csv_files(root) if sources else {}
    created = 0
    for source in sources:
        name = source["source_dataset"]
        known = known_sources.get(name)
        if known and known.get("record_kind") != "existing_dataset":
            continue
        related = files.get(name, {})
        types = set(source["event_types"])
        dataset_type = "authentication" if types == {"authentication"} else "network" if types == {"network_flow"} else "existing source"
        record_id = "existing:" + sha256(name.encode()).hexdigest()
        result = collection.update_one({"_id": record_id}, {
            "$setOnInsert": {
                "filename": related.get("filename", f"Existing dataset · {name}"),
                "source_dataset": name, "record_kind": "existing_dataset",
                "uploaded_at": datetime.now(timezone.utc), "hidden": False,
                "status": "existing_data", "content_sha256": None, "size_bytes": None,
            },
            "$set": {"observed_counts": source, "dataset_type": dataset_type,
                      "counts_checked_at": datetime.now(timezone.utc),
                      **{key: value for key, value in related.items() if key != "filename"}},
        }, upsert=True)
        created += int(result.upserted_id is not None)
    return created
