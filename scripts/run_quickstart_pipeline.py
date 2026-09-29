"""Run the supplied quickstart files through the complete persistence pipeline."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from config.settings import Settings
from database.mongo_connection import MongoDatabase
from database.mysql_connection import MySQLDatabase
from etl.pipeline import run_pipeline

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    settings = Settings.from_env()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    mysql = MySQLDatabase(settings)
    mongo = MongoDatabase(settings)
    try:
        if not mysql.ping():
            raise RuntimeError("MySQL connection failed. Check .env and the MySQL service.")
        if not mongo.ping():
            raise RuntimeError("MongoDB connection failed. Check .env and the MongoDB service.")
        summary = run_pipeline(
            ROOT / "data/raw/rba_authentication_events_quickstart.csv",
            ROOT / "data/raw/unsw_nb15_network_events_quickstart.csv",
            mysql=mysql,
            mongo=mongo,
        )
        print(json.dumps(summary.to_dict(), indent=2))
    finally:
        mongo.close()


if __name__ == "__main__":
    main()

