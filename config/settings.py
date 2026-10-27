"""Environment-backed application settings."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True, slots=True)
class Settings:
    mysql_host: str
    mysql_port: int
    mysql_database: str
    mysql_user: str
    mysql_password: str
    mongodb_uri: str
    mongodb_database: str
    log_level: str

    @classmethod
    def from_env(cls) -> "Settings":
        project_root = Path(__file__).resolve().parents[1]
        load_dotenv(project_root / ".env")
        return cls(
            mysql_host=os.getenv("MYSQL_HOST", "localhost"),
            mysql_port=int(os.getenv("MYSQL_PORT", "3306")),
            mysql_database=os.getenv("MYSQL_DATABASE", "cyber_soc"),
            mysql_user=os.getenv("MYSQL_USER", "cyber_soc_app"),
            mysql_password=os.getenv("MYSQL_PASSWORD", ""),
            mongodb_uri=os.getenv("MONGODB_URI", "mongodb://localhost:27017"),
            mongodb_database=os.getenv("MONGODB_DATABASE", "cyber_soc"),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        )
