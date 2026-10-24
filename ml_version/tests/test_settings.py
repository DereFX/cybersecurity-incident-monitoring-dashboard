from __future__ import annotations

import pytest

from config.settings import Settings
from database.mysql_connection import MySQLDatabase


def test_settings_have_safe_local_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MYSQL_PASSWORD", raising=False)
    monkeypatch.delenv("MONGODB_URI", raising=False)
    settings = Settings.from_env()
    assert settings.mysql_database == "cyber_soc"
    assert settings.mongodb_database == "cyber_soc"


def test_mysql_requires_password_before_connection() -> None:
    settings = Settings(
        mysql_host="localhost",
        mysql_port=3306,
        mysql_database="cyber_soc",
        mysql_user="test",
        mysql_password="",
        mongodb_uri="mongodb://localhost:27017",
        mongodb_database="cyber_soc",
        log_level="INFO",
    )
    with pytest.raises(ValueError, match="MYSQL_PASSWORD"):
        MySQLDatabase(settings)

