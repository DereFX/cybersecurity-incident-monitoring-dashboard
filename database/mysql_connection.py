"""Managed MySQL connections and transaction boundaries."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import mysql.connector
from mysql.connector import MySQLConnection
from mysql.connector.pooling import MySQLConnectionPool

from config.settings import Settings


class MySQLDatabase:
    def __init__(self, settings: Settings, *, pool_size: int = 5) -> None:
        if not settings.mysql_password:
            raise ValueError("MYSQL_PASSWORD is required for a MySQL connection.")
        self._pool = MySQLConnectionPool(
            pool_name="cyber_soc_pool",
            pool_size=pool_size,
            host=settings.mysql_host,
            port=settings.mysql_port,
            database=settings.mysql_database,
            user=settings.mysql_user,
            password=settings.mysql_password,
            connection_timeout=5,
            time_zone="+00:00",
            autocommit=False,
        )

    @contextmanager
    def connection(self) -> Iterator[MySQLConnection]:
        connection = self._pool.get_connection()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[MySQLConnection]:
        with self.connection() as connection:
            try:
                connection.start_transaction()
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def ping(self) -> bool:
        try:
            with self.connection() as connection:
                connection.ping(reconnect=False, attempts=1, delay=0)
            return True
        except mysql.connector.Error:
            return False

