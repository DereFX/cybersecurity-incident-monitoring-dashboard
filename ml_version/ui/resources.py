"""Cached application database resources."""

from __future__ import annotations

import streamlit as st

from config.settings import Settings
from database.mongo_connection import MongoDatabase
from database.mysql_connection import MySQLDatabase


@st.cache_resource
def get_settings() -> Settings:
    return Settings.from_env()


@st.cache_resource
def get_mysql() -> MySQLDatabase:
    return MySQLDatabase(get_settings())


@st.cache_resource
def get_mongo() -> MongoDatabase:
    mongo = MongoDatabase(get_settings())
    mongo.ensure_indexes()
    return mongo


def mysql_rows(query: str, params: tuple = ()) -> list[dict]:
    with get_mysql().connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute(query, params)
            return list(cursor.fetchall())
        finally:
            cursor.close()

