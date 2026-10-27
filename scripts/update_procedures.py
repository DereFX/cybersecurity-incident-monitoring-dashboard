"""Install the project's stored procedures in the configured MySQL database."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.settings import Settings
from database.mysql_connection import MySQLDatabase
from mysql.connector import Error as MySQLError


def procedure_statements(source: str) -> list[str]:
    delimiter, buffer, statements = ";", [], []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("USE "):
            # Use the configured connection database, not a hard-coded database name.
            continue
        if stripped.upper().startswith("DELIMITER "):
            delimiter = stripped.split(maxsplit=1)[1]
            continue
        buffer.append(line)
        if stripped.endswith(delimiter):
            statements.append("\n".join(buffer).strip()[:-len(delimiter)])
            buffer = []
    if "".join(buffer).strip():
        raise ValueError("Incomplete SQL statement")
    return statements


def main() -> None:
    statements = procedure_statements((ROOT / "database/procedures.sql").read_text(encoding="utf-8"))
    database = MySQLDatabase(Settings.from_env())
    with database.connection() as connection:
        cursor = connection.cursor()
        try:
            for statement in statements:
                cursor.execute(statement)
            connection.commit()
        except MySQLError as error:
            if error.errno in {1044, 1142, 1227, 1370}:
                raise SystemExit("Stored-procedure update requires a MySQL administrator account with CREATE ROUTINE and ALTER ROUTINE privileges. Run database/procedures.sql in MySQL Workbench as an administrator. Application data has not been deleted.") from None
            raise
        finally:
            cursor.close()
    print("Updated both stored procedures in the configured MySQL database.")


if __name__ == "__main__":
    main()
