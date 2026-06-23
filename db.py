import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "skillhub.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # rows behave like dicts: row["column_name"]
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
