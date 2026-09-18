"""
Creates / upgrades the SQLite database used by the app.

Run this once (optional — the app also initializes the schema
automatically the first time it starts):

    python init_db.py
"""
from db import DB_PATH, ensure_schema


def init_db():
    ensure_schema()
    print(f"Database ready at: {DB_PATH}")


if __name__ == "__main__":
    init_db()