import os
import psycopg2
import psycopg2.extras

def get_db_connection():
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    return conn
