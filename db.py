import os
import mysql.connector
from mysql.connector import pooling
from dotenv import load_dotenv

load_dotenv()

# Connection pool — created once at startup, reused across all requests.
# Adjust pool_size to match your hosting plan's DB connection limit.
_pool = pooling.MySQLConnectionPool(
    pool_name="skillhub_pool",
    pool_size=int(os.getenv("DB_POOL_SIZE", 5)),
    host=os.getenv("DB_HOST", "localhost"),
    port=int(os.getenv("DB_PORT", 3306)),
    database=os.getenv("DB_NAME", "skillcollab"),
    user=os.getenv("DB_USER", "root"),
    password=os.getenv("DB_PASSWORD", ""),
    autocommit=False,
    charset="utf8mb4",
    collation="utf8mb4_unicode_ci",
)


def get_db_connection():
    """Return a connection from the pool.
    Always call conn.close() when done — this returns it to the pool,
    it does NOT close the underlying TCP connection.
    """
    return _pool.get_connection()