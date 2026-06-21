import os
import psycopg2
import psycopg2.extras


class DictConnection(psycopg2.extensions.connection):
    def cursor(self, *args, **kwargs):
        kwargs.pop("dictionary", None)
        kwargs.setdefault("cursor_factory", psycopg2.extras.RealDictCursor)
        return super().cursor(*args, **kwargs)


def get_db_connection():
    return psycopg2.connect(os.getenv("DATABASE_URL"), connection_factory=DictConnection)
