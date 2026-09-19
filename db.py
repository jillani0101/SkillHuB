import os
import re

import psycopg2
from psycopg2.extras import RealDictCursor

DATABASE_URL = os.environ.get("DATABASE_URL", "")

_INSERT_OR_IGNORE = re.compile(r"\bINSERT\s+OR\s+IGNORE\s+INTO", re.IGNORECASE)
# `user` is a reserved word in PostgreSQL, so any use of it as a TABLE name must
# be quoted. This only fires when `user` directly follows a FROM/JOIN/INTO/UPDATE
# keyword, so it never touches the `'user'` role string or `user_id`/`user_skill`.
_USER_TABLE = re.compile(
    r"\b(FROM|JOIN|INTO|UPDATE)\s+(user)(?=\W|$)", re.IGNORECASE
)


def _translate(query):
    """Make existing SQLite-style queries run on PostgreSQL.

    - ``?`` parameter placeholders become psycopg2 ``%s`` placeholders.
    - ``INSERT OR IGNORE INTO`` becomes ``INSERT INTO ... ON CONFLICT DO NOTHING``.
    - The ``user`` table is quoted as ``"user"`` (reserved word in PostgreSQL).
    """
    if not query:
        return query
    translated, replaced = _INSERT_OR_IGNORE.subn("INSERT INTO", query)
    if replaced:
        translated = translated.rstrip() + " ON CONFLICT DO NOTHING"
    translated = translated.replace("?", "%s")
    return _USER_TABLE.sub(r'\1 "\2"', translated)


class _SkillHubCursor(RealDictCursor):
    """psycopg2 cursor that returns dict-like rows and understands SQLite syntax."""

    def execute(self, query, vars=None):
        return super().execute(_translate(query), vars)

    def executemany(self, query, vars=None):
        return super().executemany(_translate(query), vars)


def get_db_connection():
    """Open a PostgreSQL connection that returns rows as dict-like objects."""
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not set. Provide a PostgreSQL connection string "
            "(e.g. postgres://user:pass@host:5432/dbname)."
        )
    ensure_schema()
    return psycopg2.connect(DATABASE_URL, cursor_factory=_SkillHubCursor)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS "user" (
    user_id    SERIAL PRIMARY KEY,
    username   TEXT    NOT NULL UNIQUE,
    email      TEXT    NOT NULL UNIQUE,
    password   TEXT    NOT NULL,
    bio        TEXT,
    status     TEXT    DEFAULT 'active',
    is_verified INTEGER DEFAULT 0,
    role       TEXT    DEFAULT 'user',
    google_id  TEXT,
    created_at TEXT    DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS skill (
    skill_id   SERIAL PRIMARY KEY,
    skill_name TEXT    NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS user_skill (
    user_id  INTEGER,
    skill_id INTEGER,
    level    TEXT,
    PRIMARY KEY (user_id, skill_id),
    FOREIGN KEY (user_id)  REFERENCES "user"(user_id)  ON DELETE CASCADE,
    FOREIGN KEY (skill_id) REFERENCES skill(skill_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS project (
    project_id   SERIAL PRIMARY KEY,
    project_name TEXT    NOT NULL,
    description  TEXT,
    owner_id     INTEGER NOT NULL,
    status       TEXT    DEFAULT 'active',
    max_members  INTEGER,
    created_at   TEXT    DEFAULT CURRENT_TIMESTAMP,
    updated_at   TEXT    DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES "user"(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS project_skill (
    project_id INTEGER,
    skill_id   INTEGER,
    PRIMARY KEY (project_id, skill_id),
    FOREIGN KEY (project_id) REFERENCES project(project_id) ON DELETE CASCADE,
    FOREIGN KEY (skill_id)   REFERENCES skill(skill_id)     ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS application (
    application_id SERIAL PRIMARY KEY,
    user_id        INTEGER NOT NULL,
    project_id     INTEGER NOT NULL,
    status         TEXT    DEFAULT 'pending',
    note           TEXT,
    applied_at     TEXT    DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)    REFERENCES "user"(user_id)       ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES project(project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS message (
    message_id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL,
    sender_id  INTEGER NOT NULL,
    content    TEXT    NOT NULL,
    sent_at    TEXT    DEFAULT CURRENT_TIMESTAMP,
    is_read    INTEGER DEFAULT 0,
    FOREIGN KEY (project_id) REFERENCES project(project_id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id)  REFERENCES "user"(user_id)       ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification (
    notification_id SERIAL PRIMARY KEY,
    user_id         INTEGER NOT NULL,
    message         TEXT    NOT NULL,
    is_read         INTEGER DEFAULT 0,
    notif_type      TEXT    DEFAULT 'message',
    project_id      INTEGER,
    created_at      TEXT    DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)    REFERENCES "user"(user_id)       ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES project(project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS project_comment (
    comment_id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL,
    user_id    INTEGER NOT NULL,
    content    TEXT    NOT NULL,
    created_at TEXT    DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES project(project_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)    REFERENCES "user"(user_id)       ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS contact_message (
    id         SERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    email      TEXT NOT NULL,
    subject    TEXT NOT NULL,
    message    TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO skill (skill_name) VALUES
('Python'),('Java'),('C++'),('C'),('JavaScript'),('TypeScript'),('PHP'),('C#'),('Go'),('Rust'),
('HTML'),('CSS'),('React'),('Angular'),('Vue.js'),('Node.js'),('Express.js'),('Bootstrap'),
('MySQL'),('PostgreSQL'),('MongoDB'),('SQLite'),
('Machine Learning'),('Deep Learning'),('Data Analysis'),('Pandas'),('NumPy'),('TensorFlow'),('PyTorch'),
('Android Development'),('Flutter'),('React Native'),
('Git'),('GitHub'),('Docker'),('Kubernetes'),('Linux'),
('AWS'),('Azure'),('Google Cloud'),
('Ethical Hacking'),('Network Security'),('Penetration Testing'),
('Problem Solving'),('DSA'),('OOP')
ON CONFLICT (skill_name) DO NOTHING;
"""


def ensure_schema():
    """Create the tables and seed data if they do not exist yet."""
    conn = psycopg2.connect(DATABASE_URL)
    try:
        conn.cursor().execute(_SCHEMA)
        conn.commit()
    finally:
        conn.close()