import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "skillhub.db"))


def get_db_connection():
    """Open a SQLite connection that returns rows as dict-like objects."""
    ensure_schema()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


_SCHEMA = """
CREATE TABLE IF NOT EXISTS user (
    user_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE,
    email      TEXT    NOT NULL UNIQUE,
    password   TEXT    NOT NULL,
    bio        TEXT,
    status     TEXT    DEFAULT 'active',
    is_verified INTEGER DEFAULT 0,
    role       TEXT    DEFAULT 'user',
    google_id  TEXT,
    created_at TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS skill (
    skill_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    skill_name TEXT    NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS user_skill (
    user_id  INTEGER,
    skill_id INTEGER,
    level    TEXT,
    PRIMARY KEY (user_id, skill_id),
    FOREIGN KEY (user_id)  REFERENCES user(user_id)  ON DELETE CASCADE,
    FOREIGN KEY (skill_id) REFERENCES skill(skill_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS project (
    project_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name TEXT    NOT NULL,
    description  TEXT,
    owner_id     INTEGER NOT NULL,
    status       TEXT    DEFAULT 'active',
    max_members  INTEGER,
    created_at   TEXT    DEFAULT (datetime('now')),
    updated_at   TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (owner_id) REFERENCES user(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS project_skill (
    project_id INTEGER,
    skill_id   INTEGER,
    PRIMARY KEY (project_id, skill_id),
    FOREIGN KEY (project_id) REFERENCES project(project_id) ON DELETE CASCADE,
    FOREIGN KEY (skill_id)   REFERENCES skill(skill_id)     ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS application (
    application_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL,
    project_id     INTEGER NOT NULL,
    status         TEXT    DEFAULT 'pending',
    note           TEXT,
    applied_at     TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)    REFERENCES user(user_id)       ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES project(project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS message (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    sender_id  INTEGER NOT NULL,
    content    TEXT    NOT NULL,
    sent_at    TEXT    DEFAULT (datetime('now')),
    is_read    INTEGER DEFAULT 0,
    FOREIGN KEY (project_id) REFERENCES project(project_id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id)  REFERENCES user(user_id)       ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    message         TEXT    NOT NULL,
    is_read         INTEGER DEFAULT 0,
    notif_type      TEXT    DEFAULT 'message',
    project_id      INTEGER,
    created_at      TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)    REFERENCES user(user_id)       ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES project(project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS project_comment (
    comment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    user_id    INTEGER NOT NULL,
    content    TEXT    NOT NULL,
    created_at TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (project_id) REFERENCES project(project_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)    REFERENCES user(user_id)       ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS contact_message (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    email      TEXT NOT NULL,
    subject    TEXT NOT NULL,
    message    TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO skill (skill_name) VALUES
('Python'),('Java'),('C++'),('C'),('JavaScript'),('TypeScript'),('PHP'),('C#'),('Go'),('Rust'),
('HTML'),('CSS'),('React'),('Angular'),('Vue.js'),('Node.js'),('Express.js'),('Bootstrap'),
('MySQL'),('PostgreSQL'),('MongoDB'),('SQLite'),
('Machine Learning'),('Deep Learning'),('Data Analysis'),('Pandas'),('NumPy'),('TensorFlow'),('PyTorch'),
('Android Development'),('Flutter'),('React Native'),
('Git'),('GitHub'),('Docker'),('Kubernetes'),('Linux'),
('AWS'),('Azure'),('Google Cloud'),
('Ethical Hacking'),('Network Security'),('Penetration Testing'),
('Problem Solving'),('DSA'),('OOP');
"""


def ensure_schema():
    """Create the database file and tables if they do not exist yet."""
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        conn.executescript(_SCHEMA)
        conn.commit()
        conn.close()
        return
    # Existing database: make sure tables/columns exist without destroying data.
    conn = sqlite3.connect(DB_PATH)
    exists = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    if "user" not in exists:
        conn.executescript(_SCHEMA)
        conn.commit()
        conn.close()
        return
    cols = {r[1] for r in conn.execute("PRAGMA table_info(user)")}
    if "google_id" not in cols:
        conn.execute("ALTER TABLE user ADD COLUMN google_id TEXT")
    for table, column, ddl in (
        ("notification", "notif_type", "ALTER TABLE notification ADD COLUMN notif_type TEXT DEFAULT 'message'"),
        ("notification", "project_id", "ALTER TABLE notification ADD COLUMN project_id INTEGER"),
    ):
        cols_t = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if column not in cols_t:
            conn.execute(ddl)
    conn.commit()
    conn.close()