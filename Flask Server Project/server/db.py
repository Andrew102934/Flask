import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "filedrop.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    pk_sign BLOB NOT NULL,
    pk_enc BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    nonce BLOB NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    filename TEXT NOT NULL,
    epk BLOB NOT NULL,
    nonce BLOB NOT NULL,
    signature BLOB NOT NULL,
    blob_path TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (sender) REFERENCES users(email),
    FOREIGN KEY (recipient) REFERENCES users(email)
);

CREATE INDEX IF NOT EXISTS idx_files_recipient ON files(recipient);
"""


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


@contextmanager
def db():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()