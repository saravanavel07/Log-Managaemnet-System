"""
models.py — SQLite schema and lightweight DB helpers for LogSentry.

Kept dependency-free (stdlib sqlite3) so the project runs anywhere without
a database server. Swap `DB_PATH` / add a Postgres adapter here if scaling up.
"""
import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.environ.get("LOGSENTRY_DB", os.path.join(os.path.dirname(__file__), "logsentry.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,          -- e.g. auth, nginx, app
    severity TEXT NOT NULL,        -- INFO, WARNING, ERROR, CRITICAL
    event_type TEXT,               -- login_failed, login_success, sudo, http_request, etc.
    ip_address TEXT,
    user TEXT,
    message TEXT,
    raw TEXT
);

CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_logs_event_type ON logs(event_type);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    severity TEXT NOT NULL,        -- LOW, MEDIUM, HIGH, CRITICAL
    alert_type TEXT NOT NULL,      -- brute_force, priv_escalation, ml_anomaly
    source_ip TEXT,
    description TEXT,
    related_log_ids TEXT,          -- comma-separated ids for correlation trail
    status TEXT DEFAULT 'open'     -- open, acknowledged, resolved
);

CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def insert_log(conn, timestamp, source, severity, event_type, ip_address, user, message, raw):
    conn.execute(
        """INSERT INTO logs (timestamp, source, severity, event_type, ip_address, user, message, raw)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (timestamp, source, severity, event_type, ip_address, user, message, raw),
    )


def insert_alert(conn, created_at, severity, alert_type, source_ip, description, related_log_ids=""):
    conn.execute(
        """INSERT INTO alerts (created_at, severity, alert_type, source_ip, description, related_log_ids)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (created_at, severity, alert_type, source_ip, description, related_log_ids),
    )


def clear_table(conn, table):
    assert table in ("logs", "alerts")
    conn.execute(f"DELETE FROM {table}")


if __name__ == "__main__":
    init_db()
    print(f"Initialized database at {DB_PATH}")
