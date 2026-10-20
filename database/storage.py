import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_FILE = PROJECT_ROOT / "cloudsentry.db"


def get_connection():
    """Connect to the CloudSentry SQLite database."""
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    """Create the investigations table if it does not exist."""
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                event_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                reason TEXT NOT NULL,
                user_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )


def save_investigation(incident):
    """Save a new investigation or update an existing one."""
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO investigations (
                id, event_name, severity, reason,
                user_name, status, notes, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                notes = excluded.notes
            """,
            (
                incident["id"],
                incident["eventName"],
                incident["severity"],
                incident["reason"],
                incident["user"],
                incident["status"],
                incident["notes"],
                incident["created_at"],
            ),
        )


def load_investigations():
    """Return all saved investigations."""
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM investigations ORDER BY created_at DESC"
        ).fetchall()

    return [
        {
            "id": row["id"],
            "eventName": row["event_name"],
            "severity": row["severity"],
            "reason": row["reason"],
            "user": row["user_name"],
            "status": row["status"],
            "notes": row["notes"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]