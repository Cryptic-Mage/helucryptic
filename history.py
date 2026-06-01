import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from crypto import paseto_decrypt, paseto_encrypt

from paths import DATA_DIR
_DB_PATH  = DATA_DIR / "history.db"


def _get_conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    # WAL lets the UI read while a write is in flight (no "database is locked"
    # stalls on slow disks); NORMAL sync keeps writes cheap without risking
    # corruption on crash.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    except Exception:
        pass
    return conn


def init_db() -> None:
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                contact   TEXT    NOT NULL,
                direction TEXT    NOT NULL,
                msg_type  TEXT    NOT NULL,
                content   TEXT    NOT NULL,
                filename  TEXT,
                timestamp TEXT    NOT NULL,
                verified  INTEGER NOT NULL DEFAULT 0
            )
        """)
        # Migration: add columns if they don't exist (idempotent)
        for col, typedef in [("room_id", "TEXT"), ("sender", "TEXT")]:
            try:
                conn.execute(f"ALTER TABLE messages ADD COLUMN {col} {typedef}")
            except Exception:
                pass  # column already exists
        # Indices so the per-conversation history reads don't full-scan + sort
        # the whole table (matters once history grows on an old drive).
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_msg_contact_ts "
            "ON messages (contact, timestamp DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_msg_room_ts "
            "ON messages (room_id, timestamp DESC)"
        )


def write_message(
    contact: str,
    direction: str,
    msg_type: str,
    content: str,
    history_key: bytes,
    security_mode: str,
    filename: Optional[str] = None,
    verified: bool = False,
    room_id: Optional[str] = None,
    sender: Optional[str] = None,
) -> None:
    stored = (
        paseto_encrypt({"text": content}, history_key)
        if security_mode == "e2ee"
        else content
    )
    ts = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO messages "
            "(contact, direction, msg_type, content, filename, timestamp, verified, room_id, sender) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (contact, direction, msg_type, stored, filename, ts, int(verified), room_id, sender),
        )


def read_messages(
    contact: str,
    history_key: bytes,
    security_mode: str,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM messages WHERE contact = ? AND (room_id IS NULL OR room_id = '') "
            "ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (contact, limit, offset),
        ).fetchall()
    result = []
    for row in reversed(rows):
        r = dict(row)
        if security_mode == "e2ee":
            try:
                r["content"] = paseto_decrypt(r["content"], history_key)["text"]
            except Exception:
                r["content"] = "[decryption failed]"
        result.append(r)
    return result


def read_room_messages(
    room_id: str,
    history_key: bytes,
    security_mode: str,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM messages WHERE room_id = ? "
            "ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (room_id, limit, offset),
        ).fetchall()
    result = []
    for row in reversed(rows):
        r = dict(row)
        if security_mode == "e2ee":
            try:
                r["content"] = paseto_decrypt(r["content"], history_key)["text"]
            except Exception:
                r["content"] = "[decryption failed]"
        result.append(r)
    return result


def run_retention_policy(retention_days: int) -> int:
    if retention_days == 0:
        return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    with _get_conn() as conn:
        cur = conn.execute("DELETE FROM messages WHERE timestamp < ?", (cutoff,))
        return cur.rowcount
