import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from crypto import paseto_decrypt, paseto_encrypt

from paths import DATA_DIR
_DB_PATH  = DATA_DIR / "history.db"


from contextlib import contextmanager

def _connect() -> sqlite3.Connection:
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


@contextmanager
def _get_conn():
    conn = _connect()
    try:
        with conn:
            yield conn
    finally:
        conn.close()



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


# ---------------------------------------------------------------------------
# Peer-assisted history sync helpers (feature E)
# ---------------------------------------------------------------------------

def last_room_message_ts(room_id: str) -> Optional[str]:
    """The newest stored timestamp for a room, or None — our 'since' watermark."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT MAX(timestamp) AS ts FROM messages WHERE room_id = ?", (room_id,)
        ).fetchone()
    return row["ts"] if row and row["ts"] else None


def read_room_messages_since(
    room_id: str,
    since: Optional[str],
    history_key: bytes,
    security_mode: str,
    my_username: str = "",
    limit: int = 200,
) -> list[dict]:
    """Plaintext chat messages for a room newer than `since` (oldest first), for
    streaming to a peer that's catching up. Our own sent messages are attributed
    to `my_username` so the receiver knows the author. Undecryptable rows are
    skipped (never ship `[decryption failed]`)."""
    with _get_conn() as conn:
        if since:
            rows = conn.execute(
                "SELECT * FROM messages WHERE room_id = ? AND msg_type = 'chat' "
                "AND timestamp > ? ORDER BY timestamp ASC LIMIT ?",
                (room_id, since, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM messages WHERE room_id = ? AND msg_type = 'chat' "
                "ORDER BY timestamp ASC LIMIT ?",
                (room_id, limit),
            ).fetchall()
    out: list[dict] = []
    for row in rows:
        r = dict(row)
        content = r["content"]
        if security_mode == "e2ee":
            try:
                content = paseto_decrypt(content, history_key)["text"]
            except Exception:
                continue
        sender = r.get("sender") or (my_username if r.get("direction") == "sent" else "")
        out.append({
            "sender":    sender,
            "timestamp": r["timestamp"],
            "content":   content,
            "msg_type":  "chat",
        })
    return out


def read_room_message_keys(
    room_id: str,
    history_key: bytes,
    security_mode: str,
    limit: int = 2000,
) -> set:
    """A dedup set of (sender, content) for a room. Keyed on decrypted content
    (not timestamp) because the same logical message has different receive-local
    timestamps on each peer — content+sender is its stable cross-peer identity."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT content, sender FROM messages WHERE room_id = ? AND msg_type = 'chat' "
            "ORDER BY timestamp DESC LIMIT ?",
            (room_id, limit),
        ).fetchall()
    keys: set = set()
    for r in rows:
        content = r["content"]
        if security_mode == "e2ee":
            try:
                content = paseto_decrypt(content, history_key)["text"]
            except Exception:
                continue
        keys.add((r["sender"] or "", content))
    return keys


def run_retention_policy(retention_days: int) -> int:
    if retention_days == 0:
        return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    with _get_conn() as conn:
        cur = conn.execute("DELETE FROM messages WHERE timestamp < ?", (cutoff,))
        return cur.rowcount
