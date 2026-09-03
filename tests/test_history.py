import sqlite3
from datetime import UTC

import pytest

import history


@pytest.fixture(autouse=True)
def patch_history_dir(tmp_path, monkeypatch):
    # Patch both DATA_DIR and DB path
    monkeypatch.setattr(history, "DATA_DIR", tmp_path)
    monkeypatch.setattr(history, "_DB_PATH", tmp_path / "history.db")
    # Initialize database
    history.init_db()

def test_db_initialization():
    # Database file should exist
    assert history._DB_PATH.exists()

def test_db_wal_mode():
    conn = sqlite3.connect(history._DB_PATH)
    res = conn.execute("PRAGMA journal_mode").fetchone()
    assert res[0].lower() == "wal"
    conn.close()

def test_write_and_read_messages_plain():
    # Test plain text message storage (DTLS mode)
    history.write_message(
        contact="alice",
        direction="received",
        msg_type="chat",
        content="hello world",
        history_key=b"h" * 32,
        security_mode="dtls"
    )

    msgs = history.read_messages("alice", b"h" * 32, "dtls")
    assert len(msgs) == 1
    assert msgs[0]["contact"] == "alice"
    assert msgs[0]["content"] == "hello world"
    assert msgs[0]["direction"] == "received"

def test_write_and_read_messages_e2ee():
    # Test encrypted message storage (E2EE mode)
    history_key = b"h" * 32
    history.write_message(
        contact="alice",
        direction="sent",
        msg_type="chat",
        content="secret e2ee message",
        history_key=history_key,
        security_mode="e2ee"
    )

    # Read with decryption
    msgs = history.read_messages("alice", history_key, "e2ee")
    assert len(msgs) == 1
    assert msgs[0]["content"] == "secret e2ee message"

def test_write_and_read_room_messages():
    history_key = b"h" * 32
    # Write room message
    history.write_message(
        contact="room1",  # room id acts as contact ID or contact
        direction="received",
        msg_type="chat",
        content="hello room",
        history_key=history_key,
        security_mode="dtls",
        room_id="ROOM-1234",
        sender="bob"
    )

    # Reading individual history should not return room messages
    msgs_indiv = history.read_messages("room1", history_key, "dtls")
    assert len(msgs_indiv) == 0

    # Reading room history should return the message
    msgs_room = history.read_room_messages("ROOM-1234", history_key, "dtls")
    assert len(msgs_room) == 1
    assert msgs_room[0]["content"] == "hello room"
    assert msgs_room[0]["sender"] == "bob"

def test_retention_policy(monkeypatch):
    history_key = b"h" * 32
    # Write one current message
    history.write_message("alice", "sent", "chat", "new message", history_key, "dtls")

    # Write an old message by manual DB insertion or mocking timestamp
    # Let's directly insert an old record using the database connection
    conn = sqlite3.connect(history._DB_PATH)
    from datetime import datetime, timedelta
    old_ts = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    conn.execute(
        "INSERT INTO messages (contact, direction, msg_type, content, timestamp, verified) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("alice", "received", "chat", "old message", old_ts, 0)
    )
    conn.commit()
    conn.close()

    # Run retention policy for 5 days
    deleted_count = history.run_retention_policy(5)
    assert deleted_count == 1

    # Check messages remaining
    msgs = history.read_messages("alice", history_key, "dtls")
    assert len(msgs) == 1
    assert msgs[0]["content"] == "new message"
