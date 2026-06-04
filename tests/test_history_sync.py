"""Tests for peer-assisted history sync helpers (feature E) in history.py."""
import time

import pytest

import history


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DATA_DIR", tmp_path)
    monkeypatch.setattr(history, "_DB_PATH", tmp_path / "history.db")
    history.init_db()
    return b"0" * 32  # history_key (any 32 bytes for e2ee round-trip)


def _write(room, direction, content, key, sender=None):
    history.write_message(room, direction, "chat", content, key, "e2ee",
                          room_id=room, sender=sender)
    time.sleep(0.002)  # ensure distinct ISO timestamps


def test_last_room_message_ts(db):
    assert history.last_room_message_ts("ROOM-AB12") is None
    _write("ROOM-AB12", "received", "hi", db, sender="alice")
    _write("ROOM-AB12", "received", "there", db, sender="alice")
    ts = history.last_room_message_ts("ROOM-AB12")
    assert ts is not None
    # newest is the watermark
    rows = history.read_room_messages("ROOM-AB12", db, "e2ee")
    assert ts == rows[-1]["timestamp"]


def test_read_since_returns_only_newer(db):
    _write("ROOM-AB12", "received", "old1", db, sender="alice")
    watermark = history.last_room_message_ts("ROOM-AB12")
    _write("ROOM-AB12", "received", "new1", db, sender="bob")
    _write("ROOM-AB12", "received", "new2", db, sender="bob")
    out = history.read_room_messages_since("ROOM-AB12", watermark, db, "e2ee", "me")
    contents = [m["content"] for m in out]
    assert contents == ["new1", "new2"]
    assert all(m["sender"] == "bob" for m in out)


def test_read_since_none_returns_all_chat(db):
    _write("ROOM-AB12", "received", "a", db, sender="alice")
    _write("ROOM-AB12", "sent", "b", db, sender=None)  # my own message
    out = history.read_room_messages_since("ROOM-AB12", None, db, "e2ee", my_username="me")
    assert [m["content"] for m in out] == ["a", "b"]
    # my sent message is attributed to my_username for the receiver
    assert out[1]["sender"] == "me"


def test_dedup_keys_use_decrypted_content(db):
    _write("ROOM-AB12", "received", "secret-text", db, sender="alice")
    keys = history.read_room_message_keys("ROOM-AB12", db, "e2ee")
    assert ("alice", "secret-text") in keys


def test_since_excludes_other_rooms_and_filetype(db):
    _write("ROOM-AB12", "received", "roomA", db, sender="alice")
    _write("ROOM-ZZ99", "received", "roomB", db, sender="bob")
    history.write_message("ROOM-AB12", "received", "file", "photo.png", db, "e2ee",
                          room_id="ROOM-AB12", sender="alice", filename="photo.png")
    out = history.read_room_messages_since("ROOM-AB12", None, db, "e2ee", "me")
    assert [m["content"] for m in out] == ["roomA"]  # other room + file excluded
