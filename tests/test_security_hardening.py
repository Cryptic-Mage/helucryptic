"""Tests for the security-hardening changes:

- F-02 forward secrecy: ephemeral X25519 session-key agreement
- F-03 at-rest key protection: secure_store protect/unprotect round-trip
- F-07 hello timestamp freshness
- F-09 group key only from the room creator
"""
import base64
from datetime import UTC, datetime, timedelta

import pytest

import crypto
import secure_store
import webrtc_engine

# --- F-02: ephemeral DH gives an agreed, forward-secret session key ----------

def _new_static():
    keys = crypto.generate_and_save_keys()
    return keys


def test_ephemeral_session_key_agreement(tmp_path, monkeypatch):
    monkeypatch.setattr(crypto, "DATA_DIR", tmp_path)
    a = crypto.generate_and_save_keys()
    monkeypatch.setattr(crypto, "DATA_DIR", tmp_path / "b")
    b = crypto.generate_and_save_keys()

    a_eph_priv, a_eph_pub = crypto.generate_ephemeral_x25519()
    b_eph_priv, b_eph_pub = crypto.generate_ephemeral_x25519()

    key_a = crypto.derive_session_key_v2(
        a["x25519_private"], a_eph_priv, b["x25519_public"], b_eph_pub
    )
    key_b = crypto.derive_session_key_v2(
        b["x25519_private"], b_eph_priv, a["x25519_public"], a_eph_pub
    )
    assert key_a == key_b
    assert len(key_a) == 32


def test_ephemeral_changes_key_each_session(tmp_path, monkeypatch):
    monkeypatch.setattr(crypto, "DATA_DIR", tmp_path)
    a = crypto.generate_and_save_keys()
    b_eph_priv, b_eph_pub = crypto.generate_ephemeral_x25519()
    a_eph1_priv, _ = crypto.generate_ephemeral_x25519()
    a_eph2_priv, _ = crypto.generate_ephemeral_x25519()
    # Same statics + same peer ephemeral but a different local ephemeral → a
    # different key. This is the forward-secrecy property: knowing the statics
    # is not enough to reproduce the session key.
    k1 = crypto.derive_session_key_v2(a["x25519_private"], a_eph1_priv, a["x25519_public"], b_eph_pub)
    k2 = crypto.derive_session_key_v2(a["x25519_private"], a_eph2_priv, a["x25519_public"], b_eph_pub)
    assert k1 != k2


def test_derive_session_key_v2_requires_all_args():
    with pytest.raises(ValueError):
        crypto.derive_session_key_v2("", "x", "y", "z")


# --- F-03: OS-keystore round-trip --------------------------------------------

def test_secure_store_roundtrip():
    data = b'{"x25519_private":"secret"}'
    blob = secure_store.protect(data)
    assert secure_store.unprotect(blob) == data
    if secure_store.available():
        assert secure_store.is_protected(blob)
        assert blob != data  # actually wrapped on Windows


def test_secure_store_unprotect_passthrough_plaintext():
    # Bytes without the magic header are returned untouched.
    assert secure_store.unprotect(b"not wrapped") == b"not wrapped"


def test_keys_file_wrapped_at_rest(tmp_path, monkeypatch):
    monkeypatch.setattr(crypto, "DATA_DIR", tmp_path)
    keys = crypto.generate_and_save_keys()
    raw = (tmp_path / "keys.json").read_bytes()
    if secure_store.available():
        assert secure_store.is_protected(raw)
    # Regardless of platform, it loads back to the same identity.
    loaded = crypto.load_or_create_keys()
    assert loaded["x25519_public"] == keys["x25519_public"]


# --- engine fixture ----------------------------------------------------------

class _Settings:
    security_mode = "e2ee"
    push_to_talk_key = ""


def _engine():
    keys = {
        "x25519_private": "dGVzdF94MjU1MTlfcHJpdmF0ZV9rZXk=",
        "x25519_public": "dGVzdF94MjU1MTlfcHVibGljX2tleQ==",
        "ed25519_private": "dGVzdF9lZDI1NTE5X3ByaXZhdGVfa2V5",
        "ed25519_public": "dGVzdF9lZDI1NTE5X3B1YmxpY19rZXk=",
    }
    return webrtc_engine.WebRTCEngine("alice", _Settings(), keys)


# --- F-07: hello timestamp freshness -----------------------------------------

def test_hello_iat_fresh_accepts_now():
    e = _engine()
    assert e._hello_iat_fresh(datetime.now(UTC).isoformat())


def test_hello_iat_fresh_rejects_old_and_garbage():
    e = _engine()
    old = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    assert not e._hello_iat_fresh(old)
    assert not e._hello_iat_fresh("")
    assert not e._hello_iat_fresh("not-a-date")


# --- F-09: group key only honoured from the room creator ---------------------

@pytest.mark.asyncio
async def test_group_key_rejected_from_non_creator():
    e = _engine()
    e.room_id = "ROOM"
    e._room_creator_name = "carol"            # creator is carol
    e.session_keys["mallory"] = b"0" * 32     # mallory has a session with us
    token = crypto.paseto_encrypt(
        {"group_key": base64.b64encode(b"k" * 32).decode()}, b"0" * 32
    )
    await e._handle_group_key({"token": token}, "mallory")   # not the creator
    assert e.group_key is None                # rejected


@pytest.mark.asyncio
async def test_group_key_accepted_from_creator():
    e = _engine()
    e.room_id = "ROOM"
    e._room_creator_name = "carol"
    sk = b"1" * 32
    e.session_keys["carol"] = sk
    gk = b"k" * 32
    token = crypto.paseto_encrypt({"group_key": base64.b64encode(gk).decode()}, sk)
    await e._handle_group_key({"token": token}, "carol")
    assert e.group_key == gk
