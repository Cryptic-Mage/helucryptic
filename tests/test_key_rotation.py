"""Regression tests for hello key-rotation handling in WebRTCEngine._handle_hello.

Root cause being guarded: when a contact regenerates its identity, its new
signed hello no longer matches the key we pinned, so verification failed and
EVERY subsequent frame (chat AND call-control) was buffered/dropped silently -
the peer's messages showed "[decryption failed]" and incoming calls never rang.

Desired behaviour:
- UNVERIFIED (trust-on-first-use) contact re-keys  -> surface + re-pin (self-heal)
- VERIFIED contact re-keys (possible MITM)         -> alert + abort, never accept
- Garbage / tampered hello                          -> reject, no re-pin, no alert
"""
from datetime import UTC, datetime

import pytest

import crypto
import webrtc_engine


class _Settings:
    security_mode = "e2ee"
    push_to_talk_key = ""


class _FakeContact:
    def __init__(self, username, ed25519_pub, x25519_pub="", verified=False):
        self.username = username
        self.ed25519_pub = ed25519_pub
        self.x25519_pub = x25519_pub
        self.verified = verified
        self.nickname = ""
        self.fingerprint = ""


def _real_keys(tmp_path, name, monkeypatch):
    monkeypatch.setattr(crypto, "DATA_DIR", tmp_path / name)
    return crypto.generate_and_save_keys()


def _alice_engine(tmp_path, monkeypatch):
    alice = _real_keys(tmp_path, "alice", monkeypatch)
    return webrtc_engine.WebRTCEngine("alice", _Settings(), alice)


def _hello_token(signer_keys, peer_eph_pub, username, claim_ed_pub=None):
    payload = {
        "username": username,
        "x25519_pub": signer_keys["x25519_public"],
        "ed25519_pub": claim_ed_pub or signer_keys["ed25519_public"],
        "eph_x25519_pub": peer_eph_pub,
        "iat": datetime.now(UTC).isoformat(),
    }
    return crypto.paseto_sign(
        payload, signer_keys["ed25519_private"], signer_keys["ed25519_public"]
    )


@pytest.mark.asyncio
async def test_unverified_rekey_repins_and_unblocks(tmp_path, monkeypatch):
    e = _alice_engine(tmp_path, monkeypatch)
    bob_old = _real_keys(tmp_path, "bob_old", monkeypatch)   # stale pinned key
    bob_new = _real_keys(tmp_path, "bob_new", monkeypatch)   # current identity
    pinned = _FakeContact("bob", ed25519_pub=bob_old["ed25519_public"], verified=False)

    upserts = []
    changed = []
    monkeypatch.setattr(webrtc_engine, "get_contact", lambda u: pinned if u == "bob" else None)
    monkeypatch.setattr(webrtc_engine, "upsert_contact", lambda u, **kw: upserts.append((u, kw)))
    e.on_key_change = lambda p: changed.append(p)

    _, bob_eph_pub = crypto.generate_ephemeral_x25519()
    token = _hello_token(bob_new, bob_eph_pub, "bob")
    await e._handle_hello({"token": token}, "bob")

    # Frames from bob are no longer gated: session established + key derived.
    assert e._peer_hello_verified.get("bob") is True
    assert "bob" in e.session_keys
    # User was told the key changed, and the new key was re-pinned.
    assert changed == ["bob"]
    assert upserts and upserts[0][1].get("ed25519_pub") == bob_new["ed25519_public"]


@pytest.mark.asyncio
async def test_verified_rekey_alerts_and_aborts(tmp_path, monkeypatch):
    import asyncio
    e = _alice_engine(tmp_path, monkeypatch)
    bob_old = _real_keys(tmp_path, "vbob_old", monkeypatch)
    bob_new = _real_keys(tmp_path, "vbob_new", monkeypatch)
    pinned = _FakeContact("bob", ed25519_pub=bob_old["ed25519_public"], verified=True)

    changed = []
    removed = []
    monkeypatch.setattr(webrtc_engine, "get_contact", lambda u: pinned if u == "bob" else None)
    monkeypatch.setattr(webrtc_engine, "upsert_contact", lambda u, **kw: None)
    e.on_key_change = lambda p: changed.append(p)

    async def fake_remove(p):
        removed.append(p)
    monkeypatch.setattr(e, "remove_peer", fake_remove)

    _, bob_eph_pub = crypto.generate_ephemeral_x25519()
    token = _hello_token(bob_new, bob_eph_pub, "bob")
    await e._handle_hello({"token": token}, "bob")

    assert e._peer_hello_verified.get("bob") is not True   # aborted, not trusted
    assert "bob" not in e.session_keys
    assert changed == ["bob"]                              # MITM alert fired
    await asyncio.sleep(0)                                 # let the abort task run
    assert removed == ["bob"]


@pytest.mark.asyncio
async def test_tampered_hello_rejected(tmp_path, monkeypatch):
    e = _alice_engine(tmp_path, monkeypatch)
    bob_old = _real_keys(tmp_path, "tbob_old", monkeypatch)
    bob_new = _real_keys(tmp_path, "tbob_new", monkeypatch)
    pinned = _FakeContact("bob", ed25519_pub=bob_old["ed25519_public"], verified=False)

    upserts = []
    changed = []
    monkeypatch.setattr(webrtc_engine, "get_contact", lambda u: pinned if u == "bob" else None)
    monkeypatch.setattr(webrtc_engine, "upsert_contact", lambda u, **kw: upserts.append(u))
    e.on_key_change = lambda p: changed.append(p)

    # Signed with bob_new but LYING that the key is bob_old (claimed == pinned, so
    # it's not a rotation; the signature won't verify against the pinned key).
    _, bob_eph_pub = crypto.generate_ephemeral_x25519()
    token = _hello_token(bob_new, bob_eph_pub, "bob", claim_ed_pub=bob_old["ed25519_public"])
    await e._handle_hello({"token": token}, "bob")

    assert e._peer_hello_verified.get("bob") is not True
    assert "bob" not in e.session_keys
    assert changed == []      # no spurious alert
    assert upserts == []      # nothing re-pinned


@pytest.mark.asyncio
async def test_hello_iat_wildly_skewed_rejected(tmp_path, monkeypatch):
    e = _alice_engine(tmp_path, monkeypatch)
    bob_keys = _real_keys(tmp_path, "bob_skewed", monkeypatch)
    pinned = _FakeContact("bob", ed25519_pub=bob_keys["ed25519_public"], verified=False)
    monkeypatch.setattr(webrtc_engine, "get_contact", lambda u: pinned if u == "bob" else None)
    
    # Sign a token but with an old iat
    _, bob_eph_pub = crypto.generate_ephemeral_x25519()
    payload = {
        "username": "bob",
        "x25519_pub": bob_keys["x25519_public"],
        "ed25519_pub": bob_keys["ed25519_public"],
        "eph_x25519_pub": bob_eph_pub,
        "iat": "2020-01-01T00:00:00+00:00",
    }
    token = crypto.paseto_sign(
        payload, bob_keys["ed25519_private"], bob_keys["ed25519_public"]
    )
    await e._handle_hello({"token": token}, "bob")
    
    assert e._peer_hello_verified.get("bob") is not True
    assert "bob" not in e.session_keys


@pytest.mark.asyncio
async def test_hello_username_mismatch_ignored(tmp_path, monkeypatch):
    e = _alice_engine(tmp_path, monkeypatch)
    bob_keys = _real_keys(tmp_path, "bob_mismatch", monkeypatch)
    pinned = _FakeContact("bob", ed25519_pub=bob_keys["ed25519_public"], verified=False)
    monkeypatch.setattr(webrtc_engine, "get_contact", lambda u: pinned if u == "bob" else None)
    
    _, bob_eph_pub = crypto.generate_ephemeral_x25519()
    # Signed payload says username is "charlie" but signaling peer is "bob"
    payload = {
        "username": "charlie",
        "x25519_pub": bob_keys["x25519_public"],
        "ed25519_pub": bob_keys["ed25519_public"],
        "eph_x25519_pub": bob_eph_pub,
        "iat": datetime.fromtimestamp(datetime.now().timestamp(), UTC).isoformat(),
    }
    token = crypto.paseto_sign(
        payload, bob_keys["ed25519_private"], bob_keys["ed25519_public"]
    )
    await e._handle_hello({"token": token}, "bob")
    
    assert e._peer_hello_verified.get("bob") is not True
    assert "bob" not in e.session_keys


@pytest.mark.asyncio
async def test_hello_missing_ephemeral_key_rejected(tmp_path, monkeypatch):
    e = _alice_engine(tmp_path, monkeypatch)
    bob_keys = _real_keys(tmp_path, "bob_no_eph", monkeypatch)
    pinned = _FakeContact("bob", ed25519_pub=bob_keys["ed25519_public"], verified=False)
    monkeypatch.setattr(webrtc_engine, "get_contact", lambda u: pinned if u == "bob" else None)
    
    # Payload is missing "eph_x25519_pub"
    payload = {
        "username": "bob",
        "x25519_pub": bob_keys["x25519_public"],
        "ed25519_pub": bob_keys["ed25519_public"],
        "iat": datetime.fromtimestamp(datetime.now().timestamp(), UTC).isoformat(),
    }
    token = crypto.paseto_sign(
        payload, bob_keys["ed25519_private"], bob_keys["ed25519_public"]
    )
    await e._handle_hello({"token": token}, "bob")
    
    assert e._peer_hello_verified.get("bob") is not True
    assert "bob" not in e.session_keys

