"""Tests for PSK channel authentication (feature C) in WebRTCEngine."""
import base64
import json
import os

import pytest

import invites
import webrtc_engine


class _Settings:
    security_mode = "e2ee"
    push_to_talk_key = ""


_KEYS = {
    "x25519_private": "dGVzdF94MjU1MTlfcHJpdmF0ZV9rZXk=",
    "x25519_public": "dGVzdF94MjU1MTlfcHVibGljX2tleQ==",
    "ed25519_private": "dGVzdF9lZDI1NTE5X3ByaXZhdGVfa2V5",
    "ed25519_public": "dGVzdF9lZDI1NTE5X3B1YmxpY19rZXk=",
}


def _engine(name, psk, room="ROOM-AB12"):
    e = webrtc_engine.WebRTCEngine(name, _Settings(), _KEYS)
    e.room_id = room
    e.set_room_psk(psk)
    return e


def test_proof_is_symmetric_for_same_psk_and_room():
    psk = invites.generate_psk()
    a = _engine("alice", psk)
    b = _engine("bob", psk)
    nonce = base64.b64encode(os.urandom(16)).decode()
    assert a._psk_proof(nonce) == b._psk_proof(nonce)


def test_proof_differs_for_wrong_psk():
    nonce = "NONCE"
    a = _engine("alice", invites.generate_psk())
    c = _engine("carol", invites.generate_psk())
    assert a._psk_proof(nonce) != c._psk_proof(nonce)


def test_proof_bound_to_room_id():
    psk = invites.generate_psk()
    nonce = "NONCE"
    a = _engine("alice", psk, room="ROOM-AB12")
    d = _engine("dave", psk, room="ROOM-ZZ99")
    assert a._psk_proof(nonce) != d._psk_proof(nonce)


def test_set_room_psk_clears():
    a = _engine("alice", invites.generate_psk())
    a._psk_authed["bob"] = True
    a.set_room_psk(None)
    assert a.room_psk is None
    assert a._psk_authed == {}


@pytest.mark.asyncio
async def test_challenge_is_answered_with_valid_proof():
    psk = invites.generate_psk()
    a = _engine("alice", psk)
    sent = []

    class FakeCh:
        readyState = "open"
        def send(self, s): sent.append(s)

    a.data_channels["bob"] = FakeCh()
    await a._handle_psk("psk_challenge", {"nonce": "PEERNONCE"}, "bob")
    msg = json.loads(sent[0])
    assert msg["__type"] == "psk_response"
    # The proof must verify against what a peer holding the same PSK expects.
    assert msg["proof"] == _engine("bob", psk)._psk_proof("PEERNONCE")


@pytest.mark.asyncio
async def test_correct_response_authenticates_and_starts_session():
    psk = invites.generate_psk()
    a = _engine("alice", psk)
    a._psk_my_nonce["bob"] = "MYNONCE"
    started = []
    async def fake_start(p): started.append(p)
    a._start_session = fake_start

    good_proof = _engine("bob", psk)._psk_proof("MYNONCE")
    await a._handle_psk("psk_response", {"proof": good_proof}, "bob")
    assert a._psk_authed["bob"] is True
    assert started == ["bob"]


@pytest.mark.asyncio
async def test_wrong_response_aborts_connection():
    a = _engine("alice", invites.generate_psk())
    a._psk_my_nonce["bob"] = "MYNONCE"
    removed = []
    async def fake_remove(p): removed.append(p)
    a.remove_peer = fake_remove

    await a._handle_psk("psk_response", {"proof": "deadbeef"}, "bob")
    assert a._psk_authed.get("bob") is not True
    assert removed == ["bob"]
