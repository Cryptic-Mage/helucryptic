"""Tests for PSK channel authentication (feature C) in WebRTCEngine.

The proof is HMAC(psk, nonce | room_id | responder_username): binding the
RESPONDER's name into the proof is what defeats the reflection attack (echoing
a victim's own nonce back at them and replaying their answer).
"""
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


def test_proof_agrees_for_same_psk_room_and_responder():
    psk = invites.generate_psk()
    a = _engine("alice", psk)
    b = _engine("bob", psk)
    nonce = base64.b64encode(os.urandom(16)).decode()
    # Both engines derive the same proof for the same responder identity.
    assert a._psk_proof(nonce, "alice") == b._psk_proof(nonce, "alice")


def test_proof_differs_for_wrong_psk():
    nonce = "NONCE"
    a = _engine("alice", invites.generate_psk())
    c = _engine("carol", invites.generate_psk())
    assert a._psk_proof(nonce, "x") != c._psk_proof(nonce, "x")


def test_proof_bound_to_room_id():
    psk = invites.generate_psk()
    nonce = "NONCE"
    a = _engine("alice", psk, room="ROOM-AB12")
    d = _engine("dave", psk, room="ROOM-ZZ99")
    assert a._psk_proof(nonce, "x") != d._psk_proof(nonce, "x")


def test_proof_bound_to_responder_identity():
    psk = invites.generate_psk()
    a = _engine("alice", psk)
    assert a._psk_proof("NONCE", "alice") != a._psk_proof("NONCE", "mallory")


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
    # The proof must verify against what a peer holding the same PSK expects
    # for responder "alice" (the engine answering the challenge).
    assert msg["proof"] == _engine("bob", psk)._psk_proof("PEERNONCE", "alice")


@pytest.mark.asyncio
async def test_correct_response_authenticates_and_starts_session():
    psk = invites.generate_psk()
    a = _engine("alice", psk)
    a._psk_my_nonce["bob"] = "MYNONCE"
    started = []
    async def fake_start(p): started.append(p)
    a._start_session = fake_start

    good_proof = _engine("bob", psk)._psk_proof("MYNONCE", "bob")
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


@pytest.mark.asyncio
async def test_reflection_attack_is_rejected():
    """Mallory (no PSK) echoes Alice's own nonce back as a challenge, then
    replays Alice's answer as her response. The responder binding must make
    the replayed proof fail."""
    psk = invites.generate_psk()
    alice = _engine("alice", psk)
    alice._psk_my_nonce["mallory"] = "ALICE-NONCE"

    captured = []

    class FakeCh:
        readyState = "open"
        def send(self, s): captured.append(s)

    alice.data_channels["mallory"] = FakeCh()

    removed = []
    async def fake_remove(p): removed.append(p)
    alice.remove_peer = fake_remove

    # Mallory reflects Alice's own nonce as HER challenge; Alice answers.
    await alice._handle_psk("psk_challenge", {"nonce": "ALICE-NONCE"}, "mallory")
    reflected_proof = json.loads(captured[0])["proof"]

    # Mallory replays Alice's answer as her own response to Alice's challenge.
    await alice._handle_psk("psk_response", {"proof": reflected_proof}, "mallory")
    assert alice._psk_authed.get("mallory") is not True
    assert removed == ["mallory"]


@pytest.mark.asyncio
async def test_nonce_is_single_use():
    """A correct proof consumes the pending nonce - replaying it later must
    not re-trigger session start against a stale nonce."""
    psk = invites.generate_psk()
    a = _engine("alice", psk)
    a._psk_my_nonce["bob"] = "MYNONCE"
    started = []
    async def fake_start(p): started.append(p)
    a._start_session = fake_start

    good_proof = _engine("bob", psk)._psk_proof("MYNONCE", "bob")
    await a._handle_psk("psk_response", {"proof": good_proof}, "bob")
    assert "bob" not in a._psk_my_nonce  # nonce consumed
