"""Engine-level tests for advisory membership PKI (feature D)."""
import json
from types import SimpleNamespace

import pytest

import crypto
import webrtc_engine


class _Settings:
    security_mode = "dtls"   # plaintext frames keep the test focused on membership
    push_to_talk_key = ""


def _keys(tmp_path, name, monkeypatch):
    monkeypatch.setattr(crypto, "DATA_DIR", tmp_path / name)
    return crypto.generate_and_save_keys()


def _engine(name, keys):
    e = webrtc_engine.WebRTCEngine(name, _Settings(), keys)
    e.room_id = "ROOM-AB12"
    return e


def test_creator_self_certifies(tmp_path, monkeypatch):
    ck = _keys(tmp_path, "creator", monkeypatch)
    c = _engine("creator", ck)
    c.adopt_creator_identity()
    assert c.room_creator_pubkey == ck["ed25519_public"]
    assert crypto.verify_membership_cert(
        c.my_membership_cert, c.room_creator_pubkey,
        "ROOM-AB12", "creator", ck["ed25519_public"])


def test_evaluate_membership_flags_valid_and_invalid(tmp_path, monkeypatch):
    ck = _keys(tmp_path, "creator", monkeypatch)
    mk = _keys(tmp_path, "member", monkeypatch)
    c = _engine("creator", ck)
    c.adopt_creator_identity()
    cert = crypto.issue_membership_cert(
        ck["ed25519_private"], ck["ed25519_public"], "ROOM-AB12", "bob", mk["ed25519_public"])
    monkeypatch.setattr(webrtc_engine, "get_contact",
                        lambda u: SimpleNamespace(ed25519_pub=mk["ed25519_public"]) if u == "bob" else None)
    changes = []
    c.on_membership_change = lambda p, ok: changes.append((p, ok))

    assert c._evaluate_membership("bob", cert) is True
    assert c.is_member("bob") is True
    assert changes[-1] == ("bob", True)

    assert c._evaluate_membership("bob", "garbage-cert") is False
    assert c.is_member("bob") is False
    assert changes[-1] == ("bob", False)


@pytest.mark.asyncio
async def test_cert_grant_is_stored_and_rebroadcast(tmp_path, monkeypatch):
    mk = _keys(tmp_path, "member", monkeypatch)
    member = _engine("bob", mk)
    member.set_room_creator_pubkey("creatorpub")

    sent = []

    class _Ch:
        readyState = "open"
        def send(self, s): sent.append(s)

    member.data_channels["carol"] = _Ch()      # somewhere to rebroadcast to
    await member._handle_cert_grant({"__type": "cert_grant", "cert": "CERT123"}, "creator")

    assert member.my_membership_cert == "CERT123"
    kinds = [json.loads(s).get("__type") for s in sent]
    assert "membership" in kinds      # announced our new membership to peers


@pytest.mark.asyncio
async def test_purge_clears_membership(tmp_path, monkeypatch):
    ck = _keys(tmp_path, "creator", monkeypatch)
    c = _engine("creator", ck)
    c.adopt_creator_identity()
    c._peer_is_member["bob"] = True
    c.purge_secrets()
    assert c.my_membership_cert is None
    assert c.room_creator_pubkey is None
    assert c._peer_is_member == {}


def test_evaluate_membership_returns_false_when_contact_missing(tmp_path, monkeypatch):
    ck = _keys(tmp_path, "creator", monkeypatch)
    c = _engine("creator", ck)
    c.adopt_creator_identity()
    # No contact registered for "bob"
    monkeypatch.setattr(webrtc_engine, "get_contact", lambda u: None)
    assert c._evaluate_membership("bob", "some-cert") is False


@pytest.mark.asyncio
async def test_send_cert_grant_noop_for_non_creator(tmp_path, monkeypatch):
    mk = _keys(tmp_path, "member", monkeypatch)
    c = _engine("bob", mk)
    c.is_room_creator = False
    
    sent = []
    class _Ch:
        readyState = "open"
        def send(self, s): sent.append(s)
    c.data_channels["creator"] = _Ch()
    
    await c._send_cert_grant("creator", "bob", mk["ed25519_public"])
    assert sent == []  # should not send anything because bob is not the creator


@pytest.mark.asyncio
async def test_handle_membership_decrypts_and_evaluates(tmp_path, monkeypatch):
    mk = _keys(tmp_path, "member", monkeypatch)
    c = _engine("bob", mk)
    c.session_keys["carol"] = b"key"
    c.room_creator_pubkey = "creatorpub"

    evaluated = []
    c._evaluate_membership = lambda peer, cert: evaluated.append((peer, cert))
    
    # Simple frame decrypt mock or bypass decryption by using plaintext or mocking _decrypt_with_session
    c._decrypt_with_session = lambda frame, peer: {"cert": "DECRYPTED_CERT"} if peer == "carol" else {}
    
    await c._handle_membership({"__type": "membership", "token": "dummy"}, "carol")
    assert evaluated == [("carol", "DECRYPTED_CERT")]

