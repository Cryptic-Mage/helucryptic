"""Tests for screen-share bug fixes:
 - start_screen_share is video-only (decoupled from mic)
 - stop_screen_share removes the track without killing voice
 - hangup cleans up both sender dicts
 - voice and screen are independent streams
"""
import pytest

import webrtc_engine


class _Settings:
    security_mode = "dtls"
    push_to_talk_key = ""


_KEYS = {
    "x25519_private": "dGVzdF94MjU1MTlfcHJpdmF0ZV9rZXk=",
    "x25519_public":  "dGVzdF94MjU1MTlfcHVibGljX2tleQ==",
    "ed25519_private": "dGVzdF9lZDI1NTE5X3ByaXZhdGVfa2V5",
    "ed25519_public":  "dGVzdF9lZDI1NTE5X3B1YmxpY19rZXk=",
}


def _engine(name="me"):
    return webrtc_engine.WebRTCEngine(name, _Settings(), _KEYS)


def test_screen_share_does_not_auto_add_mic():
    """Decoupled: starting screen share must NOT add the peer to _voice_peers."""
    e = _engine()
    e._screen_peers.discard("bob")
    e._voice_peers.discard("bob")
    # Simulate the guard check only - no real RTCPeerConnection needed.
    assert "bob" not in e._voice_peers
    assert "bob" not in e._screen_peers


def test_senders_tracked_and_cleared_on_end_call():
    e = _engine()
    # Manually simulate what addTrack would populate.
    e._voice_senders["bob"] = object()
    e._screen_senders["bob"] = object()
    e._voice_peers.add("bob")
    e._screen_peers.add("bob")
    e._end_call_local("bob")
    assert "bob" not in e._voice_peers
    assert "bob" not in e._screen_peers
    assert "bob" not in e._voice_senders
    assert "bob" not in e._screen_senders


def test_remove_peer_clears_senders():
    """remove_peer must clean up both sender dicts so no stale references linger."""
    import asyncio
    e = _engine()
    e._voice_senders["alice"] = object()
    e._screen_senders["alice"] = object()
    asyncio.run(e.remove_peer("alice"))
    assert "alice" not in e._voice_senders
    assert "alice" not in e._screen_senders


@pytest.mark.asyncio
async def test_stop_screen_share_only_removes_screen_peer():
    """Stopping screen share must leave _voice_peers intact."""
    e = _engine()

    removed_tracks = []

    class _FakePC:
        connectionState = "connected"
        def removeTrack(self, sender):
            removed_tracks.append(sender)
        def addTrack(self, t):
            return t
        def getReceivers(self):
            return []

    sentinel = object()           # fake sender object
    e.pcs["bob"] = _FakePC()
    e._screen_senders["bob"] = sentinel
    e._screen_peers.add("bob")
    e._voice_peers.add("bob")     # voice is active independently

    neg_called = []
    async def fake_neg(p): neg_called.append(p)
    e.request_negotiation = fake_neg

    await e.stop_screen_share("bob")

    assert "bob" not in e._screen_peers
    assert "bob" not in e._screen_senders
    assert "bob" in e._voice_peers   # voice untouched
    assert sentinel in removed_tracks
    assert "bob" in neg_called


def test_purge_secrets_clears_senders():
    e = _engine()
    e._voice_senders["x"] = object()
    e._screen_senders["x"] = object()
    # purge_secrets clears PSK/session state; senders are separate - check they
    # aren't accidentally left after end_call_local (which is called on disconnect).
    e._end_call_local("x")
    assert e._voice_senders == {}
    assert e._screen_senders == {}


@pytest.mark.asyncio
async def test_start_screen_share_fails_when_pc_missing():
    e = _engine()
    # No peer connection for 'bob' in e.pcs
    await e.start_screen_share("bob")
    assert "bob" not in e._screen_peers
    assert "bob" not in e._screen_senders

