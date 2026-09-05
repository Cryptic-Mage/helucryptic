import asyncio
import json
from unittest.mock import AsyncMock, MagicMock
import pytest
import webrtc_engine

class MockSettings:
    def __init__(self):
        self.security_mode = "e2ee"
        self.push_to_talk_key = ""

@pytest.fixture
def mock_keys():
    return {
        "x25519_private": "dGVzdF94MjU1MTlfcHJpdmF0ZV9rZXk=",
        "x25519_public": "dGVzdF94MjU1MTlfcHVibGljX2tleQ==",
        "ed25519_private": "dGVzdF9lZDI1NTE5X3ByaXZhdGVfa2V5",
        "ed25519_public": "dGVzdF9lZDI1NTE5X3B1YmxpY19rZXk="
    }

@pytest.fixture
def engine(mock_keys):
    settings = MockSettings()
    eng = webrtc_engine.WebRTCEngine("alice", settings, mock_keys)
    yield eng
    for t in list(eng._bg_tasks):
        try:
            t.cancel()
        except Exception:
            pass

@pytest.mark.asyncio
async def test_dispatch_unverify_triggers_callback(engine):
    callback_mock = MagicMock()
    engine.on_peer_unverified = callback_mock

    # Simulate receiving unverify frame: _dispatch_frame(frame, peer)
    await engine._dispatch_frame({"__type": "unverify"}, "bob")

    callback_mock.assert_called_once_with("bob")

@pytest.mark.asyncio
async def test_send_unverify_via_datachannel(engine):
    mock_dc = MagicMock()
    mock_dc.readyState = "open"
    engine.data_channels["bob"] = mock_dc

    await engine.send_unverify("bob")

    mock_dc.send.assert_called_once()
    sent_data = json.loads(mock_dc.send.call_args[0][0])
    assert sent_data == {"__type": "unverify"}

@pytest.mark.asyncio
async def test_send_unverify_fallback_to_relay(engine):
    engine._send_ws = AsyncMock()
    relay_mock = AsyncMock()
    engine.send_via_relay = relay_mock

    # bob has no open datachannel, fallback to relay
    await engine.send_unverify("bob")

    relay_mock.assert_awaited_once_with("bob", {"__type": "unverify"})
