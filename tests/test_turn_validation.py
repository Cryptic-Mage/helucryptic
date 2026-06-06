import asyncio
import pytest

import webrtc_engine as W


def test_rejects_bad_scheme():
    ok, msg = asyncio.run(W.test_turn("http://nope"))
    assert ok is False and "turn:" in msg


def test_rejects_empty():
    ok, msg = asyncio.run(W.test_turn(""))
    assert ok is False


def test_turn_success_on_relay_candidate(monkeypatch):
    class DummyPC:
        def __init__(self, config):
            self.iceGatheringState = "complete"
            self.localDescription = type('SDP', (), {'sdp': "typ relay candidate here"})()
        def createDataChannel(self, label):
            pass
        async def createOffer(self):
            return "offer"
        async def setLocalDescription(self, desc):
            pass
        async def close(self):
            pass
    
    monkeypatch.setattr(W, "RTCPeerConnection", DummyPC)
    ok, msg = asyncio.run(W.test_turn("turn:relay.example:3478"))
    assert ok is True
    assert msg == "Relay reachable"


def test_turn_failure_on_no_relay_candidate(monkeypatch):
    class DummyPC:
        def __init__(self, config):
            self.iceGatheringState = "complete"
            self.localDescription = type('SDP', (), {'sdp': "only host and srflx candidates"})()
        def createDataChannel(self, label):
            pass
        async def createOffer(self):
            return "offer"
        async def setLocalDescription(self, desc):
            pass
        async def close(self):
            pass
    
    monkeypatch.setattr(W, "RTCPeerConnection", DummyPC)
    ok, msg = asyncio.run(W.test_turn("turn:relay.example:3478"))
    assert ok is False
    assert "No relay candidate" in msg


def test_turn_timeout(monkeypatch):
    # We want wait_for to timeout or to raise TimeoutError
    class DummyPC:
        def __init__(self, config):
            # Keeps it at "gathering" to trigger timeout
            self.iceGatheringState = "gathering"
            self.localDescription = None
        def createDataChannel(self, label):
            pass
        async def createOffer(self):
            return "offer"
        async def setLocalDescription(self, desc):
            pass
        async def close(self):
            pass

    monkeypatch.setattr(W, "RTCPeerConnection", DummyPC)
    
    # We can patch asyncio.wait_for to raise TimeoutError to run instantly
    async def mock_wait_for(coro, timeout):
        raise asyncio.TimeoutError()
        
    monkeypatch.setattr(asyncio, "wait_for", mock_wait_for)
    
    ok, msg = asyncio.run(W.test_turn("turn:relay.example:3478"))
    assert ok is False
    assert "Timed out" in msg


def test_turn_generic_exception(monkeypatch):
    class DummyPC:
        def __init__(self, config):
            self.iceGatheringState = "new"
        def createDataChannel(self, label):
            raise RuntimeError("some RTC error")
        async def close(self):
            pass
            
    monkeypatch.setattr(W, "RTCPeerConnection", DummyPC)
    ok, msg = asyncio.run(W.test_turn("turn:relay.example:3478"))
    assert ok is False
    assert "Error: RuntimeError" in msg

