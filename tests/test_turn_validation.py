import asyncio

import webrtc_engine as W


def test_rejects_bad_scheme():
    ok, msg = asyncio.run(W.test_turn("http://nope"))
    assert ok is False and "turn:" in msg


def test_rejects_empty():
    ok, msg = asyncio.run(W.test_turn(""))
    assert ok is False
