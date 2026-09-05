"""Recovering from a dropped link, and the video bitrate ceiling.

Both cover failures that looked like something else: a signaling connection that
never came back after the internet dropped, and a 1080p screen share that
arrived looking like 360p.
"""
import types

import pytest

import client
import config
import webrtc_engine as we

# ---------------------------------------------------------------------------
# _is_ws_alive - the reconnect loop depends on this being right for whichever
# websockets version is installed. `.closed` exists only on the legacy protocol;
# the new asyncio client exposes `.state` instead.
# ---------------------------------------------------------------------------

def test_is_ws_alive_none():
    assert client._is_ws_alive(None) is False


def test_is_ws_alive_legacy_open_attribute():
    assert client._is_ws_alive(types.SimpleNamespace(open=True, closed=False)) is True
    assert client._is_ws_alive(types.SimpleNamespace(open=False, closed=True)) is False


def test_is_ws_alive_new_api_state_attribute():
    """websockets>=13 asyncio client: no `.open`, no `.closed`, only `.state`."""
    open_conn = types.SimpleNamespace(state=types.SimpleNamespace(name="OPEN"))
    closed_conn = types.SimpleNamespace(state=types.SimpleNamespace(name="CLOSED"))
    assert client._is_ws_alive(open_conn) is True
    assert client._is_ws_alive(closed_conn) is False


def test_is_ws_alive_closed_only():
    assert client._is_ws_alive(types.SimpleNamespace(closed=False)) is True
    assert client._is_ws_alive(types.SimpleNamespace(closed=True)) is False


def test_is_ws_alive_never_reports_a_dead_socket_as_alive_by_accident():
    """The bug this replaces: `not ws.closed` raised AttributeError on the new
    API, and the surrounding `except` turned that into "still connected"."""
    new_api_closed = types.SimpleNamespace(state=types.SimpleNamespace(name="CLOSED"))
    assert not hasattr(new_api_closed, "closed")
    assert client._is_ws_alive(new_api_closed) is False


# ---------------------------------------------------------------------------
# Intentional-close marking: a socket we close ourselves must not trigger the
# auto-reconnect loop, and the mark rides on the socket so a replacement
# connection cannot be confused with the one being torn down.
# ---------------------------------------------------------------------------

class _Sock:
    pass


def test_unmarked_socket_is_an_unexpected_drop():
    assert client._was_closed_intentionally(_Sock()) is False


def test_marked_socket_is_deliberate():
    s = _Sock()
    client._mark_intentional_close(s)
    assert client._was_closed_intentionally(s) is True


def test_mark_is_per_socket_not_global():
    old, new = _Sock(), _Sock()
    client._mark_intentional_close(old)
    assert client._was_closed_intentionally(new) is False


def test_mark_tolerates_a_socket_that_rejects_attributes():
    class _Slotted:
        __slots__ = ()

    s = _Slotted()
    client._mark_intentional_close(s)          # must not raise
    assert client._was_closed_intentionally(s) is False


# ---------------------------------------------------------------------------
# Video bitrate ceiling
# ---------------------------------------------------------------------------

def _codec_module(name):
    return __import__(f"aiortc.codecs.{name}", fromlist=["MAX_BITRATE"])


@pytest.fixture
def restore_codecs():
    saved = {}
    for name in ("vpx", "h264"):
        m = _codec_module(name)
        saved[name] = (m.MAX_BITRATE, m.DEFAULT_BITRATE)
    yield
    for name, (mx, dflt) in saved.items():
        m = _codec_module(name)
        m.MAX_BITRATE, m.DEFAULT_BITRATE = mx, dflt


def test_ceiling_is_raised_for_both_video_codecs(restore_codecs):
    """aiortc ships 1.5 Mbps (VP8) / 3 Mbps (H.264) caps - far too low for a
    1080p screen share, which is why the receiver saw a 360p-looking image."""
    we.raise_video_bitrate_ceiling(max_bitrate=8_000_000, start_bitrate=2_500_000)
    for name in ("vpx", "h264"):
        m = _codec_module(name)
        assert m.MAX_BITRATE == 8_000_000
        assert m.DEFAULT_BITRATE == 2_500_000


def test_ceiling_is_never_lowered(restore_codecs):
    """Raising a ceiling is safe; quietly lowering someone else's is not."""
    m = _codec_module("vpx")
    m.MAX_BITRATE = 20_000_000
    we.raise_video_bitrate_ceiling(max_bitrate=8_000_000, start_bitrate=1_000_000)
    assert m.MAX_BITRATE == 20_000_000


def test_start_bitrate_is_clamped_into_the_codec_range(restore_codecs):
    """The encoder clamps to [MIN, MAX] itself; a start outside that range would
    be silently overridden, so keep it inside."""
    m = _codec_module("vpx")
    m.MAX_BITRATE = 1_500_000          # back to aiortc's shipped cap
    we.raise_video_bitrate_ceiling(max_bitrate=4_000_000, start_bitrate=99_000_000)
    assert m.DEFAULT_BITRATE == m.MAX_BITRATE == 4_000_000

    we.raise_video_bitrate_ceiling(max_bitrate=4_000_000, start_bitrate=1)
    assert m.DEFAULT_BITRATE == m.MIN_BITRATE


def test_import_applies_the_ceiling(restore_codecs):
    """Importing the engine must be enough - encoders are built later, deep
    inside aiortc, with no hook for us to pass a bitrate through."""
    assert _codec_module("vpx").MAX_BITRATE >= config.VIDEO_MAX_BITRATE
