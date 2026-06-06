import pytest
import webrtc_engine as W


class S:
    turn_url = "turn:relay.example:3478"
    turn_username = "u"
    turn_password = "p"
    screen_max_w = 1280
    screen_max_h = 720
    screen_fps = 10


_KEYS = {"x25519_public": "", "ed25519_public": "", "x25519_private": "", "ed25519_private": ""}


def _engine():
    return W.WebRTCEngine("me", S(), _KEYS)


def test_ice_servers_include_turn_when_configured():
    assert len(_engine()._ice_servers()) == 3  # 2 STUN + 1 TURN


def test_ice_servers_stun_only_without_turn():
    class NoTurn(S):
        turn_url = ""
    e = W.WebRTCEngine("me", NoTurn(), _KEYS)
    assert len(e._ice_servers()) == 2


def test_get_diagnostics_shape_and_redaction():
    e = _engine()
    e.signaling_status = "connected"
    e._ice_states["bob"] = "checking"
    d = e.get_diagnostics()
    assert d["signaling"] == "connected"
    assert d["turn_configured"] is True
    assert isinstance(d["peers"], list)
    blob = repr(d).lower()
    for forbidden in ("password", "candidate", "sdp", "private", "\"p\""):
        assert forbidden not in blob


def test_get_diagnostics_when_last_error_set():
    e = _engine()
    e.last_error = "Failed to connect to signaling"
    d = e.get_diagnostics()
    assert d["last_error"] == "Failed to connect to signaling"


def test_get_diagnostics_hub_fallback_on_exception(monkeypatch):
    e = _engine()
    e.room_id = "ROOM-123"
    # Cause current_hub to raise an exception
    monkeypatch.setattr(e, "current_hub", lambda: exec("raise ValueError('hub error')"))
    d = e.get_diagnostics()
    assert d["hub"] == "?"


def test_get_diagnostics_peer_details():
    e = _engine()
    # Mock a minimal peer connection
    class DummyPC:
        connectionState = "connected"
        signalingState = "stable"
        iceConnectionState = "completed"
        iceGatheringState = "complete"
    
    class DummyDC:
        readyState = "open"

    e.pcs["bob"] = DummyPC()
    e.data_channels["bob"] = DummyDC()
    e._hello_sent["bob"] = True
    e._peer_hello_verified["bob"] = True
    e.session_keys["bob"] = b"key"

    d = e.get_diagnostics()
    assert d["num_peers"] == 1
    peer_info = d["peers"][0]
    assert peer_info["peer"] == "bob"
    assert peer_info["connection"] == "connected"
    assert peer_info["signaling"] == "stable"
    assert peer_info["ice"] == "completed"
    assert peer_info["ice_gathering"] == "complete"
    assert peer_info["datachannel"] == "open"
    assert peer_info["hello_sent"] is True
    assert peer_info["hello_ok"] is True
    assert peer_info["session_key"] is True


def test_diagnostics_ui_rendering(monkeypatch):
    pytest.importorskip("flet")
    import client
    import flet as ft

    class FakeClipboard:
        def set(self, text):
            pass

    class FakePage:
        def __init__(self):
            self.clipboard = FakeClipboard()

    class FakeApp:
        def __init__(self):
            self.page = FakePage()
            self._diag_open = False

        def _render_diagnostics_state(self):
            return "fake diagnostics state"

        def _render_diagnostics_log(self):
            return "fake logs"

        def _log(self, text):
            pass

        def _close_dialog(self, dlg):
            pass

        def _show_dialog(self, dlg):
            self.dialog = dlg

        def _fire_and_forget(self, coro):
            pass

        async def _set_clipboard(self, text):
            pass


    app = FakeApp()
    client.HelucrypticApp._show_diagnostics(app, None)

    assert app._diag_open is True
    assert isinstance(app.dialog, ft.AlertDialog)
    col = app.dialog.content.content
    assert isinstance(col, ft.Column)
    assert len(col.controls) == 3
    
    # Verify the first section (Peer info) is a scrollable container with expand=True
    top_container = col.controls[0]
    assert isinstance(top_container, ft.Container)
    assert top_container.expand is True
    assert isinstance(top_container.content, ft.Column)
    assert top_container.content.scroll == ft.ScrollMode.AUTO

    # Verify the second section (Logs) is a scrollable container with expand=True
    bottom_container = col.controls[2]
    assert isinstance(bottom_container, ft.Container)
    assert bottom_container.expand is True
    assert isinstance(bottom_container.content, ft.Column)
    assert bottom_container.content.scroll == ft.ScrollMode.AUTO
