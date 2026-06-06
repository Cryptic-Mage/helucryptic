"""Regression test for the startup spinner bug.

StartupScreen.connect() calls on_done(url, password) with TWO args. If main's
launch_app (the on_done) only accepts one, clicking Connect raises TypeError,
which breaks the Flet session and leaves the UI stuck on a loading spinner.
"""
import asyncio
import types

import pytest

import client


def test_launch_app_accepts_url_and_password(monkeypatch):
    captured = {}

    class FakeStartup:
        def __init__(self, page, on_done):
            captured["on_done"] = on_done

    class FakeApp:
        def __init__(self, page):
            self._server_password = None

        def _refresh_contact_list(self):
            pass

    monkeypatch.setattr(client, "StartupScreen", FakeStartup)
    monkeypatch.setattr(client, "HelucrypticApp", FakeApp)
    monkeypatch.setattr(client, "load_settings", lambda: types.SimpleNamespace(signaling_url=""))
    monkeypatch.setattr(client, "save_settings", lambda s: None)

    class FakePage:
        def __init__(self):
            self.window = types.SimpleNamespace(width=0, height=0, icon=None)
            self.controls = []
        def add(self, *a, **k):
            pass
        def update(self, *a, **k):
            pass

    page = FakePage()
    asyncio.run(client.main(page))

    on_done = captured["on_done"]
    # This is exactly how StartupScreen.connect() calls it — two positional args.
    on_done("wss://example", "s3cret")  # must NOT raise TypeError


def test_to_ws_url_normalizes_schemes():
    assert client._to_ws_url("https://example.com") == "wss://example.com"
    assert client._to_ws_url("http://example.com/") == "ws://example.com"
    assert client._to_ws_url("example.com") == "ws://example.com"
    assert client._to_ws_url("wss://secure.org") == "wss://secure.org"


def test_generate_room_code_format():
    code = client.generate_room_code()
    assert code.startswith("ROOM-")
    assert len(code) == 9
    suffix = code.split("-")[1]
    assert len(suffix) == 4
    assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" for c in suffix)


@pytest.mark.asyncio
async def test_startup_screen_select_a_and_b():
    class FakePage:
        def __init__(self):
            self.controls = []
        def add(self, *a, **k):
            pass
        def update(self, *a, **k):
            pass

    page = FakePage()
    done_called = []
    screen = client.StartupScreen(page, on_done=lambda url, pw: done_called.append((url, pw)))
    
    # Initially active is 'a'
    assert screen._selected == "a"
    
    # Select 'b'
    screen._select_b(None)
    assert screen._radio_group.value == "b"
    assert screen._selected == "b"
    
    # Select 'a'
    screen._select_a(None)
    assert screen._radio_group.value == "a"
    assert screen._selected == "a"


@pytest.mark.asyncio
async def test_startup_screen_connect_validation_a():
    class FakePage:
        def __init__(self):
            self.controls = []
        def add(self, *a, **k):
            pass
        def update(self, *a, **k):
            pass

    page = FakePage()
    done_called = []
    screen = client.StartupScreen(page, on_done=lambda url, pw: done_called.append((url, pw)))
    
    # Empty password should set error
    screen._pw_field.value = ""
    screen._connect(None)
    assert screen._pw_error.visible is True
    assert len(done_called) == 0

    # With password, calls on_done
    screen._pw_field.value = "my_password"
    screen._connect(None)
    assert done_called == [(client.HELUCRYPTIC_SERVER_URL, "my_password")]


@pytest.mark.asyncio
async def test_startup_screen_connect_validation_b():
    class FakePage:
        def __init__(self):
            self.controls = []
        def add(self, *a, **k):
            pass
        def update(self, *a, **k):
            pass

    page = FakePage()
    done_called = []
    screen = client.StartupScreen(page, on_done=lambda url, pw: done_called.append((url, pw)))
    screen._select_b(None)

    # Invalid URL scheme
    screen._url_field.value = "ftp://invalid-url"
    screen._connect(None)
    assert screen._url_error.visible is True
    assert len(done_called) == 0

    # Valid URL scheme
    screen._url_field.value = "http://localhost:8000"
    screen._custom_pw_field.value = "custom_pw"
    screen._connect(None)
    assert done_called == [("ws://localhost:8000", "custom_pw")]


