"""Regression test for the startup spinner bug.

StartupScreen.connect() calls on_done(url, password) with TWO args. If main's
launch_app (the on_done) only accepts one, clicking Connect raises TypeError,
which breaks the Flet session and leaves the UI stuck on a loading spinner.
"""
import asyncio
import types

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
