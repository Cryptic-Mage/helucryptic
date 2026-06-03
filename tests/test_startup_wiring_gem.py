import asyncio
import types

import client_gem


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

    monkeypatch.setattr(client_gem, "StartupScreen", FakeStartup)
    monkeypatch.setattr(client_gem, "HelucrypticApp", FakeApp)
    monkeypatch.setattr(client_gem, "load_settings", lambda: types.SimpleNamespace(signaling_url=""))
    monkeypatch.setattr(client_gem, "save_settings", lambda s: None)

    class FakePage:
        def __init__(self):
            self.window = types.SimpleNamespace(width=0, height=0, icon=None)
            self.controls = []
        def add(self, *a, **k):
            pass
        def update(self, *a, **k):
            pass

    page = FakePage()
    asyncio.run(client_gem.main(page))

    on_done = captured["on_done"]
    on_done("wss://example", "s3cret")
