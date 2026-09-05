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
    # This is exactly how StartupScreen.connect() calls it - two positional args.
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
    screen._verify_fn = None
    
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
async def test_startup_screen_with_verification():
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
    screen._pw_field.value = "wrong_pw"

    # 1. Verify failure prevents on_done and displays error
    async def mock_fail(url, pw):
        return False, "Invalid server access password."
    screen._verify_fn = mock_fail
    task = screen._connect(None)
    if task:
        await task
    assert screen._pw_error.visible is True
    assert screen._pw_error.value == "Invalid server access password."
    assert len(done_called) == 0

    # 2. Verify success proceeds to on_done
    async def mock_ok(url, pw):
        return True, ""
    screen._verify_fn = mock_ok
    screen._pw_field.value = "good_pw"
    task = screen._connect(None)
    if task:
        await task
    assert done_called == [(client.HELUCRYPTIC_SERVER_URL, "good_pw")]


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
    screen._verify_fn = None
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


def test_auth_error_flags_and_toasts():
    import client

    class FakeApp:
        def __init__(self):
            self._auth_failed = False
            self.engine = type("Engine", (object,), {"last_error": ""})()
            self.toasts = []

        def _toast(self, msg, level):
            self.toasts.append((msg, level))

    app = FakeApp()
    client.HelucrypticApp._handle_sig_error(app, {}, "Invalid server access password.")
    assert app._auth_failed is True
    assert len(app.toasts) == 1
    assert "Authentication failed" in app.toasts[0][0]


def test_offline_peer_cleanup_on_signaling_error(monkeypatch):
    import client

    class FakeEngine:
        def __init__(self):
            self.pcs = {"pika": "some_pc"}
            self.removed_peers = []

        async def remove_peer(self, username):
            self.removed_peers.append(username)
            self.pcs.pop(username, None)

    class FakeApp:
        def __init__(self):
            self.engine = FakeEngine()
            self._pending_invites = set()
            self.toasts = []

        def _fire_and_forget(self, coro):
            import asyncio
            asyncio.run(coro)

        def _toast(self, msg, level):
            self.toasts.append((msg, level))

    app = FakeApp()
    client.HelucrypticApp._handle_sig_error(app, {}, "User 'pika' is offline.")

    assert "pika" not in app.engine.pcs
    assert app.engine.removed_peers == ["pika"]
    assert app.toasts == [("User 'pika' is offline.", "warn")]


def test_apply_aggregate_status_retains_signaling_when_ws_open(monkeypatch):
    import client

    class FakeWS:
        open = True

    class FakeApp:
        def __init__(self):
            self.ws = FakeWS()
            self.status_dot = type("Dot", (object,), {"bgcolor": ""})()
            self.status_label = type("Label", (object,), {"value": "", "color": ""})()
            self.engine = type("Engine", (object,), {"signaling_status": ""})()
            self._motion_ok = False
            self._STATUS_COLORS = {
                "idle":         "FAINT",
                "connecting":   "YELLOW",
                "connected":    "GREEN",
                "partial":      "YELLOW",
                "disconnected": "RED",
            }

        def _update_status(self, label: str, color: str) -> None:
            self.status_dot.bgcolor = color
            self.status_label.value = label
            self.status_label.color = color
            self.engine.signaling_status = label.lower()

        _apply_aggregate_status = client.HelucrypticApp._apply_aggregate_status

    app = FakeApp()
    app._apply_aggregate_status({"pika": "closed"}, group=False)
    
    assert app.status_label.value == "SIGNALING"
    assert app.status_dot.bgcolor == client.C.YELLOW


def test_restart_app(monkeypatch):
    import os
    import sys
    
    exec_args = []
    def fake_execv(executable, args):
        exec_args.append((executable, args))
        
    monkeypatch.setattr(os, "execv", fake_execv)
    
    client.restart_app()
    
    assert len(exec_args) == 1
    assert exec_args[0][0] == sys.executable
    assert exec_args[0][1] == [sys.executable] + sys.argv


@pytest.mark.asyncio
async def test_sctp_filter_unhandled_exception(monkeypatch):
    import sys
    
    captured_handler = None
    default_handler_calls = 0
    class FakeLoop:
        def set_exception_handler(self, handler):
            nonlocal captured_handler
            captured_handler = handler
        def default_exception_handler(self, ctx):
            nonlocal default_handler_calls
            default_handler_calls += 1

    monkeypatch.setattr(client.asyncio, "get_event_loop", lambda: FakeLoop())
    monkeypatch.setattr(client, "_install_log_capture", lambda: None)
    monkeypatch.setattr(client, "flet_theme", type("FakeTheme", (object,), {"apply": lambda *a, **kw: None})())
    monkeypatch.setattr(client, "load_settings", lambda: type("FakeSettings", (object,), {"signaling_url": ""})())
    monkeypatch.setattr(client, "StartupScreen", lambda page, on_done: None)
    
    class FakePage:
        class FakeWindow:
            width = 1180
            height = 760
            min_width = 940
            min_height = 600
            icon = None
        window = FakeWindow()
        title = ""
        padding = 0
        controls = []
        def update(self):
            pass
            
    page = FakePage()
    await client.main(page)
    
    assert captured_handler is not None

    # Mock restart_app
    restart_calls = 0
    def fake_restart():
        nonlocal restart_calls
        restart_calls += 1
    monkeypatch.setattr(client, "restart_app", fake_restart)

    # 1. Unhandled exception, --dev NOT in sys.argv
    monkeypatch.setattr(sys, "argv", ["client.py"])
    ctx = {"exception": ValueError("test error")}
    captured_handler(FakeLoop(), ctx)
    assert restart_calls == 1
    assert default_handler_calls == 1

    # 2. Unhandled exception, --dev IS in sys.argv
    restart_calls = 0
    default_handler_calls = 0
    monkeypatch.setattr(sys, "argv", ["client.py", "--dev"])
    ctx = {"exception": ValueError("test error")}
    captured_handler(FakeLoop(), ctx)
    assert restart_calls == 0
    assert default_handler_calls == 1

    # 3. Ignored exceptions, --dev NOT in sys.argv
    for exc_class in [asyncio.CancelledError, KeyboardInterrupt, SystemExit, ConnectionError]:
        restart_calls = 0
        default_handler_calls = 0
        monkeypatch.setattr(sys, "argv", ["client.py"])
        ctx = {"exception": exc_class("test ignored")}
        captured_handler(FakeLoop(), ctx)
        assert restart_calls == 0
        assert default_handler_calls == 1

    # 4. ConnectionError with "Cannot send data" message
    restart_calls = 0
    default_handler_calls = 0
    monkeypatch.setattr(sys, "argv", ["client.py"])
    ctx = {"exception": ConnectionError("Cannot send data")}
    captured_handler(FakeLoop(), ctx)
    assert restart_calls == 0
    assert default_handler_calls == 0


def test_entry_point_exception_handling_non_dev(monkeypatch):
    import sys

    import flet as ft
    
    def fake_app(target):
        raise RuntimeError("Startup fail")
    monkeypatch.setattr(ft, "app", fake_app)
    
    restart_calls = 0
    def fake_restart():
        nonlocal restart_calls
        restart_calls += 1
    monkeypatch.setattr(client, "restart_app", fake_restart)
    
    monkeypatch.setattr(sys, "argv", ["client.py"])
    
    code = """
try:
    ft.app(target=main)
except Exception as e:
    if "--dev" not in sys.argv:
        restart_app()
    else:
        raise
"""
    globals_dict = {
        "ft": ft,
        "main": client.main,
        "sys": sys,
        "restart_app": client.restart_app
    }
    exec(code, globals_dict)
    
    assert restart_calls == 1


def test_entry_point_exception_handling_dev(monkeypatch):
    import sys

    import flet as ft
    
    def fake_app(target):
        raise RuntimeError("Startup fail")
    monkeypatch.setattr(ft, "app", fake_app)
    
    restart_calls = 0
    def fake_restart():
        nonlocal restart_calls
        restart_calls += 1
    monkeypatch.setattr(client, "restart_app", fake_restart)
    
    monkeypatch.setattr(sys, "argv", ["client.py", "--dev"])
    
    code = """
try:
    ft.app(target=main)
except Exception as e:
    if "--dev" not in sys.argv:
        restart_app()
    else:
        raise
"""
    globals_dict = {
        "ft": ft,
        "main": client.main,
        "sys": sys,
        "restart_app": client.restart_app
    }
    with pytest.raises(RuntimeError, match="Startup fail"):
        exec(code, globals_dict)
    assert restart_calls == 0


def test_insights_panel_builds_without_name_errors():
    from client import _EASE_OUT, HelucrypticApp

    assert _EASE_OUT is not None
    app = HelucrypticApp.__new__(HelucrypticApp)
    app.settings = types.SimpleNamespace(security_mode="e2ee")
    panel = app._build_insights_panel()
    assert panel is not None


@pytest.mark.asyncio
async def test_startup_screen_has_loading_and_form_containers():
    class FakePage:
        def __init__(self):
            self.controls = []
        def add(self, *a, **k):
            pass
        def update(self, *a, **k):
            pass

    page = FakePage()
    screen = client.StartupScreen(page, on_done=lambda url, pw: None)
    assert screen._form_container is not None
    assert screen._loading_container is not None
    assert screen._form_container.visible is True
    assert screen._loading_container.visible is False


@pytest.mark.asyncio
async def test_startup_screen_transition_flow_success(monkeypatch):
    class FakePage:
        def __init__(self):
            self.controls = []
        def add(self, *a, **k):
            pass
        def update(self, *a, **k):
            pass

    page = FakePage()
    done_called = []
    screen = client.StartupScreen(page, on_done=lambda u, p: done_called.append((u, p)))
    screen._pw_field.value = "valid_password"

    # Fast forward sleep to make test instant
    orig_sleep = asyncio.sleep
    monkeypatch.setattr(asyncio, "sleep", lambda sec: orig_sleep(0))

    async def mock_ok(url, pw):
        return True, ""

    screen._verify_fn = mock_ok
    task = screen._connect(None)
    if task:
        await task

    assert screen._loading_status.value == "Access Granted"
    assert screen._loading_ring.color == client.C.GREEN
    assert done_called == [(client.HELUCRYPTIC_SERVER_URL, "valid_password")]


@pytest.mark.asyncio
async def test_startup_screen_transition_flow_failure(monkeypatch):
    class FakePage:
        def __init__(self):
            self.controls = []
        def add(self, *a, **k):
            pass
        def update(self, *a, **k):
            pass

    page = FakePage()
    done_called = []
    screen = client.StartupScreen(page, on_done=lambda u, p: done_called.append((u, p)))
    screen._pw_field.value = "wrong_password"

    # Fast forward sleep to make test instant
    orig_sleep = asyncio.sleep
    monkeypatch.setattr(asyncio, "sleep", lambda sec: orig_sleep(0))

    async def mock_fail(url, pw):
        return False, "Incorrect credentials"

    screen._verify_fn = mock_fail
    task = screen._connect(None)
    if task:
        await task

    assert len(done_called) == 0
    # After failure sequence finishes, form is back, loading container is hidden, error is displayed
    assert screen._form_container.visible is True
    assert screen._loading_container.visible is False
    assert screen._pw_field.disabled is False
    assert screen._pw_error.visible is True
    assert screen._pw_error.value == "Incorrect credentials"
    assert screen._connecting is False


@pytest.mark.asyncio
async def test_startup_screen_connect_guards_concurrent_calls():
    class FakePage:
        def __init__(self):
            self.controls = []
        def add(self, *a, **k):
            pass
        def update(self, *a, **k):
            pass

    page = FakePage()
    screen = client.StartupScreen(page, on_done=lambda u, p: None)
    screen._pw_field.value = "my_password"

    call_count = 0
    async def slow_verify(url, pw):
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.05)
        return True, ""

    screen._verify_fn = slow_verify

    # Trigger connect twice rapidly
    t1 = screen._connect(None)
    t2 = screen._connect(None)  # Must be ignored because screen._connecting is True

    assert t2 is None
    if t1:
        await t1
    assert call_count == 1


@pytest.mark.asyncio
async def test_check_signaling_auth_timeout_fails(monkeypatch):
    class FakeWS:
        async def recv(self):
            await asyncio.sleep(10)
        async def close(self):
            pass

    async def fake_connect(*a, **k):
        return FakeWS()

    monkeypatch.setattr(client.websockets, "connect", fake_connect)

    # Calling check_signaling_auth with short timeout should return False, not True
    ok, err = await client.check_signaling_auth("ws://localhost:9999", "pw", timeout=0.01)
    assert ok is False
    assert "timed out" in err.lower()







