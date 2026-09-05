"""_apply_port_forward must be safe to call from startup, Settings, and connect.

A forwarded port is what gets a symmetric-NAT peer through without a relay, so
connecting should engage the mapping on its own rather than only after a trip
through Settings. That makes the method run repeatedly, and repeated teardown
would drop a healthy mapping and leave several renewal loops running at once.

The real method is bound onto a stub so the logic under test is the shipped one,
without constructing the whole Flet app.
"""
import types

import pytest

import client


class _Settings:
    def __init__(self, enabled=True):
        self.port_forward_enabled = enabled


class _Manager:
    def __init__(self):
        self.stopped = False

    async def stop(self):
        self.stopped = True


class _App:
    """Minimal stand-in carrying only what _apply_port_forward touches."""

    def __init__(self, enabled=True):
        self.settings = _Settings(enabled)
        self._pf_manager = None
        self._pf_starting = False
        self.started = 0
        self.cleared = 0

    def _fire_and_forget(self, coro):
        # Run the coroutine far enough to record the call, then discard it.
        try:
            coro.send(None)
        except StopIteration:
            pass
        except Exception:
            pass
        return None

    _apply_port_forward = client.HelucrypticApp._apply_port_forward


@pytest.fixture
def app(monkeypatch):
    a = _App()

    async def fake_start(self):
        self.started += 1

    monkeypatch.setattr(client.HelucrypticApp, "_start_port_forward",
                        fake_start, raising=True)
    monkeypatch.setattr(client, "clear_forwarded_port",
                        lambda: setattr(a, "cleared", a.cleared + 1))
    a._start_port_forward = types.MethodType(fake_start, a)
    return a


def test_first_call_starts_the_mapping(app):
    app._apply_port_forward()
    assert app.started == 1


def test_repeat_calls_do_not_restart_a_healthy_mapping(app):
    """Connect calls this every time; it must not re-request the mapping."""
    app._apply_port_forward()
    app._pf_manager = _Manager()          # the start completed
    app._apply_port_forward()
    app._apply_port_forward()
    assert app.started == 1
    assert app._pf_manager.stopped is False


def test_a_start_in_flight_is_not_duplicated(app):
    """Gateway discovery is slow; a second call meanwhile must not race it."""
    app._pf_starting = True
    app._apply_port_forward()
    assert app.started == 0


def test_restart_tears_down_and_starts_again(app):
    """Saving Settings is the one caller that means the setting changed."""
    manager = _Manager()
    app._pf_manager = manager
    app._apply_port_forward(restart=True)
    assert manager.stopped is True
    assert app._pf_manager is None
    assert app.started == 1
    assert app.cleared == 1


def test_disabled_stops_and_clears(app):
    manager = _Manager()
    app._pf_manager = manager
    app.settings.port_forward_enabled = False
    app._apply_port_forward()
    assert manager.stopped is True
    assert app._pf_manager is None
    assert app.cleared == 1
    assert app.started == 0


def test_disabled_is_safe_with_no_manager(app):
    app.settings.port_forward_enabled = False
    app._apply_port_forward()
    assert app.started == 0
    assert app.cleared == 1
