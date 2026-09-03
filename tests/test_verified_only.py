import types

import client


def _app(verified_only, allowed=()):
    o = types.SimpleNamespace()
    o.settings = types.SimpleNamespace(verified_only=verified_only)
    o._session_allowed = set(allowed)
    return o


_is_allowed = client.HelucrypticApp._is_allowed


def test_allowed_when_mode_off(monkeypatch):
    monkeypatch.setattr(client, "get_contact", lambda u: None)
    assert _is_allowed(_app(False), "bob") is True


def test_blocked_when_unverified(monkeypatch):
    monkeypatch.setattr(client, "get_contact", lambda u: types.SimpleNamespace(verified=False))
    assert _is_allowed(_app(True), "bob") is False


def test_allowed_when_verified(monkeypatch):
    monkeypatch.setattr(client, "get_contact", lambda u: types.SimpleNamespace(verified=True))
    assert _is_allowed(_app(True), "bob") is True


def test_allowed_when_session_allowed(monkeypatch):
    monkeypatch.setattr(client, "get_contact", lambda u: types.SimpleNamespace(verified=False))
    assert _is_allowed(_app(True, {"bob"}), "bob") is True


def test_room_not_gated(monkeypatch):
    monkeypatch.setattr(client, "get_contact", lambda u: None)
    assert _is_allowed(_app(True), "") is True


def test_blocked_when_contact_missing_and_not_in_session_allowed(monkeypatch):
    monkeypatch.setattr(client, "get_contact", lambda u: None)
    assert _is_allowed(_app(True), "bob") is False

