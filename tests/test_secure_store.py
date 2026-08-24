"""Dedicated tests for secure_store.py - OS-keystore protection."""
import secure_store

from constants.secure_store_constants import MAGIC


def test_available_returns_bool():
    assert isinstance(secure_store.available(), bool)


def test_is_protected_detects_magic():
    assert secure_store.is_protected(MAGIC + b"data") is True


def test_is_protected_no_magic():
    assert secure_store.is_protected(b"plain data") is False
    assert secure_store.is_protected(b"") is False


def test_unprotect_passthrough_plaintext():
    data = b"not wrapped at all"
    assert secure_store.unprotect(data) == data


def test_unprotect_empty_bytes():
    assert secure_store.unprotect(b"") == b""


def test_protect_unprotect_roundtrip():
    data = b'{"x25519_private":"secret"}'
    blob = secure_store.protect(data)
    assert secure_store.unprotect(blob) == data


def test_protect_adds_magic_on_windows(monkeypatch):
    monkeypatch.setattr(secure_store, "available", lambda: True)
    data = b"test data"
    blob = secure_store.protect(data)
    assert blob.startswith(MAGIC)
    assert secure_store.is_protected(blob)
