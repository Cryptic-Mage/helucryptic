import json

import pytest

import settings
from settings import Settings


@pytest.fixture(autouse=True)
def patch_settings_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "DATA_DIR", tmp_path)
    monkeypatch.setattr(settings, "_SETTINGS_PATH", tmp_path / "settings.json")

def test_default_settings():
    s = settings.load_settings()
    assert s.security_mode == "e2ee"
    assert s.retention_days == 30
    assert s.push_to_talk_key == "space"
    assert s.signaling_url == "ws://127.0.0.1:8000"
    assert s.low_perf_mode is False

def test_save_and_load_settings():
    s = Settings(
        security_mode="dtls",
        retention_days=15,
        push_to_talk_key="ctrl",
        signaling_url="ws://example.com",
        low_perf_mode=True
    )
    settings.save_settings(s)

    # Check if saved to disk correctly
    assert settings._SETTINGS_PATH.exists()

    # Load settings back
    loaded = settings.load_settings()
    assert loaded.security_mode == "dtls"
    assert loaded.retention_days == 15
    assert loaded.push_to_talk_key == "ctrl"
    assert loaded.signaling_url == "ws://example.com"
    assert loaded.low_perf_mode is True

def test_load_corrupted_settings():
    # Write invalid JSON to settings file
    settings.DATA_DIR.mkdir(exist_ok=True)
    settings._SETTINGS_PATH.write_text("corrupted json string{")

    # It should catch the exception and return default settings
    s = settings.load_settings()
    assert s.security_mode == "e2ee"
    assert s.retention_days == 30

def test_port_forward_fields_default_off():
    s = Settings()
    assert s.port_forward_enabled is False
    assert s.forwarded_port == 0


def test_forwarded_port_clamped_when_enabled():
    from settings import _clamp
    s = Settings(port_forward_enabled=True, forwarded_port=70000)
    _clamp(s)
    assert s.forwarded_port == 65535
    s2 = Settings(port_forward_enabled=True, forwarded_port=80)
    _clamp(s2)
    assert s2.forwarded_port == 1024


def test_forwarded_port_not_clamped_when_disabled():
    from settings import _clamp
    s = Settings(port_forward_enabled=False, forwarded_port=0)
    _clamp(s)
    assert s.forwarded_port == 0


def test_load_partial_or_unknown_fields():
    # Save JSON with an unknown field and missing fields
    settings.DATA_DIR.mkdir(exist_ok=True)
    settings._SETTINGS_PATH.write_text(json.dumps({
        "security_mode": "dtls",
        "unknown_field": "some_value"
    }))

    s = settings.load_settings()
    # Explicitly matched fields are loaded
    assert s.security_mode == "dtls"
    # Unspecified fields use default values
    assert s.retention_days == 30
    assert s.push_to_talk_key == "space"
