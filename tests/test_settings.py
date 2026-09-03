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

def test_noise_reduce_fields_default_off():
    s = Settings()
    assert s.noise_reduce is False
    assert s.noise_reduce_stationary is True


def test_noise_reduce_fields_round_trip():
    s = Settings(noise_reduce=True, noise_reduce_stationary=False)
    settings.save_settings(s)

    loaded = settings.load_settings()
    assert loaded.noise_reduce is True
    assert loaded.noise_reduce_stationary is False


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


def test_settings_ui_rendering(monkeypatch):
    pytest.importorskip("flet")
    import flet as ft

    import client
    from settings import Settings

    class FakeApp:
        settings = Settings()
        def _settings_on_retention_change(self, ev): pass
        def _settings_on_profile_change(self, ev): pass
        def _settings_do_test_turn(self, ev): pass
        def _settings_do_pf_autodetect(self, ev): pass
        def _settings_do_pf_test(self, ev): pass
        def _settings_export_keys(self, ev): pass
        def _settings_import_keys(self, ev): pass
        def _settings_regen_keys(self, ev): pass
        def _settings_do_switch_profile(self, ev): pass
        def _settings_do_create_profile(self, ev): pass
        def _settings_save(self, ev): pass
        def _close_dialog(self, dlg): pass
        def _show_dialog(self, dlg): pass
        def _reveal(self, card, delay=0): pass
        def _show_my_identity(self, ev): pass
        def _show_backup(self, ev): pass
        def _show_restore(self, ev): pass
        def _show_wipe(self, ev): pass
        
        # Bind the real method from client.HelucrypticApp
        _settings_section = client.HelucrypticApp._settings_section

    app = FakeApp()
    client.HelucrypticApp._show_settings(app, None)

    assert isinstance(app._settings_dlg, ft.AlertDialog)
    assert app._settings_retention_dd.value == "30"
    assert app._settings_profile_dd.value == "balanced"


def test_settings_noise_reduce_checkbox_renders_and_saves(monkeypatch):
    pytest.importorskip("flet")
    import client

    monkeypatch.setattr(client, "save_settings", lambda s: None)

    class FakeApp:
        settings = Settings(noise_reduce=True)
        def _settings_on_retention_change(self, ev): pass
        def _settings_on_profile_change(self, ev): pass
        def _settings_do_test_turn(self, ev): pass
        def _settings_do_pf_autodetect(self, ev): pass
        def _settings_do_pf_test(self, ev): pass
        def _settings_export_keys(self, ev): pass
        def _settings_import_keys(self, ev): pass
        def _settings_regen_keys(self, ev): pass
        def _settings_do_switch_profile(self, ev): pass
        def _settings_do_create_profile(self, ev): pass
        def _close_dialog(self, dlg): pass
        def _show_dialog(self, dlg): pass
        def _reveal(self, card, delay=0): pass
        def _show_my_identity(self, ev): pass
        def _show_backup(self, ev): pass
        def _show_restore(self, ev): pass
        def _show_wipe(self, ev): pass
        def _log(self, msg): pass
        def _update_perf_parameters(self): pass
        def _apply_port_forward(self): pass
        _settings_section = client.HelucrypticApp._settings_section
        _settings_save = client.HelucrypticApp._settings_save

    app = FakeApp()
    client.HelucrypticApp._show_settings(app, None)

    # Checkbox reflects the stored setting...
    assert app._settings_noise_reduce_cb.value is True

    # ...and Save writes the checkbox state back onto settings.
    app._settings_noise_reduce_cb.value = False
    client.HelucrypticApp._settings_save(app, None)
    assert app.settings.noise_reduce is False

