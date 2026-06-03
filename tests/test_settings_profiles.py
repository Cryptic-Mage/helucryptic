import os
import tempfile

os.environ["USERPROFILE"] = os.environ["HOME"] = tempfile.mkdtemp()

import settings as S


def test_profiles_have_expected_values():
    assert S.PROFILES["old_pc"]["screen_fps"] == 5
    assert S.PROFILES["overclock"] == {
        "screen_max_w": 2560, "screen_max_h": 1440,
        "screen_fps": 60, "jpeg_quality": 75, "tile_render_fps": 30,
    }


def test_apply_profile_sets_concrete_and_label():
    s = S.Settings()
    S.apply_profile(s, "quality")
    assert s.screen_max_w == 1920 and s.screen_fps == 30
    assert s.performance_profile == "quality"


def test_profile_for_values_detects_custom():
    s = S.Settings()
    S.apply_profile(s, "balanced")
    s.screen_fps = 13
    assert S.profile_for_values(S.asdict(s)) == "custom"


def test_load_clamps_out_of_range(tmp_path, monkeypatch):
    p = tmp_path / "settings.json"
    monkeypatch.setattr(S, "_SETTINGS_PATH", p)
    p.write_text('{"screen_fps": 9999, "screen_max_w": 99999}')
    loaded = S.load_settings()
    assert loaded.screen_fps == 60 and loaded.screen_max_w == 2560


def test_first_run_seeds_from_config(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "_SETTINGS_PATH", tmp_path / "none.json")
    loaded = S.load_settings()
    assert loaded.screen_max_w in (854, 960, 1280, 1920, 2560)
    assert loaded.performance_profile in S.PROFILES or loaded.performance_profile == "custom"


def test_roundtrip_persists_new_fields(tmp_path, monkeypatch):
    p = tmp_path / "settings.json"
    monkeypatch.setattr(S, "_SETTINGS_PATH", p)
    s = S.load_settings()
    S.apply_profile(s, "old_pc")
    s.turn_url = "turn:relay.example:3478"
    S.save_settings(s)
    reloaded = S.load_settings()
    assert reloaded.screen_fps == 5 and reloaded.turn_url == "turn:relay.example:3478"
    assert reloaded.performance_profile == "old_pc"
