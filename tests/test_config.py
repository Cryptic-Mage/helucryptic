"""Tests for config.py — environment variable parsing and defaults."""

import config


def test_bool_truthy_values():
    assert config._bool("1") is True
    assert config._bool("true") is True
    assert config._bool("TRUE") is True
    assert config._bool("yes") is True
    assert config._bool("on") is True


def test_bool_falsy_values():
    assert config._bool("") is False
    assert config._bool("0") is False
    assert config._bool("false") is False
    assert config._bool("no") is False
    assert config._bool("off") is False
    assert config._bool(None) is False


def test_bool_default():
    assert config._bool(None, default=True) is True
    assert config._bool("", default=True) is True


def test_int_range_normal():
    assert config._int_range("NONEXISTENT_ENV", default=50, minimum=0, maximum=100) == 50


def test_int_range_clamps_below_minimum(monkeypatch):
    monkeypatch.setenv("TEST_CLAMP_LOW", "-5")
    assert config._int_range("TEST_CLAMP_LOW", default=50, minimum=10, maximum=100) == 10


def test_int_range_clamps_above_maximum(monkeypatch):
    monkeypatch.setenv("TEST_CLAMP_HIGH", "9999")
    assert config._int_range("TEST_CLAMP_HIGH", default=50, minimum=10, maximum=100) == 100


def test_int_range_invalid_input_returns_default(monkeypatch):
    monkeypatch.setenv("TEST_INVALID", "not-a-number")
    assert config._int_range("TEST_INVALID", default=42, minimum=0, maximum=100) == 42


def test_int_range_empty_input_returns_default(monkeypatch):
    monkeypatch.setenv("TEST_EMPTY", "")
    assert config._int_range("TEST_EMPTY", default=42, minimum=0, maximum=100) == 42


def test_bundle_dir_from_source():
    d = config._bundle_dir()
    assert d.exists()
    assert (d / "config.py").exists()


def test_default_constants_have_correct_types():
    assert isinstance(config.SCREEN_MAX_WIDTH, int) and config.SCREEN_MAX_WIDTH > 0
    assert isinstance(config.SCREEN_MAX_HEIGHT, int) and config.SCREEN_MAX_HEIGHT > 0
    assert isinstance(config.SCREEN_FPS, int) and config.SCREEN_FPS > 0
    assert isinstance(config.TURN_URL, str)
    assert isinstance(config.SERVER_PASSWORD, str)
