"""Tests for theme/contrast.py - WCAG luminance and contrast utilities."""
import pytest

from theme.contrast import (
    _to_rgb,
    contrast_ratio,
    meets_AA,
    relative_luminance,
)


def test_to_rgb_basic():
    assert _to_rgb("#ff0000") == (255, 0, 0)
    assert _to_rgb("#00ff00") == (0, 255, 0)
    assert _to_rgb("#0000ff") == (0, 0, 255)
    assert _to_rgb("#ffffff") == (255, 255, 255)
    assert _to_rgb("#000000") == (0, 0, 0)


def test_to_rgb_strips_alpha():
    assert _to_rgb("#ff000080") == (255, 0, 0)
    assert _to_rgb("#abc123ff") == (171, 193, 35)


def test_to_rgb_invalid():
    with pytest.raises(ValueError, match="expected #rrggbb"):
        _to_rgb("not-a-color")
    with pytest.raises(ValueError, match="expected #rrggbb"):
        _to_rgb("#xyz")
    with pytest.raises(ValueError, match="expected #rrggbb"):
        _to_rgb("")


def test_relative_luminance_black():
    assert relative_luminance("#000000") == 0.0


def test_relative_luminance_white():
    assert relative_luminance("#ffffff") == 1.0


def test_relative_luminance_mid_grey():
    lum = relative_luminance("#808080")
    assert 0.2 < lum < 0.3


def test_contrast_ratio_black_on_white():
    assert round(contrast_ratio("#000000", "#ffffff"), 1) == 21.0


def test_contrast_ratio_identical():
    assert contrast_ratio("#123456", "#123456") == 1.0


def test_contrast_ratio_order_independent():
    a, b = "#0a0b0d", "#e7e9ec"
    assert contrast_ratio(a, b) == contrast_ratio(b, a)


def test_meets_AA_normal_text():
    assert meets_AA("#000000", "#ffffff") is True
    assert meets_AA("#999999", "#ffffff") is False


def test_meets_AA_large_text():
    assert meets_AA("#777777", "#ffffff", large_text=True) is True
    assert meets_AA("#aaaaaa", "#ffffff", large_text=True) is False
