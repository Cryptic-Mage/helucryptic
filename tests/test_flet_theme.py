"""Contract tests for the Flet theme adapter.

Skipped automatically when Flet isn't installed (the token layer is tested
separately and needs no framework). In a Flet-equipped environment these
verify that tokens map onto real Flet objects without error.
"""
import pytest

ft = pytest.importorskip("flet")

from theme import flet_theme, tokens


def test_font_weight_maps_to_nearest_bucket():
    assert flet_theme.font_weight(650) == ft.FontWeight.W_700  # 6.5 -> 7
    assert flet_theme.font_weight(400) == ft.FontWeight.W_400
    assert flet_theme.font_weight(450) == ft.FontWeight.W_500  # 4.5 -> 5
    # Out-of-range clamps into 100..900.
    assert flet_theme.font_weight(50) == ft.FontWeight.W_100
    assert flet_theme.font_weight(2000) == ft.FontWeight.W_900


def test_text_style_for_every_role():
    for role in tokens.TYPE:
        style = flet_theme.text_style(role)
        assert isinstance(style, ft.TextStyle)
        assert style.size == tokens.TYPE[role]["size"]


def test_box_shadow_levels():
    assert flet_theme.box_shadow(0) is None            # flat
    for level in (1, 2, 3):
        shadow = flet_theme.box_shadow(level)
        assert isinstance(shadow, ft.BoxShadow)
        assert shadow.spread_radius <= 0               # never a glow


def test_box_shadow_clamps_out_of_range():
    assert flet_theme.box_shadow(99) is not None       # clamps to last step


def test_build_theme_and_color_scheme():
    theme = flet_theme.build_theme()
    assert isinstance(theme, ft.Theme)
    cs = flet_theme.color_scheme()
    assert cs.primary == tokens.PALETTE.accent
    assert cs.surface == tokens.PALETTE.surface


def test_animation_speeds():
    assert flet_theme.animation("fast").duration == tokens.MOTION["fast"]
    assert flet_theme.animation("slow").duration == tokens.MOTION["slow"]
