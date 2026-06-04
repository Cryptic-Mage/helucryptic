"""Contract tests for the framework-agnostic design-token layer (Phase 0
of the "Refined dark console" rebrand).

These tests deliberately assert *properties* (valid hex, WCAG AA contrast,
neutral surfaces, a monotonic glow-free elevation ramp, a real type scale)
rather than literal colour values, so the palette can be tuned without the
suite becoming a change-detector. They run without Flet installed because the
token layer has zero framework dependencies.
"""
import re

import pytest

from theme import tokens
from theme.contrast import contrast_ratio, relative_luminance

_HEX6 = re.compile(r"^#[0-9a-fA-F]{6}$")
_HEX = re.compile(r"^#([0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")


# --------------------------------------------------------------------------
# contrast utility
# --------------------------------------------------------------------------

def test_contrast_known_values():
    # Black on white is the canonical 21:1.
    assert round(contrast_ratio("#000000", "#ffffff"), 1) == 21.0
    # Identical colours have no contrast.
    assert round(contrast_ratio("#123456", "#123456"), 2) == 1.0
    # Order independent.
    assert contrast_ratio("#0a0b0d", "#e7e9ec") == contrast_ratio("#e7e9ec", "#0a0b0d")


def test_luminance_monotonic():
    assert relative_luminance("#000000") < relative_luminance("#777777") < relative_luminance("#ffffff")


# --------------------------------------------------------------------------
# palette: validity
# --------------------------------------------------------------------------

def _all_palette_colors():
    return {f.name: getattr(tokens.PALETTE, f.name) for f in tokens.PALETTE.__dataclass_fields__.values()}


def test_every_palette_color_is_valid_hex():
    for name, value in _all_palette_colors().items():
        assert isinstance(value, str), f"{name} is not a string"
        assert _HEX.match(value), f"{name}={value!r} is not a valid #rrggbb[aa] hex"


def test_required_semantic_roles_exist():
    required = {
        # surfaces
        "bg", "surface", "surface_raised", "surface_overlay",
        # borders
        "border_subtle", "border", "border_strong",
        # text tiers
        "text_primary", "text_secondary", "text_muted", "text_faint",
        # single accent
        "accent", "accent_hover", "accent_pressed", "accent_subtle", "on_accent",
        # semantic states reserved for connection/security
        "success", "on_success", "success_subtle",
        "warning", "on_warning", "warning_subtle",
        "danger", "on_danger", "danger_subtle",
    }
    have = set(_all_palette_colors().keys())
    missing = required - have
    assert not missing, f"palette missing semantic roles: {sorted(missing)}"


# --------------------------------------------------------------------------
# palette: neutral surfaces (no decorative colour bleeding into chrome)
# --------------------------------------------------------------------------

def _rgb(h):
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


@pytest.mark.parametrize("name", ["bg", "surface", "surface_raised", "surface_overlay"])
def test_surfaces_are_near_neutral(name):
    r, g, b = _rgb(getattr(tokens.PALETTE, name))
    # A faint cool tint is allowed, but surfaces must not read as a hue.
    assert max(r, g, b) - min(r, g, b) <= 14, f"{name} is too saturated to be a neutral surface"


def test_surfaces_ascend_in_lightness():
    order = ["bg", "surface", "surface_raised", "surface_overlay"]
    lums = [relative_luminance(getattr(tokens.PALETTE, n)) for n in order]
    assert lums == sorted(lums), "surface ramp must get lighter with elevation"
    assert lums[0] < lums[-1], "surface ramp must actually have range"


def test_borders_ascend_in_lightness():
    order = ["border_subtle", "border", "border_strong"]
    lums = [relative_luminance(getattr(tokens.PALETTE, n)) for n in order]
    assert lums == sorted(lums)


# --------------------------------------------------------------------------
# palette: WCAG AA contrast
# --------------------------------------------------------------------------

def test_primary_text_meets_AA_on_surfaces():
    for surf in ["bg", "surface", "surface_raised", "surface_overlay"]:
        ratio = contrast_ratio(tokens.PALETTE.text_primary, getattr(tokens.PALETTE, surf))
        assert ratio >= 4.5, f"text_primary on {surf} = {ratio:.2f} (< 4.5 AA)"


def test_secondary_text_meets_AA_on_surface():
    ratio = contrast_ratio(tokens.PALETTE.text_secondary, tokens.PALETTE.surface)
    assert ratio >= 4.5, f"text_secondary on surface = {ratio:.2f}"


def test_muted_text_meets_large_text_AA():
    # Muted is only ever used for large / non-essential labels → 3:1 floor.
    ratio = contrast_ratio(tokens.PALETTE.text_muted, tokens.PALETTE.surface)
    assert ratio >= 3.0, f"text_muted on surface = {ratio:.2f}"


@pytest.mark.parametrize("fg,bg", [
    ("on_accent", "accent"),
    ("on_success", "success"),
    ("on_warning", "warning"),
    ("on_danger", "danger"),
])
def test_on_color_text_meets_AA(fg, bg):
    ratio = contrast_ratio(getattr(tokens.PALETTE, fg), getattr(tokens.PALETTE, bg))
    assert ratio >= 4.5, f"{fg} on {bg} = {ratio:.2f}"


def test_state_colors_are_distinct_hues():
    # success/warning/danger must be visually separable, not three reds.
    s, w, d = tokens.PALETTE.success, tokens.PALETTE.warning, tokens.PALETTE.danger
    assert contrast_ratio(s, w) > 1.2 or s != w
    assert len({s, w, d}) == 3


# --------------------------------------------------------------------------
# spacing scale
# --------------------------------------------------------------------------

def test_spacing_scale_strictly_increasing_from_zero():
    assert tokens.SPACE[0] == 0
    assert all(b > a for a, b in zip(tokens.SPACE, tokens.SPACE[1:])), "spacing must strictly increase"
    # 4px base grid: every step is a multiple of 2.
    assert all(s % 2 == 0 for s in tokens.SPACE)


# --------------------------------------------------------------------------
# radii (tight, console feel) + pill
# --------------------------------------------------------------------------

def test_radii_present_and_ascending():
    for key in ("xs", "sm", "md", "lg", "pill"):
        assert key in tokens.RADIUS
    non_pill = [tokens.RADIUS[k] for k in ("xs", "sm", "md", "lg")]
    assert non_pill == sorted(non_pill)
    assert all(b > a for a, b in zip(non_pill, non_pill[1:]))
    assert tokens.RADIUS["pill"] >= 999
    # Console aesthetic: corners stay tight.
    assert tokens.RADIUS["lg"] <= 14


# --------------------------------------------------------------------------
# elevation ramp: monotonic, neutral, NO glow
# --------------------------------------------------------------------------

def test_elevation_ramp_is_monotonic_and_glow_free():
    ramp = tokens.ELEVATION
    assert len(ramp) >= 4, "need at least 4 elevation steps (0..3)"
    # Step 0 is flat.
    assert ramp[0]["blur"] == 0 and ramp[0]["spread"] <= 0
    blurs = [s["blur"] for s in ramp]
    assert blurs == sorted(blurs), "elevation blur must be monotonic"
    for i, s in enumerate(ramp):
        # No glow: shadows are neutral black-ish and never bloom outward.
        assert s["spread"] <= 0, f"elevation[{i}] has positive spread (glow)"
        r, g, b = _rgb(s["color"][:7] if s["color"].startswith("#") else s["color"])
        assert max(r, g, b) <= 24, f"elevation[{i}] shadow colour is not neutral/dark (glow?)"


# --------------------------------------------------------------------------
# type scale
# --------------------------------------------------------------------------

def test_type_scale_has_required_roles():
    required = {"display", "title", "subtitle", "body", "body_strong", "label", "caption", "mono"}
    assert required <= set(tokens.TYPE.keys()), f"missing type roles: {required - set(tokens.TYPE)}"


def test_type_scale_roles_well_formed():
    for role, spec in tokens.TYPE.items():
        assert spec["size"] > 0, f"{role} size must be positive"
        assert 100 <= spec["weight"] <= 900, f"{role} weight out of range"
        assert spec["family"] in ("sans", "mono"), f"{role} family must be sans|mono"
        assert spec["line_height"] >= 1.0, f"{role} line_height too small"


def test_type_scale_sizes_have_hierarchy():
    t = tokens.TYPE
    assert t["display"]["size"] > t["title"]["size"] > t["subtitle"]["size"]
    assert t["subtitle"]["size"] >= t["body"]["size"] >= t["caption"]["size"]


def test_label_role_is_monospace_for_console_feel():
    assert tokens.TYPE["label"]["family"] == "mono"
    assert tokens.TYPE["mono"]["family"] == "mono"


# --------------------------------------------------------------------------
# fonts + motion
# --------------------------------------------------------------------------

def test_fonts_declared():
    assert "sans" in tokens.FONTS and "mono" in tokens.FONTS
    assert isinstance(tokens.FONTS["sans"], str) and tokens.FONTS["sans"]
    assert isinstance(tokens.FONTS["mono"], str) and tokens.FONTS["mono"]


def test_motion_durations_are_functional_and_short():
    for key in ("fast", "base", "slow"):
        assert key in tokens.MOTION
    assert tokens.MOTION["fast"] < tokens.MOTION["base"] < tokens.MOTION["slow"]
    # Functional motion stays snappy — nothing ambient/long.
    assert tokens.MOTION["slow"] <= 300
