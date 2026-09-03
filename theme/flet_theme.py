"""Flet adapter for the design tokens.

Translates the framework-agnostic tokens in ``theme.tokens`` into concrete Flet
objects: an ``ft.Theme`` / ``ft.ColorScheme``, ``ft.TextStyle`` per type role,
``ft.BoxShadow`` per elevation step, and standard animations.

This is the ONLY theme module that imports Flet, so the token layer stays
testable without Flet installed. Nothing here is wired into screens yet
(Phase 0 = foundation only); screen migration happens in later phases.

Typical use (later, in main()):
    from theme import flet_theme
    flet_theme.apply(page)            # theme + bgcolor + fonts
    ...
    ft.Text("Connected", style=flet_theme.text_style("label"))
    container.shadow = flet_theme.box_shadow(2)
"""
from __future__ import annotations

import os

import flet as ft

from . import tokens
from .tokens import PALETTE

# Optional bundled font assets. If these files are present (added in a later
# phase), they're registered; otherwise the family names fall back gracefully
# to the platform default, so the app never breaks for a missing font file.
_FONT_DIR = os.path.join(os.path.dirname(__file__), "fonts")
_FONT_FILES = {
    tokens.FONTS["sans"]: "Inter-Variable.ttf",
    tokens.FONTS["mono"]: "JetBrainsMono-Variable.ttf",
}


# --------------------------------------------------------------------------
# primitive mappers
# --------------------------------------------------------------------------

def font_weight(numeric: int) -> ft.FontWeight:
    """Map a 100-900 numeric weight to the nearest Flet FontWeight enum.

    Uses conventional round-half-up (not Python's banker's rounding) so e.g.
    650 -> W_700 and 450 -> W_500, matching designer expectations.
    """
    bucket = max(1, min(9, int(numeric / 100 + 0.5)))
    return getattr(ft.FontWeight, f"W_{bucket * 100}")


def _family(logical: str) -> str:
    return tokens.FONTS.get(logical, tokens.FONTS["sans"])


_ROLE_COLORS = {
    "display": PALETTE.text_primary,
    "title": PALETTE.text_primary,
    "subtitle": PALETTE.text_primary,
    "body": PALETTE.text_primary,
    "body_strong": PALETTE.text_primary,
    "label": PALETTE.text_muted,
    "caption": PALETTE.text_secondary,
    "mono": PALETTE.text_primary,
}


def text_style(role: str) -> ft.TextStyle:
    """Build an ft.TextStyle for a named type role (e.g. 'title', 'label')."""
    spec = tokens.TYPE[role]
    return ft.TextStyle(
        size=spec["size"],
        weight=font_weight(spec["weight"]),
        height=spec["line_height"],
        letter_spacing=spec["tracking"],
        font_family=_family(spec["family"]),
        color=_ROLE_COLORS.get(role, PALETTE.text_primary),
    )


def box_shadow(level: int) -> ft.BoxShadow | None:
    """Build the ft.BoxShadow for an elevation step (0 == flat == None)."""
    step = tokens.ELEVATION[max(0, min(level, len(tokens.ELEVATION) - 1))]
    if step["blur"] == 0:
        return None
    return ft.BoxShadow(
        blur_radius=step["blur"],
        spread_radius=step["spread"],
        offset=ft.Offset(0, step["y"]),
        color=step["color"],
    )


def animation(speed: str = "base", curve: ft.AnimationCurve | None = None) -> ft.Animation:
    """Standard functional animation for a named motion speed."""
    return ft.Animation(tokens.MOTION[speed], curve or ft.AnimationCurve.EASE_OUT)


# --------------------------------------------------------------------------
# colour scheme + theme
# --------------------------------------------------------------------------

def color_scheme() -> ft.ColorScheme:
    """Map tokens onto Flet's Material ColorScheme so built-in controls
    (dialogs, dropdowns, checkboxes) inherit the palette instead of defaulting
    to stock Material - fixing the audit's dialog-inconsistency at the root."""
    # Conservative, widely-supported field set (avoids deprecated Material
    # fields like background/on_background that some Flet builds reject).
    return ft.ColorScheme(
        primary=PALETTE.accent,
        on_primary=PALETTE.on_accent,
        primary_container=PALETTE.accent_subtle,
        on_primary_container=PALETTE.accent,
        secondary=PALETTE.accent,
        on_secondary=PALETTE.on_accent,
        surface=PALETTE.surface,
        on_surface=PALETTE.text_primary,
        error=PALETTE.danger,
        on_error=PALETTE.on_danger,
        outline=PALETTE.border,
        outline_variant=PALETTE.border_subtle,
        shadow="#000000",
    )


def build_theme() -> ft.Theme:
    """The application ft.Theme built from tokens."""
    return ft.Theme(
        color_scheme=color_scheme(),
        font_family=tokens.FONTS["sans"],
        use_material3=True,
    )


# --------------------------------------------------------------------------
# page application
# --------------------------------------------------------------------------

def register_fonts(page: ft.Page) -> None:
    """Register bundled fonts if their files exist; otherwise no-op (graceful
    fallback to system fonts)."""
    fonts = {}
    for family, filename in _FONT_FILES.items():
        path = os.path.join(_FONT_DIR, filename)
        if os.path.exists(path):
            fonts[family] = path
    if fonts:
        page.fonts = {**(getattr(page, "fonts", None) or {}), **fonts}


def apply(page: ft.Page) -> None:
    """Apply the full theme foundation to a page: fonts, dark theme, backdrop.
    Static background by design (no animated gradient / perf fork)."""
    register_fonts(page)
    page.theme_mode = ft.ThemeMode.DARK
    page.theme = build_theme()
    page.bgcolor = PALETTE.bg


__all__ = [
    "animation",
    "apply",
    "box_shadow",
    "build_theme",
    "color_scheme",
    "font_weight",
    "register_fonts",
    "text_style",
]
