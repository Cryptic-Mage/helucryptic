"""Design tokens - the single source of truth for Helucryptic's "Refined dark
console" visual language.

This module is deliberately framework-agnostic (no Flet import) so it can be
unit-tested in isolation and reused anywhere. The Flet adapter
(``theme.flet_theme``) translates these tokens into an ``ft.Theme`` /
``ft.ColorScheme`` and concrete ``ft.TextStyle`` / ``ft.BoxShadow`` objects.

Design principles encoded here (see the UX audit):
  * Neutral, near-black surfaces - colour never decorates chrome.
  * ONE cool accent; colour otherwise reserved for connection/security state.
  * Depth via a monotonic, glow-free elevation ramp (neutral shadows only).
  * A real type scale with named roles; mono-tinged labels for a console feel.
  * Functional, short motion - nothing ambient.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Palette:
    # --- Surfaces (near-neutral, ascending lightness with elevation) --------
    bg: str               # app backdrop (static, no animation)
    surface: str          # primary panel
    surface_raised: str   # cards, inputs
    surface_overlay: str  # dialogs, popovers, menus

    # --- Borders (hairline → strong) ---------------------------------------
    border_subtle: str
    border: str
    border_strong: str

    # --- Text tiers --------------------------------------------------------
    text_primary: str
    text_secondary: str
    text_muted: str
    text_faint: str

    # --- Single cool accent (interactive / brand) --------------------------
    accent: str
    accent_hover: str
    accent_pressed: str
    accent_subtle: str    # low-emphasis tinted surface (selected row, chips)
    on_accent: str        # text/icon on a filled accent surface

    # --- Semantic state (reserved for connection / security) ---------------
    success: str          # connected / verified
    on_success: str
    success_subtle: str
    warning: str          # connecting / caution
    on_warning: str
    warning_subtle: str
    danger: str           # failed / error / destructive
    on_danger: str
    danger_subtle: str


# Concrete palette. Values are tuned so the contract tests (AA contrast,
# neutral surfaces, ascending ramps) pass; tweak freely within those bounds.
PALETTE = Palette(
    # Surfaces - cool near-black, faint blue undertone, clearly stepped.
    bg="#0a0b0d",
    surface="#101216",
    surface_raised="#181b21",
    surface_overlay="#1f232b",

    # Borders - hairlines that stay quiet until they need to assert structure.
    border_subtle="#23272f",
    border="#2e333d",
    border_strong="#3d4450",

    # Text - high-legibility neutral ramp.
    text_primary="#e8eaee",
    text_secondary="#b3b9c4",
    text_muted="#7d8593",
    text_faint="#4a515d",

    # Accent - a restrained, slightly desaturated cyan (console/security feel).
    accent="#4cbdea",
    accent_hover="#67c8ef",
    accent_pressed="#37a3cf",
    accent_subtle="#122530",
    on_accent="#04141c",

    # State colours - distinct hues, each with AA-passing on-colour + tint.
    success="#3ccf8e",
    on_success="#04140d",
    success_subtle="#0d2620",
    warning="#e3b341",
    on_warning="#1c1404",
    warning_subtle="#2a2310",
    danger="#e5565c",
    on_danger="#1d0608",
    danger_subtle="#2b1417",
)


# --- Spacing: 4px-based grid (named indices) -------------------------------
# Access by index: SPACE[3] == 8. Strictly increasing, all even.
SPACE = (0, 2, 4, 8, 12, 16, 24, 32, 48, 64)


# --- Radii: tight corners for a precise, console-grade feel ----------------
RADIUS = {
    "xs": 4,
    "sm": 6,
    "md": 8,
    "lg": 12,
    "pill": 999,
}


# --- Elevation ramp: neutral shadows, NO glow (spread <= 0, dark colour) ----
# Each step is a dict the Flet adapter maps to ft.BoxShadow.
ELEVATION = [
    {"blur": 0,  "y": 0, "spread": 0,  "color": "#00000000"},  # 0: flat
    {"blur": 2,  "y": 1, "spread": -1, "color": "#0000004d"},  # 1: subtle raise
    {"blur": 8,  "y": 3, "spread": -2, "color": "#00000066"},  # 2: card / popover
    {"blur": 24, "y": 8, "spread": -4, "color": "#00000099"},  # 3: dialog / overlay
]


# --- Type scale: named roles. Sizes in px, weights 100-900, line_height as a
# unitless multiplier, tracking in px, family is a logical name ("sans"|"mono").
TYPE = {
    "display":     {"size": 22, "weight": 700, "line_height": 1.25, "tracking": -0.2, "family": "sans"},
    "title":       {"size": 16, "weight": 650, "line_height": 1.3,  "tracking": -0.1, "family": "sans"},
    "subtitle":    {"size": 14, "weight": 600, "line_height": 1.35, "tracking": 0.0,  "family": "sans"},
    "body":        {"size": 13, "weight": 400, "line_height": 1.5,  "tracking": 0.0,  "family": "sans"},
    "body_strong": {"size": 13, "weight": 600, "line_height": 1.5,  "tracking": 0.0,  "family": "sans"},
    "label":       {"size": 11, "weight": 600, "line_height": 1.3,  "tracking": 0.4,  "family": "mono"},
    "caption":     {"size": 11, "weight": 400, "line_height": 1.4,  "tracking": 0.0,  "family": "sans"},
    "mono":        {"size": 12, "weight": 450, "line_height": 1.45, "tracking": 0.0,  "family": "mono"},
}


# --- Fonts: logical name -> bundled family. The adapter registers these. ----
FONTS = {
    "sans": "Inter",
    "mono": "JetBrains Mono",
}


# --- Motion: functional only, short. Durations in ms. ----------------------
MOTION = {
    "fast": 120,   # hover / press feedback
    "base": 180,   # selection, state transitions
    "slow": 260,   # entering surfaces (dialogs)
}
