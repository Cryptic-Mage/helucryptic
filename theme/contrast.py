"""WCAG 2.x relative-luminance + contrast-ratio utilities.

Framework-agnostic (pure Python, no Flet). Used by the token layer's tests to
guarantee AA contrast, and reusable by the app for runtime accessibility checks.

Reference: https://www.w3.org/TR/WCAG21/#dfn-relative-luminance
"""
from __future__ import annotations


def _to_rgb(hex_color: str) -> tuple[int, int, int]:
    """Parse '#rrggbb' or '#rrggbbaa' (alpha ignored) into 0-255 ints."""
    h = hex_color.lstrip("#")
    if len(h) == 8:  # drop alpha channel for luminance purposes
        h = h[:6]
    if len(h) != 6:
        raise ValueError(f"expected #rrggbb[aa], got {hex_color!r}")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _linearize(channel_255: int) -> float:
    c = channel_255 / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color: str) -> float:
    """WCAG relative luminance in [0, 1]."""
    r, g, b = _to_rgb(hex_color)
    return 0.2126 * _linearize(r) + 0.7152 * _linearize(g) + 0.0722 * _linearize(b)


def contrast_ratio(a: str, b: str) -> float:
    """WCAG contrast ratio in [1, 21]; order-independent."""
    la, lb = relative_luminance(a), relative_luminance(b)
    lighter, darker = max(la, lb), min(la, lb)
    return (lighter + 0.05) / (darker + 0.05)


def meets_AA(fg: str, bg: str, *, large_text: bool = False) -> bool:
    """True if fg/bg meet WCAG AA (4.5:1 normal text, 3:1 large text)."""
    return contrast_ratio(fg, bg) >= (3.0 if large_text else 4.5)
