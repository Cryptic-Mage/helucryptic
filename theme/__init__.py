"""Helucryptic design system - "Refined dark console".

Two layers:
  * ``theme.tokens``  - framework-agnostic design tokens (colours, spacing,
    radii, elevation, type scale, motion). No Flet dependency; fully testable.
  * ``theme.contrast``- WCAG luminance/contrast utilities.
  * ``theme.flet_theme`` - Flet adapter (imported lazily; needs Flet installed).

Import tokens directly:  ``from theme import tokens``  or  ``from theme import PALETTE``.
The Flet adapter is intentionally NOT imported here so the token layer stays
usable (and testable) without Flet present.
"""
from . import contrast, tokens
from .tokens import ELEVATION, FONTS, MOTION, PALETTE, RADIUS, SPACE, TYPE

__all__ = [
    "ELEVATION",
    "FONTS",
    "MOTION",
    "PALETTE",
    "RADIUS",
    "SPACE",
    "TYPE",
    "contrast",
    "tokens",
]
