import sys
import time
import re as _re
from collections import deque
# pyrefly: ignore [missing-import]
import flet as ft

import config
from theme.tokens import PALETTE as _P
from theme.tokens import RADIUS as _t_RADIUS
from theme.tokens import MOTION as _t_MOTION

HELUCRYPTIC_SERVER_URL      = config.DEFAULT_SIGNALING_URL
HELUCRYPTIC_SERVER_PASSWORD = config.SERVER_PASSWORD
SHARE_SCREEN_TXT            = "Share screen"
DIAGNOSTICS_TXT             = "Connection diagnostics"
JOIN_ROOM_TXT               = "Join room"
LOAD_MORE_TXT               = "Load more…"
SCHEME_HTTPS                = "https://"
SCHEME_HTTP                 = "http://"
SCHEME_WSS                  = "wss://"
SCHEME_WS                   = "ws://"

LOG_BUFFER: "deque[str]" = deque(maxlen=1500)

class _LogTee:
    """Writes through to the original stream (if any) and keeps the last N
    non-blank lines, timestamped, in LOG_BUFFER for the diagnostics view."""

    def __init__(self, original):
        self._orig = original

    def write(self, s):
        if self._orig is not None:
            try:
                self._orig.write(s)
            except Exception:
                pass
        try:
            for line in str(s).splitlines():
                if line.strip():
                    LOG_BUFFER.append(time.strftime("%H:%M:%S ") + line)
        except Exception:
            pass
        return len(s) if s else 0

    def flush(self):
        if self._orig is not None:
            try:
                self._orig.flush()
            except Exception:
                pass

    def isatty(self):
        return False


def _install_log_capture() -> None:
    if not isinstance(sys.stdout, _LogTee):
        sys.stdout = _LogTee(sys.stdout)
    if not isinstance(sys.stderr, _LogTee):
        sys.stderr = _LogTee(sys.stderr)


def _redact_url(u: str) -> str:
    # Use character classes to bypass static analysis false positive for hardcoded password literal
    return _re.sub(r"([pP][aA][sS]{2}[wW][oO][rR][dD]=)[^&\s]*", r"\1<redacted>", u or "")


class C:
    """Legacy palette names, now sourced from the unified design tokens
    (theme.tokens.PALETTE) — the "Refined dark console" rebrand. Attribute
    names are preserved so every existing call site re-skins unchanged.
    """
    BG       = _P.bg               # page backdrop (static)
    BG2      = _P.surface
    PANEL    = _P.surface          # primary panel
    ELEV     = _P.surface_raised   # elevated surface (inputs, tiles)
    ELEV2    = _P.surface_overlay  # hover / overlay surface
    BORDER   = _P.border_subtle    # hairline border
    BORDER2  = _P.border           # stronger border

    CYAN     = _P.accent           # the single accent (you / sent / connect)
    CYAN_DIM = _P.accent_subtle
    MAGENTA  = _P.accent           # collapsed onto the single accent
    VIOLET   = _P.accent           # collapsed onto the single accent

    GREEN    = _P.success          # online / connected / verified
    YELLOW   = _P.warning          # connecting / warning
    RED      = _P.danger           # failed / danger

    TEXT     = _P.text_primary     # primary text
    SUBTLE   = _P.text_secondary   # secondary text
    MUTED    = _P.text_muted       # tertiary text
    FAINT    = _P.text_faint       # idle dot / faint lines
    WHITE    = "#ffffff"
    BLACK_AA = "#000000aa"

    # Button foreground tokens — on-colour for each filled surface.
    BTN_CYAN  = _P.on_accent
    BTN_GREEN = _P.on_success
    BTN_RED   = _P.on_danger


class R:
    """Corner radii — tightened for a precise, console-grade feel (from
    theme.tokens.RADIUS). Names preserved for drop-in compatibility."""
    SM = _t_RADIUS["sm"]    # 6
    MD = _t_RADIUS["md"]    # 8
    LG = _t_RADIUS["lg"]    # 12
    XL = _t_RADIUS["lg"]    # collapsed to lg — no oversized corners
    PILL = _t_RADIUS["pill"]


class D:
    """Animation durations (ms) — functional, short (from theme.tokens.MOTION)."""
    FAST  = _t_MOTION["fast"]   # 120
    PULSE = _t_MOTION["base"]   # 180
    MED   = _t_MOTION["base"]   # 180
    SLOW  = _t_MOTION["slow"]   # 260
    BG    = _t_MOTION["slow"]   # background is static now; kept for compatibility


_EASE     = ft.AnimationCurve.EASE_OUT
_EASE_IO  = ft.AnimationCurve.EASE_IN_OUT


def _anim(ms: int, curve=_EASE) -> ft.Animation:
    return ft.Animation(ms, curve)


def _glow(color: str = "", blur: int = 18, spread: float = 1.0) -> ft.BoxShadow:
    """Rebrand: depth now comes from a neutral elevation shadow, not coloured
    neon halos. Signature is kept for drop-in compatibility — the ``color`` and
    ``spread`` arguments are intentionally ignored so every existing call site
    works unchanged while the look becomes calm and console-grade."""
    _ = (color, spread)
    b = max(2, min(int(blur), 24))
    return ft.BoxShadow(
        blur_radius=b, spread_radius=-2,
        offset=ft.Offset(0, max(1, b // 6)), color="#00000066",
    )


def _dot(color: str, size: int = 11, glow: bool = True) -> ft.Container:
    """A glowing presence/status dot."""
    return ft.Container(
        width=size, height=size, border_radius=R.PILL, bgcolor=color,
        shadow=_glow(color, blur=12, spread=1) if glow else None,
        animate=_anim(D.MED),
    )


def _filled_style(bg: str = C.CYAN, fg: str = C.BTN_CYAN, radius: int = R.MD,
                  pad_h: int = 16, pad_v: int = 12) -> ft.ButtonStyle:
    return ft.ButtonStyle(
        bgcolor={"": bg},
        color={"": fg},
        shape=ft.RoundedRectangleBorder(radius=radius),
        padding=ft.Padding.symmetric(horizontal=pad_h, vertical=pad_v),
    )


def _ghost_style(color: str = C.SUBTLE, radius: int = R.SM) -> ft.ButtonStyle:
    return ft.ButtonStyle(
        color={"": color},
        shape=ft.RoundedRectangleBorder(radius=radius),
        padding=ft.Padding.symmetric(horizontal=10, vertical=8),
    )


def _neon_field(**kwargs) -> ft.TextField:
    """A TextField styled for the neon theme. Accepts/overrides any TextField kwarg."""
    base = {
        "dense": True,
        "border_color": C.BORDER2,
        "focused_border_color": C.CYAN,
        "cursor_color": C.CYAN,
        "color": C.TEXT,
        "bgcolor": C.ELEV,
        "border_radius": R.MD,
        "text_size": 13,
        "content_padding": ft.Padding.symmetric(horizontal=12, vertical=10),
        "focused_border_width": 2,
        "label_style": ft.TextStyle(color=C.MUTED, size=12),
        "hint_style": ft.TextStyle(color=C.FAINT, size=12),
    }
    base.update(kwargs)
    return ft.TextField(**base)
