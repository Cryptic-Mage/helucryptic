"""Centralised runtime configuration.

Reads settings from environment variables (optionally seeded from a `.env`
file) so that no credentials or deployment URLs are hardcoded in source. Works
both when running from source and when bundled into a PyInstaller/Nuitka
executable (the bundled `.env`, if present, is found via ``sys._MEIPASS``).

Precedence for every value:  real environment variable  >  bundled .env  >
project .env  >  built-in default.
"""
import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
except Exception:  # python-dotenv missing - env vars still work, just no .env file
    def load_dotenv(*_a, **_k):  # type: ignore
        return False


def _bundle_dir() -> Path:
    """Directory that holds bundled data files (frozen) or the source tree."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)))
    return Path(__file__).resolve().parent


# Load a `.env` next to the bundle/source first, then fall back to the CWD so a
# real environment variable always wins (load_dotenv never overrides existing).
_bundled_env = _bundle_dir() / ".env"
if _bundled_env.exists():
    load_dotenv(_bundled_env)
load_dotenv()  # also picks up a .env in the current working directory


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int_range(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


# --- Signaling ---------------------------------------------------------------
# Default points at the public Cloudflare Worker so a fresh checkout still
# connects; override in `.env` for self-hosting.
DEFAULT_SIGNALING_URL = os.getenv(
    "HELUCRYPTIC_SIGNALING_URL",
    "wss://helucryptic-signaling.crypticmage00.workers.dev/",
)

# Shared access token for the official server. Empty string means "no password
# configured" - the client sends nothing and the server (if it also has no
# password configured) allows the connection. Set this in `.env`.
SERVER_PASSWORD = os.getenv("HELUCRYPTIC_SERVER_PASSWORD", "")

# --- Performance -------------------------------------------------------------
# Low-perf mode tightens defaults for old/weak hardware (lower screen-share
# resolution + frame rate). Users can still override per-call in the UI.
LOW_PERF_MODE = _bool(os.getenv("HELUCRYPTIC_LOW_PERF_MODE"), False)

# Screen-share capture caps fed to the (software) video encoder. Ceilings allow
# the "overclock" profile (2560x1440 @ 60). These are first-run seeds for the
# in-app performance profile (see settings.py); after that Settings is the
# authoritative control.
SCREEN_MAX_WIDTH  = _int_range("HELUCRYPTIC_SCREEN_MAX_WIDTH",  960 if LOW_PERF_MODE else 1280, 320, 2560)
SCREEN_MAX_HEIGHT = _int_range("HELUCRYPTIC_SCREEN_MAX_HEIGHT", 540 if LOW_PERF_MODE else 720, 240, 1440)
SCREEN_FPS        = _int_range("HELUCRYPTIC_SCREEN_FPS",        10 if LOW_PERF_MODE else 15, 1, 60)
JPEG_QUALITY      = _int_range("HELUCRYPTIC_JPEG_QUALITY",      45 if LOW_PERF_MODE else 55, 1, 100)
TILE_RENDER_FPS   = _int_range("HELUCRYPTIC_TILE_RENDER_FPS",   5 if LOW_PERF_MODE else 10, 1, 60)

# --- TURN (optional NAT relay) ----------------------------------------------
# Public STUN alone fails behind symmetric / carrier-grade NAT. Provide a TURN
# relay here to make those connections succeed.
TURN_URL      = os.getenv("HELUCRYPTIC_TURN_URL", "")
TURN_USERNAME = os.getenv("HELUCRYPTIC_TURN_USERNAME", "")
TURN_PASSWORD = os.getenv("HELUCRYPTIC_TURN_PASSWORD", "")

# --- Port forwarding (optional) ---------------------------------------------
# When a user has a genuinely reachable forwarded port (Proton VPN P2P port
# forwarding or a manual router forward on a real public IP), bind ICE to it so
# a symmetric-NAT peer can connect directly. First-run seeds only.
PORT_FORWARD_ENABLED = _bool(os.getenv("HELUCRYPTIC_PORT_FORWARD_ENABLED"), False)
FORWARDED_PORT       = _int_range("HELUCRYPTIC_FORWARDED_PORT", 0, 0, 65535)
