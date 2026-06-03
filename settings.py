import json
from dataclasses import asdict, dataclass, fields
from pathlib import Path

import config

from paths import DATA_DIR, write_private_text
_SETTINGS_PATH = DATA_DIR / "settings.json"

# Performance profiles map a single user choice to the concrete media caps.
PROFILES = {
    "old_pc":    {"screen_max_w": 854,  "screen_max_h": 480,  "screen_fps": 5,  "jpeg_quality": 45, "tile_render_fps": 5},
    "balanced":  {"screen_max_w": 1280, "screen_max_h": 720,  "screen_fps": 10, "jpeg_quality": 55, "tile_render_fps": 10},
    "quality":   {"screen_max_w": 1920, "screen_max_h": 1080, "screen_fps": 30, "jpeg_quality": 70, "tile_render_fps": 20},
    "overclock": {"screen_max_w": 2560, "screen_max_h": 1440, "screen_fps": 60, "jpeg_quality": 75, "tile_render_fps": 30},
}
_PROFILE_KEYS = ("screen_max_w", "screen_max_h", "screen_fps", "jpeg_quality", "tile_render_fps")
_CLAMP = {
    "screen_max_w": (320, 2560), "screen_max_h": (240, 1440),
    "screen_fps": (1, 60), "jpeg_quality": (1, 100), "tile_render_fps": (1, 60),
}


@dataclass
class Settings:
    security_mode: str = "e2ee"           # "dtls" | "e2ee"
    retention_days: int = 30              # 0 = never delete
    push_to_talk_key: str = "space"
    signaling_url: str = "ws://127.0.0.1:8000"
    low_perf_mode: bool = False
    # Performance (concrete caps + a label derived from them)
    performance_profile: str = "balanced"
    screen_max_w: int = 1280
    screen_max_h: int = 720
    screen_fps: int = 10
    jpeg_quality: int = 55
    tile_render_fps: int = 10
    # TURN relay (optional)
    turn_url: str = ""
    turn_username: str = ""
    turn_password: str = ""
    # Port forwarding (VPN/router) — bind ICE to a reachable forwarded port
    port_forward_enabled: bool = False
    forwarded_port: int = 0
    # Trust: when on, block 1-to-1 actions with unverified contacts.
    verified_only: bool = False


_FIELDS = {f.name for f in fields(Settings)}


def apply_profile(s: "Settings", name: str) -> None:
    """Overwrite the concrete caps from a named preset and set the label."""
    preset = PROFILES.get(name)
    if not preset:
        return
    for k, v in preset.items():
        setattr(s, k, v)
    s.performance_profile = name


def profile_for_values(vals: dict) -> str:
    """Return the profile name matching these concrete values, else 'custom'."""
    for name, preset in PROFILES.items():
        if all(vals.get(k) == preset[k] for k in _PROFILE_KEYS):
            return name
    return "custom"


def _clamp(s: "Settings") -> None:
    for name, (lo, hi) in _CLAMP.items():
        try:
            v = int(getattr(s, name))
        except (TypeError, ValueError):
            v = lo
        setattr(s, name, max(lo, min(hi, v)))
    # The forwarded port only matters when enabled; clamp it to a valid,
    # non-privileged range then. Left at 0 (unset) when disabled.
    if s.port_forward_enabled:
        try:
            p = int(s.forwarded_port)
        except (TypeError, ValueError):
            p = 1024
        s.forwarded_port = max(1024, min(65535, p))


def _seed_missing(s: "Settings", raw: dict) -> None:
    # Env (via config) seeds perf/TURN fields ONLY on first run (when absent
    # from settings.json). After that settings.json is authoritative.
    seeds = {
        "screen_max_w": config.SCREEN_MAX_WIDTH, "screen_max_h": config.SCREEN_MAX_HEIGHT,
        "screen_fps": config.SCREEN_FPS, "jpeg_quality": config.JPEG_QUALITY,
        "tile_render_fps": config.TILE_RENDER_FPS, "turn_url": config.TURN_URL,
        "turn_username": config.TURN_USERNAME, "turn_password": config.TURN_PASSWORD,
        "port_forward_enabled": config.PORT_FORWARD_ENABLED,
        "forwarded_port": config.FORWARDED_PORT,
    }
    for k, v in seeds.items():
        if k not in raw:
            setattr(s, k, v)


def load_settings() -> Settings:
    DATA_DIR.mkdir(exist_ok=True)
    raw = {}
    if _SETTINGS_PATH.exists():
        try:
            raw = json.loads(_SETTINGS_PATH.read_text())
        except Exception:
            raw = {}
    s = Settings(**{k: v for k, v in raw.items() if k in _FIELDS})
    _seed_missing(s, raw)
    _clamp(s)
    # Label always reflects the concrete values (handles custom env seeds).
    s.performance_profile = profile_for_values(asdict(s))
    return s


def save_settings(s: Settings) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    write_private_text(_SETTINGS_PATH, json.dumps(asdict(s), indent=2))


# Convenience re-export so callers can do `from settings import asdict`.
__all__ = ["Settings", "PROFILES", "apply_profile", "profile_for_values",
           "load_settings", "save_settings", "asdict"]
