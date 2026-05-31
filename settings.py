import json
from dataclasses import asdict, dataclass
from pathlib import Path

DATA_DIR = Path.home() / ".helucryptic"
_SETTINGS_PATH = DATA_DIR / "settings.json"

_FIELDS = {"security_mode", "retention_days", "push_to_talk_key", "signaling_url"}


@dataclass
class Settings:
    security_mode: str = "e2ee"          # "dtls" | "e2ee"
    retention_days: int = 30             # 0 = never delete
    push_to_talk_key: str = "space"
    signaling_url: str = "ws://127.0.0.1:8000"


def load_settings() -> Settings:
    DATA_DIR.mkdir(exist_ok=True)
    if _SETTINGS_PATH.exists():
        try:
            data = json.loads(_SETTINGS_PATH.read_text())
            return Settings(**{k: v for k, v in data.items() if k in _FIELDS})
        except Exception:
            pass
    return Settings()


def save_settings(s: Settings) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    _SETTINGS_PATH.write_text(json.dumps(asdict(s), indent=2))
