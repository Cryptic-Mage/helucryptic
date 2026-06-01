"""Single source of truth for the data directory.

By default data lives in the per-user home dir (`~/.helucryptic`). If a
`portable.flag` file sits next to the executable (frozen build) or the project
root (running from source), data instead lives in a local `data/` folder beside
it — for USB/offline use. Existing non-portable data is never moved automatically.
"""
import sys
from pathlib import Path

_PORTABLE_FLAG = "portable.flag"


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def resolve_data_dir(base: Path | None = None) -> Path:
    base = base if base is not None else _base_dir()
    if (base / _PORTABLE_FLAG).exists():
        return base / "data"
    return Path.home() / ".helucryptic"


def is_portable(base: Path | None = None) -> bool:
    base = base if base is not None else _base_dir()
    return (base / _PORTABLE_FLAG).exists()


# Resolved once at import — portable status doesn't change during a run.
DATA_DIR = resolve_data_dir()
