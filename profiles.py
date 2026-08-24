"""Multi-profile compartmentalisation (feature G).

A profile is a fully sandboxed data directory - its own keys, contacts, settings
and encrypted history - living under ``<root>/profiles/<name>/``. The active
profile is recorded in ``<root>/profiles/.active``; with no pointer the app uses
the root directly (unchanged behaviour).

Switching profiles re-points every module that resolves a data path, so the app
can hot-reload a different identity without restarting.
"""
import re
import shutil
from pathlib import Path

import paths

_SAFE = re.compile(r"[^A-Za-z0-9 _-]")


def _profiles_root() -> Path:
    return paths._root_dir() / "profiles"


def _pointer() -> Path:
    return _profiles_root() / ".active"


def _sanitize(name: str) -> str:
    return _SAFE.sub("", (name or "").strip())[:40].strip()


def list_profiles() -> list[str]:
    root = _profiles_root()
    if not root.exists():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir())


def active_name() -> str | None:
    ptr = _pointer()
    try:
        if ptr.exists():
            return ptr.read_text(encoding="utf-8").strip() or None
    except Exception:
        pass
    return None


def active_dir() -> Path | None:
    name = active_name()
    return (_profiles_root() / name) if name else None


def create_profile(name: str) -> str:
    """Create (or no-op if it exists) a profile directory. Returns the safe name."""
    safe = _sanitize(name)
    if not safe:
        raise ValueError("Profile name must contain letters, numbers, spaces, - or _")
    (_profiles_root() / safe).mkdir(parents=True, exist_ok=True)
    return safe


def set_active(name: str) -> str:
    """Mark a profile active (creating it if needed). Returns the safe name."""
    safe = create_profile(name)
    _pointer().write_text(safe, encoding="utf-8")
    return safe


def clear_active() -> None:
    ptr = _pointer()
    try:
        if ptr.exists():
            ptr.unlink()
    except OSError:
        pass


def delete_profile(name: str) -> None:
    safe = _sanitize(name)
    d = _profiles_root() / safe
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)
    if active_name() == safe:
        clear_active()


def repoint_data_dir(new_dir: Path) -> None:
    """Point every data-path-resolving module at ``new_dir`` (hot reload).

    crypto/backup read ``DATA_DIR`` per call; settings/contacts/history cache a
    path constant - so both the module ``DATA_DIR`` name and the cached constants
    are updated here. This is the one place that must know those names."""
    new_dir.mkdir(parents=True, exist_ok=True)
    import backup
    import contacts
    import crypto
    import history
    import settings

    paths.DATA_DIR            = new_dir
    crypto.DATA_DIR           = new_dir
    backup.DATA_DIR           = new_dir
    settings.DATA_DIR         = new_dir
    settings._SETTINGS_PATH   = new_dir / "settings.json"
    contacts.DATA_DIR         = new_dir
    contacts._CONTACTS_PATH   = new_dir / "contacts.json"
    history.DATA_DIR          = new_dir
    history._DB_PATH          = new_dir / "history.db"
