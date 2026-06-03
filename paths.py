"""Single source of truth for the data directory.

By default data lives in the per-user home dir (`~/.helucryptic`). If a
`portable.flag` file sits next to the executable (frozen build) or the project
root (running from source), data instead lives in a local `data/` folder beside
it — for USB/offline use. Existing non-portable data is never moved automatically.
"""
import sys
import os
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


def write_private_text(path: Path, text: str) -> None:
    """Atomically write user-private app data with restrictive permissions."""
    write_private_bytes(path, text.encode("utf-8"))


def write_private_bytes(path: Path, data: bytes) -> None:
    """Atomically write user-private bytes with restrictive permissions.

    POSIX modes (0o600) are honoured on Unix; on Windows they are a no-op, so we
    additionally tighten the parent directory ACL to the current user (see
    :func:`harden_dir`) the first time the data dir is created.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def harden_dir(path: Path) -> None:
    """Best-effort: restrict ``path``'s ACL to the current user on Windows.

    On the user profile this is usually already the case, but a portable
    ``data/`` folder beside the executable may inherit broader permissions.
    Failures are swallowed — this is defence-in-depth, not a hard requirement.
    """
    if sys.platform != "win32":
        return
    try:
        import subprocess

        user = os.environ.get("USERNAME") or ""
        if not user:
            return
        # Disable inheritance (copy current ACEs) then grant only this user.
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=10, check=False,
        )
    except Exception:
        pass
