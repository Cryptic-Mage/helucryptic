"""Encrypted profile backup/restore + emergency wipe.

A backup bundles the profile files (keys, contacts, settings, optionally the
history DB), encrypts them under a passphrase-derived key (scrypt → PASETO
v4.local / XChaCha20-Poly1305), and writes a small JSON container. Restore
validates and decrypts BEFORE touching any live file, and backs up each
existing file to `.bak` before overwriting — a failed restore leaves the
current profile intact.
"""
import base64
import json
import os
import shutil
import tempfile

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from crypto import paseto_decrypt, paseto_encrypt
from paths import DATA_DIR

_MAGIC = "HELUBAK1"
_PROFILE_FILES = ["keys.json", "contacts.json", "settings.json"]
_HISTORY_FILE = "history.db"
_HISTORY_SIDECARS = ["history.db-wal", "history.db-shm"]

# scrypt parameters (memory-hard). n=2**14 keeps it snappy while still costly.
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def export_backup(passphrase: str, include_history: bool = False) -> bytes:
    """Return an encrypted backup blob for the current profile."""
    import os

    files = {}
    names = list(_PROFILE_FILES) + ([_HISTORY_FILE] if include_history else [])
    for name in names:
        p = DATA_DIR / name
        if p.exists():
            files[name] = base64.b64encode(p.read_bytes()).decode()

    salt = os.urandom(16)
    token = paseto_encrypt({"files": files}, _derive_key(passphrase, salt))
    container = {
        "magic": _MAGIC, "v": 1, "kdf": "scrypt",
        "salt": base64.b64encode(salt).decode(), "token": token,
    }
    return json.dumps(container).encode()


def validate_and_decrypt(data: bytes, passphrase: str) -> dict:
    """Validate + decrypt a backup blob. Raises ValueError on any problem."""
    try:
        container = json.loads(data)
    except Exception:
        raise ValueError("Not a valid backup file")
    if not isinstance(container, dict) or container.get("magic") != _MAGIC:
        raise ValueError("Not a helucryptic backup file")
    try:
        salt = base64.b64decode(container["salt"])
        payload = paseto_decrypt(container["token"], _derive_key(passphrase, salt))
    except Exception:
        raise ValueError("Wrong passphrase or corrupted backup")
    if not isinstance(payload, dict) or not isinstance(payload.get("files"), dict):
        raise ValueError("Backup contents are invalid")
    return payload


def import_backup(data: bytes, passphrase: str) -> list:
    """Restore a backup. Validates fully before writing anything."""
    payload = validate_and_decrypt(data, passphrase)
    allowed = set(_PROFILE_FILES) | {_HISTORY_FILE}
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    decoded = {}
    for name, b64 in payload["files"].items():
        if name not in allowed:
            continue  # ignore unexpected entries
        try:
            decoded[name] = base64.b64decode(b64)
        except Exception:
            raise ValueError(f"Backup entry {name} is invalid")

    temps = {}
    backups = {}
    restored = []
    replaced = []
    try:
        # Stage every restored file first. Live files are untouched until all
        # decoded bytes have been written successfully.
        for name, raw in decoded.items():
            fd, tmp_name = tempfile.mkstemp(prefix=f".restore-{name}.", dir=DATA_DIR)
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            temps[name] = DATA_DIR / tmp_name

        for name in decoded:
            target = DATA_DIR / name
            backup_path = target.with_name(target.name + ".bak")
            if target.exists():
                shutil.copy2(target, backup_path)
                backups[name] = backup_path
            # If we are overwriting history.db, also back up and remove existing WAL/SHM sidecars
            if name == _HISTORY_FILE:
                for sidecar in _HISTORY_SIDECARS:
                    sidecar_path = DATA_DIR / sidecar
                    if sidecar_path.exists():
                        sidecar_bak = sidecar_path.with_name(sidecar_path.name + ".bak")
                        try:
                            shutil.copy2(sidecar_path, sidecar_bak)
                            backups[sidecar] = sidecar_bak
                            sidecar_path.unlink()
                        except Exception:
                            # if copy/delete fails, try at least to unlink the sidecar
                            try:
                                sidecar_path.unlink()
                            except Exception:
                                pass
            os.replace(temps[name], target)
            replaced.append(name)
            restored.append(name)
    except Exception as ex:
        # Best-effort rollback for any file already swapped into place.
        for name in reversed(replaced):
            target = DATA_DIR / name
            backup_path = backups.get(name)
            try:
                if backup_path and backup_path.exists():
                    shutil.copy2(backup_path, target)
                elif target.exists():
                    target.unlink()
            except Exception:
                pass
        # Restore database sidecar files if they were backed up during this failed session
        for sidecar in _HISTORY_SIDECARS:
            sidecar_path = DATA_DIR / sidecar
            sidecar_bak = backups.get(sidecar)
            if sidecar_bak and sidecar_bak.exists():
                try:
                    if sidecar_path.exists():
                        sidecar_path.unlink()
                    shutil.copy2(sidecar_bak, sidecar_path)
                except Exception:
                    pass
        raise ValueError(f"Could not restore backup: {type(ex).__name__}") from ex
    finally:
        for tmp in temps.values():
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass
    return restored


def emergency_wipe() -> list:
    """Delete the known profile files (and history sidecars). Touches nothing else."""
    removed = []
    for name in _PROFILE_FILES + [_HISTORY_FILE] + _HISTORY_SIDECARS:
        p = DATA_DIR / name
        try:
            if p.exists():
                p.unlink()
                removed.append(name)
        except Exception:
            pass
    return removed
