import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
import pyseto
from pyseto import Key

from paths import DATA_DIR


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Key generation & persistence
# ---------------------------------------------------------------------------

def generate_and_save_keys() -> dict:
    ensure_data_dir()
    x_priv = X25519PrivateKey.generate()
    e_priv = Ed25519PrivateKey.generate()
    keys = {
        "x25519_private": base64.b64encode(
            x_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ).decode(),
        "x25519_public": base64.b64encode(
            x_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode(),
        "ed25519_private": base64.b64encode(
            e_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ).decode(),
        "ed25519_public": base64.b64encode(
            e_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    (DATA_DIR / "keys.json").write_text(json.dumps(keys, indent=2))
    return keys


_REQUIRED_KEY_FIELDS = {"x25519_private", "x25519_public", "ed25519_private", "ed25519_public"}


def load_or_create_keys() -> dict:
    path = DATA_DIR / "keys.json"
    if path.exists():
        try:
            keys = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as ex:
            raise RuntimeError(
                f"Your key file at {path} is corrupted and could not be read ({ex}). "
                f"Restore it from a backup/export, or delete it to generate a new "
                f"identity (this loses your existing contacts' verification)."
            ) from ex
        if not _REQUIRED_KEY_FIELDS.issubset(keys):
            raise RuntimeError(
                f"Your key file at {path} is missing required fields. "
                f"Restore it from a backup/export, or delete it to generate a new identity."
            )
        return keys
    return generate_and_save_keys()


# ---------------------------------------------------------------------------
# HKDF helpers
# ---------------------------------------------------------------------------

def derive_session_key(my_x25519_priv_b64: str, peer_x25519_pub_b64: str) -> bytes:
    if not my_x25519_priv_b64 or not peer_x25519_pub_b64:
        raise ValueError("derive_session_key called before hello handshake complete")
    my_priv = X25519PrivateKey.from_private_bytes(base64.b64decode(my_x25519_priv_b64))
    peer_pub = X25519PublicKey.from_public_bytes(base64.b64decode(peer_x25519_pub_b64))
    shared = my_priv.exchange(peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"helucryptic-session-v1",
    ).derive(shared)


def derive_history_key(ed25519_priv_b64: str) -> bytes:
    raw = base64.b64decode(ed25519_priv_b64)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"helucryptic-history-v1",
    ).derive(raw)


# ---------------------------------------------------------------------------
# PASETO v4 helpers
# ---------------------------------------------------------------------------

def _ed25519_signing_key(priv_b64: str, pub_b64: str) -> Key:
    # pyseto v4.public: build the signing key from the raw Ed25519 private seed.
    # (Only `d` may be set for a signing key; `x` alone makes a verify key.)
    return Key.from_asymmetric_key_params(4, d=base64.b64decode(priv_b64))


def _ed25519_verify_key(pub_b64: str) -> Key:
    return Key.from_asymmetric_key_params(4, x=base64.b64decode(pub_b64))


def paseto_sign(payload: dict, ed25519_priv_b64: str, ed25519_pub_b64: str) -> str:
    key = _ed25519_signing_key(ed25519_priv_b64, ed25519_pub_b64)
    token = pyseto.encode(key, payload=json.dumps(payload).encode())
    return token.decode() if isinstance(token, bytes) else token


def paseto_verify(token_str: str, ed25519_pub_b64: str) -> dict:
    key = _ed25519_verify_key(ed25519_pub_b64)
    decoded = pyseto.decode(key, token_str.encode() if isinstance(token_str, str) else token_str)
    return json.loads(decoded.payload)


def paseto_encrypt(payload: dict, symmetric_key: bytes) -> str:
    key = Key.new(version=4, purpose="local", key=symmetric_key)
    token = pyseto.encode(key, payload=json.dumps(payload).encode())
    return token.decode() if isinstance(token, bytes) else token


def paseto_decrypt(token_str: str, symmetric_key: bytes) -> dict:
    key = Key.new(version=4, purpose="local", key=symmetric_key)
    decoded = pyseto.decode(key, token_str.encode() if isinstance(token_str, str) else token_str)
    return json.loads(decoded.payload)


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

def compute_fingerprint(x25519_pub_b64: str) -> str:
    raw = base64.b64decode(x25519_pub_b64)
    digest = hashlib.sha256(raw).hexdigest().upper()
    return " ".join(digest[i:i + 4] for i in range(0, 64, 4))
