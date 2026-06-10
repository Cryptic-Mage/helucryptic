import base64
import hashlib
import json
import logging
import sys
from datetime import UTC, datetime

# pyrefly: ignore [missing-import]
import pyseto
# pyrefly: ignore [missing-import]
from cryptography.hazmat.primitives import hashes
# pyrefly: ignore [missing-import]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
# pyrefly: ignore [missing-import]
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
# pyrefly: ignore [missing-import]
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# pyrefly: ignore [missing-import]
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
# pyrefly: ignore [missing-import]
from pyseto import Key

import secure_store
from paths import DATA_DIR, harden_dir, write_private_bytes
from constants.crypto_constants import KEYS_FILE, REQUIRED_KEY_FIELDS

# Configure standard logger
logger = logging.getLogger("helucryptic.crypto")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _formatter = logging.Formatter("[crypto] %(message)s")
    _handler.setFormatter(_formatter)
    logger.addHandler(_handler)


def _keys_path():
    # Resolved per-call (not cached) so tests can monkeypatch DATA_DIR.
    return DATA_DIR / KEYS_FILE


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    harden_dir(DATA_DIR)


# ---------------------------------------------------------------------------
# Key generation & persistence
# ---------------------------------------------------------------------------

def generate_and_save_keys() -> dict:
    ensure_data_dir()
    logger.info("Generating a fresh set of identity keys (X25519 and Ed25519)")
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
        "created_at": datetime.now(UTC).isoformat(),
    }
    _save_keys(keys)
    logger.info("Successfully generated and saved identity keys to %s", _keys_path())
    return keys


def _save_keys(keys: dict) -> None:
    """Persist the identity keys, wrapped with the OS keystore where available."""
    ensure_data_dir()
    logger.info("Saving identity keys")
    try:
        plaintext = json.dumps(keys, indent=2).encode("utf-8")
        write_private_bytes(_keys_path(), secure_store.protect(plaintext))
    except Exception:
        logger.exception("Failed to save identity keys")
        raise


def export_keys_plaintext(path=None) -> bytes:
    """Return the identity keys as plaintext JSON bytes (DPAPI-unwrapped).

    Used by the backup system so a backup stays portable across machines — the
    backup is itself passphrase-encrypted, and DPAPI blobs are machine-bound.
    """
    raw = (path or _keys_path()).read_bytes()
    return secure_store.unprotect(raw)


def import_keys_plaintext(data: bytes) -> dict:
    """Validate an exported keys file and install it as the active identity.

    Accepts plaintext JSON (the portable export format) or a DPAPI blob from
    THIS machine. Raises ValueError on anything malformed, BEFORE touching the
    live key file — a failed import leaves the current identity intact.
    """
    try:
        plain = secure_store.unprotect(data)
        keys = json.loads(plain)
    except Exception as ex:
        raise ValueError(
            "Not a valid helucryptic keys file (it may be a DPAPI-wrapped export "
            "from another machine — re-export with the current app version)"
        ) from ex
    if not isinstance(keys, dict) or not REQUIRED_KEY_FIELDS.issubset(keys):
        raise ValueError("Keys file is missing required fields")
    for field in REQUIRED_KEY_FIELDS:
        try:
            if len(base64.b64decode(keys[field])) != 32:
                raise ValueError
        except Exception:
            raise ValueError(f"Keys file field {field!r} is not a valid 32-byte key")
    _save_keys(keys)
    logger.info("Imported identity keys")
    return keys


def load_or_create_keys() -> dict:
    path = _keys_path()
    if path.exists():
        logger.info("Loading existing identity keys from %s", path)
        try:
            raw = path.read_bytes()
            keys = json.loads(secure_store.unprotect(raw))
        except (OSError, ValueError) as ex:
            logger.error("Failed to read identity keys: file at %s is corrupted", path)
            raise RuntimeError(
                f"Your key file at {path} is corrupted and could not be read ({ex}). "
                f"Restore it from a backup/export, or delete it to generate a new "
                f"identity (this loses your existing contacts' verification)."
            ) from ex
        if not REQUIRED_KEY_FIELDS.issubset(keys):
            logger.error("Failed to read identity keys: missing required fields in %s", path)
            raise RuntimeError(
                f"Your key file at {path} is missing required fields. "
                f"Restore it from a backup/export, or delete it to generate a new identity."
            )
        # Migrate a legacy plaintext key file to the OS-wrapped format in place.
        if secure_store.available() and not secure_store.is_protected(raw):
            try:
                logger.info("Migrating legacy plaintext key file to OS-wrapped format in place")
                _save_keys(keys)
            except Exception as e:
                logger.warning("Failed to migrate legacy key file to OS-wrapped format: %s", e)
        return keys
    logger.info("Key file does not exist at %s. Creating a new identity...", path)
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


def generate_ephemeral_x25519() -> tuple[str, str]:
    """Fresh per-session X25519 keypair → (private_b64, public_b64)."""
    priv = X25519PrivateKey.generate()
    priv_b64 = base64.b64encode(
        priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode()
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return priv_b64, pub_b64


def derive_session_key_v2(
    my_x25519_priv_b64: str,
    my_eph_priv_b64: str,
    peer_x25519_pub_b64: str,
    peer_eph_pub_b64: str,
) -> bytes:
    """Forward-secret, authenticated session key (helucryptic-session-v2).

    Combines three X25519 exchanges — ephemeral×ephemeral (forward secrecy) plus
    the two static×ephemeral cross terms (binds the session to both long-term
    identities). The two peers order the cross terms by static public key so they
    derive an identical key regardless of who initiated. Knowledge of the static
    private keys alone cannot recover the key: every term but the cross-binding
    requires an ephemeral private, and the ephemerals are discarded after use.
    """
    if not all((my_x25519_priv_b64, my_eph_priv_b64, peer_x25519_pub_b64, peer_eph_pub_b64)):
        raise ValueError("derive_session_key_v2 called before ephemeral hello complete")

    my_x_priv   = X25519PrivateKey.from_private_bytes(base64.b64decode(my_x25519_priv_b64))
    my_eph_priv = X25519PrivateKey.from_private_bytes(base64.b64decode(my_eph_priv_b64))
    peer_x_pub_raw   = base64.b64decode(peer_x25519_pub_b64)
    peer_eph_pub_raw = base64.b64decode(peer_eph_pub_b64)
    peer_x_pub   = X25519PublicKey.from_public_bytes(peer_x_pub_raw)
    peer_eph_pub = X25519PublicKey.from_public_bytes(peer_eph_pub_raw)

    my_x_pub_raw = my_x_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    dh_ee = my_eph_priv.exchange(peer_eph_pub)
    # Canonical ordering: "low" is the peer with the smaller static public key.
    if my_x_pub_raw < peer_x_pub_raw:          # I am low
        dh_a = my_x_priv.exchange(peer_eph_pub)    # low_static × high_eph
        dh_b = my_eph_priv.exchange(peer_x_pub)    # low_eph × high_static
    else:                                       # I am high
        dh_a = my_eph_priv.exchange(peer_x_pub)    # low_static × high_eph
        dh_b = my_x_priv.exchange(peer_eph_pub)    # low_eph × high_static

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"helucryptic-session-v2",
    ).derive(dh_ee + dh_a + dh_b)


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

def _ed25519_signing_key(priv_b64: str) -> Key:
    # pyseto v4.public: build the signing key from the raw Ed25519 private seed.
    # (Only `d` may be set for a signing key; `x` alone makes a verify key.)
    return Key.from_asymmetric_key_params(4, d=base64.b64decode(priv_b64))


def _ed25519_verify_key(pub_b64: str) -> Key:
    return Key.from_asymmetric_key_params(4, x=base64.b64decode(pub_b64))


def paseto_sign(payload: dict, ed25519_priv_b64: str, ed25519_pub_b64: str) -> str:
    logger.debug("Signing PASETO token")
    _ = ed25519_pub_b64  # Parameter kept for signature compatibility
    key = _ed25519_signing_key(ed25519_priv_b64)
    token = pyseto.encode(key, payload=json.dumps(payload).encode())
    return token.decode() if isinstance(token, bytes) else token


def paseto_verify(token_str: str, ed25519_pub_b64: str) -> dict:
    logger.debug("Verifying PASETO token")
    key = _ed25519_verify_key(ed25519_pub_b64)
    decoded = pyseto.decode(key, token_str.encode() if isinstance(token_str, str) else token_str)
    return json.loads(decoded.payload)


# ---------------------------------------------------------------------------
# Membership certificates (feature D) — the room creator vouches for a member by
# signing (room_id, member username, member ed25519 key) with its identity key.
# A PASETO v4.public token, so verification is the same Ed25519 path as the hello.
# ---------------------------------------------------------------------------

def issue_membership_cert(
    creator_ed25519_priv_b64: str,
    creator_ed25519_pub_b64: str,
    room_id: str,
    member_username: str,
    member_ed25519_pub_b64: str,
) -> str:
    """Creator-signed membership cert binding a member's identity to a room."""
    logger.info("Issuing membership certificate for user=%s in room=%s", member_username, room_id)
    payload = {
        "r":   room_id,
        "u":   member_username,
        "e":   member_ed25519_pub_b64,
        "iat": datetime.now(UTC).isoformat(),
    }
    return paseto_sign(payload, creator_ed25519_priv_b64, creator_ed25519_pub_b64)


def verify_membership_cert(
    cert: str,
    creator_ed25519_pub_b64: str,
    room_id: str,
    member_username: str,
    member_ed25519_pub_b64: str,
) -> bool:
    """True iff `cert` is a valid creator signature binding this member to this
    room (and the bound key matches the member's actual hello key)."""
    logger.info("Verifying membership certificate for user=%s in room=%s", member_username, room_id)
    if not cert or not creator_ed25519_pub_b64:
        logger.warning("Empty cert or missing creator key; verification failed")
        return False
    try:
        payload = paseto_verify(cert, creator_ed25519_pub_b64)
    except Exception as e:
        logger.warning("Membership certificate verification failed: %s", e)
        return False
    
    success = (
        payload.get("r") == room_id
        and payload.get("u") == member_username
        and payload.get("e") == member_ed25519_pub_b64
    )
    if success:
        logger.info("Membership certificate verification succeeded for user=%s in room=%s", member_username, room_id)
    else:
        logger.warning("Membership certificate payload mismatch: expected (room=%s, user=%s) but got (room=%s, user=%s)",
                       room_id, member_username, payload.get("r"), payload.get("u"))
    return success


def paseto_encrypt(payload: dict, symmetric_key: bytes) -> str:
    logger.debug("Encrypting payload using PASETO v4 local")
    key = Key.new(version=4, purpose="local", key=symmetric_key)
    token = pyseto.encode(key, payload=json.dumps(payload).encode())
    return token.decode() if isinstance(token, bytes) else token


def paseto_decrypt(token_str: str, symmetric_key: bytes) -> dict:
    logger.debug("Decrypting token using PASETO v4 local")
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
