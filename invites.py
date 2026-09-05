"""Room invite code - a shareable code that configures the receiver's client to
reach a signaling server and join a group room (Quiet-style invite, adapted).

Format: ``HELU-INV1:<base64url(json)>`` (mirrors identity.py's ``HELU1:``).

The JSON payload uses compact keys; only ``r`` (room) and ``u`` (signaling URL)
are required - the rest are optional carriers for later features:

    r  room_id              ROOM-XXXX
    u  signaling_url        ws:// wss:// http:// https://
    p  server_password      optional shared access token
    k  psk                  optional base64 32-byte pre-shared key (channel auth)
    c  creator_ed25519_pub  optional, for membership PKI (creator's signing key)
    v  version              format version (1)
    h  checksum             sha256 of the canonical payload (sans h), hex[:16]

The checksum is a corruption/tamper guard, NOT a secret - anyone holding the
code can read every field. Treat the whole code as sensitive (it may carry the
server password and/or PSK) and share it over a trusted channel.
"""
import base64
import hashlib
import json
import logging
import sys

# Configure standard logger
logger = logging.getLogger("helucryptic.invites")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    _stream = sys.stderr if sys.stderr is not None else sys.stdout
    if _stream is not None:
        _handler = logging.StreamHandler(_stream)
        _formatter = logging.Formatter("[invites] %(message)s")
        _handler.setFormatter(_formatter)
        logger.addHandler(_handler)
    else:
        logger.addHandler(logging.NullHandler())


from constants.invite_constants import FIELDS, PREFIX, ROOM_RE, URL_RE, VERSION


def generate_psk() -> str:
    """A fresh base64 32-byte pre-shared key for PSK channel auth (feature C)."""
    import secrets
    logger.info("Generating a fresh 32-byte PSK for channel auth")
    return base64.b64encode(secrets.token_bytes(32)).decode()


def _checksum(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()[:16]


def encode_invite(
    room_id: str,
    signaling_url: str,
    password: str | None = None,
    psk: str | None = None,
    creator_ed25519_pub: str | None = None,
    ephemeral: bool = False,
) -> str:
    """Build a HELU-INV1 invite code. Raises ValueError on invalid room/URL."""
    room_id = (room_id or "").strip().upper()
    signaling_url = (signaling_url or "").strip()
    
    logger.info("Encoding invite: room_id=%s, url=%s, ephemeral=%s, has_password=%s, has_psk=%s",
                room_id, signaling_url, ephemeral, password is not None, psk is not None)

    if not ROOM_RE.match(room_id):
        logger.error("Failed to encode invite: Invalid room_id=%r", room_id)
        raise ValueError("Invalid room id (expected ROOM-XXXX)")
    if not URL_RE.match(signaling_url):
        logger.error("Failed to encode invite: Invalid signaling_url=%r", signaling_url)
        raise ValueError("Invalid signaling URL (expected ws://, wss://, http:// or https://)")
    if psk is not None:
        try:
            if len(base64.b64decode(psk)) != 32:
                raise ValueError
        except Exception:
            logger.error("Failed to encode invite: PSK must be base64 of 32 bytes")
            raise ValueError("PSK must be base64 of 32 bytes")

    payload: dict = {
        FIELDS["version"]:       VERSION,
        FIELDS["room_id"]:       room_id,
        FIELDS["signaling_url"]: signaling_url,
    }
    if password:
        payload[FIELDS["password"]] = password
    if psk:
        payload[FIELDS["psk"]] = psk
    if creator_ed25519_pub:
        payload[FIELDS["creator_ed25519_pub"]] = creator_ed25519_pub
    if ephemeral:
        payload[FIELDS["ephemeral"]] = 1

    payload["h"] = _checksum(payload)
    raw = json.dumps(payload, separators=(",", ":")).encode()
    
    logger.info("Successfully encoded invite code for room_id=%s", room_id)
    return PREFIX + base64.urlsafe_b64encode(raw).decode()


def _validate_basic_structure(code: str) -> dict:
    code = (code or "").strip()
    if not code.startswith(PREFIX):
        logger.warning("Failed to decode invite: does not start with prefix %s", PREFIX)
        raise ValueError("Not a helucryptic invite code")
    try:
        raw = base64.urlsafe_b64decode(code[len(PREFIX):])
        data = json.loads(raw)
    except Exception as e:
        logger.warning("Failed to decode invite: malformed base64/JSON (%s)", e)
        raise ValueError("Malformed invite code")
    if not isinstance(data, dict):
        logger.warning("Failed to decode invite: payload is not a dict")
        raise ValueError("Malformed invite code")
    return data


def _validate_fields(out: dict) -> None:
    if not isinstance(out["room_id"], str) or not ROOM_RE.match(out["room_id"]):
        logger.warning("Failed to decode invite: invalid room_id")
        raise ValueError("Invite code has an invalid room id")
    if not isinstance(out["signaling_url"], str) or not URL_RE.match(out["signaling_url"]):
        logger.warning("Failed to decode invite: invalid signaling URL")
        raise ValueError("Invite code has an invalid signaling URL")
    if out["psk"] is not None:
        try:
            if len(base64.b64decode(out["psk"])) != 32:
                raise ValueError
        except Exception:
            logger.warning("Failed to decode invite: invalid PSK")
            raise ValueError("Invite code has an invalid PSK")


def decode_invite(code: str) -> dict:
    """Parse + validate a HELU-INV1 invite code. Raises ValueError on any problem.

    Returns a dict with full-name keys: room_id, signaling_url, password, psk,
    creator_ed25519_pub, version (missing optional fields are None)."""
    logger.info("Decoding invite code")
    data = _validate_basic_structure(code)

    supplied = data.pop("h", None)
    if not isinstance(supplied, str) or _checksum(data) != supplied:
        logger.warning("Failed to decode invite: checksum mismatch")
        raise ValueError("Invite code is corrupted or was tampered with")

    out = {full: data.get(short) for full, short in FIELDS.items()}
    out["ephemeral"] = bool(out.get("ephemeral"))
    _validate_fields(out)
    
    logger.info("Successfully decoded invite code for room_id=%s, signaling_url=%s",
                out.get("room_id"), out.get("signaling_url"))
    return out
