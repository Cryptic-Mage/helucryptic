"""Room invite code — a shareable code that configures the receiver's client to
reach a signaling server and join a group room (Quiet-style invite, adapted).

Format: ``HELU-INV1:<base64url(json)>`` (mirrors identity.py's ``HELU1:``).

The JSON payload uses compact keys; only ``r`` (room) and ``u`` (signaling URL)
are required — the rest are optional carriers for later features:

    r  room_id              ROOM-XXXX
    u  signaling_url        ws:// wss:// http:// https://
    p  server_password      optional shared access token
    k  psk                  optional base64 32-byte pre-shared key (channel auth)
    c  creator_ed25519_pub  optional, for membership PKI (creator's signing key)
    v  version              format version (1)
    h  checksum             sha256 of the canonical payload (sans h), hex[:16]

The checksum is a corruption/tamper guard, NOT a secret — anyone holding the
code can read every field. Treat the whole code as sensitive (it may carry the
server password and/or PSK) and share it over a trusted channel.
"""
import base64
import hashlib
import json
import re

_PREFIX  = "HELU-INV1:"
_VERSION = 1

_ROOM_RE   = re.compile(r"^ROOM-[A-Z0-9]{4}$")
_URL_RE    = re.compile(r"^(ws|wss|http|https)://", re.IGNORECASE)

# Map full names <-> compact JSON keys (everything except the checksum 'h').
_FIELDS = {
    "room_id":             "r",
    "signaling_url":       "u",
    "password":            "p",
    "psk":                 "k",
    "creator_ed25519_pub": "c",
    "ephemeral":           "m",
    "version":             "v",
}


def generate_psk() -> str:
    """A fresh base64 32-byte pre-shared key for PSK channel auth (feature C)."""
    import secrets
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
    if not _ROOM_RE.match(room_id):
        raise ValueError("Invalid room id (expected ROOM-XXXX)")
    if not _URL_RE.match(signaling_url):
        raise ValueError("Invalid signaling URL (expected ws://, wss://, http:// or https://)")
    if psk is not None:
        try:
            if len(base64.b64decode(psk)) != 32:
                raise ValueError
        except Exception:
            raise ValueError("PSK must be base64 of 32 bytes")

    payload: dict = {
        _FIELDS["version"]:       _VERSION,
        _FIELDS["room_id"]:       room_id,
        _FIELDS["signaling_url"]: signaling_url,
    }
    if password:
        payload[_FIELDS["password"]] = password
    if psk:
        payload[_FIELDS["psk"]] = psk
    if creator_ed25519_pub:
        payload[_FIELDS["creator_ed25519_pub"]] = creator_ed25519_pub
    if ephemeral:
        payload[_FIELDS["ephemeral"]] = 1

    payload["h"] = _checksum(payload)
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return _PREFIX + base64.urlsafe_b64encode(raw).decode()


def decode_invite(code: str) -> dict:
    """Parse + validate a HELU-INV1 invite code. Raises ValueError on any problem.

    Returns a dict with full-name keys: room_id, signaling_url, password, psk,
    creator_ed25519_pub, version (missing optional fields are None)."""
    code = (code or "").strip()
    if not code.startswith(_PREFIX):
        raise ValueError("Not a helucryptic invite code")
    try:
        raw = base64.urlsafe_b64decode(code[len(_PREFIX):])
        data = json.loads(raw)
    except Exception:
        raise ValueError("Malformed invite code")
    if not isinstance(data, dict):
        raise ValueError("Malformed invite code")

    supplied = data.pop("h", None)
    if not isinstance(supplied, str) or _checksum(data) != supplied:
        raise ValueError("Invite code is corrupted or was tampered with")

    out = {full: data.get(short) for full, short in _FIELDS.items()}
    out["ephemeral"] = bool(out.get("ephemeral"))
    if not isinstance(out["room_id"], str) or not _ROOM_RE.match(out["room_id"] or ""):
        raise ValueError("Invite code has an invalid room id")
    if not isinstance(out["signaling_url"], str) or not _URL_RE.match(out["signaling_url"] or ""):
        raise ValueError("Invite code has an invalid signaling URL")
    if out["psk"] is not None:
        try:
            if len(base64.b64decode(out["psk"])) != 32:
                raise ValueError
        except Exception:
            raise ValueError("Invite code has an invalid PSK")
    return out
