"""Contact identity payload - encode/decode a shareable verification code.

Format: ``HELU1:<base64url(json)>`` where the JSON holds ONLY public identity
data: username, X25519 public key, Ed25519 public key, and the fingerprint
(which doubles as a tamper/corruption checksum). No private keys ever.
"""
import base64
import json

from crypto import compute_fingerprint

_PREFIX = "HELU1:"


def encode_identity(username: str, x25519_pub: str, ed25519_pub: str) -> str:
    payload = {
        "u": username,
        "x": x25519_pub,
        "e": ed25519_pub,
        "f": compute_fingerprint(x25519_pub),
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return _PREFIX + base64.urlsafe_b64encode(raw).decode()


def decode_identity(code: str) -> dict:
    """Parse + validate a HELU1 identity code. Raises ValueError on any problem."""
    code = (code or "").strip()
    if not code.startswith(_PREFIX):
        raise ValueError("Not a helucryptic identity code")
    try:
        raw = base64.urlsafe_b64decode(code[len(_PREFIX):])
        data = json.loads(raw)
    except Exception:
        raise ValueError("Malformed identity code")
    if not isinstance(data, dict):
        raise ValueError("Malformed identity code")
    for k in ("u", "x", "e", "f"):
        if not isinstance(data.get(k), str) or not data[k]:
            raise ValueError("Identity code is missing required fields")
    try:
        recomputed = compute_fingerprint(data["x"])
    except Exception:
        raise ValueError("Identity code has an invalid key")
    if recomputed != data["f"]:
        raise ValueError("Fingerprint does not match the key (corrupted or tampered)")
    return {
        "username": data["u"],
        "x25519_pub": data["x"],
        "ed25519_pub": data["e"],
        "fingerprint": data["f"],
    }


def qr_png_base64(text: str) -> str:
    """Render `text` as a QR code PNG, returned base64-encoded for ft.Image."""
    import io

    import qrcode

    img = qrcode.make(text)
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    return base64.b64encode(bio.getvalue()).decode()
