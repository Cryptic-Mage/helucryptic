import base64

import pytest

import identity
from crypto import compute_fingerprint

# A valid 32-byte X25519 public key (base64) and any Ed25519 pub stand-in.
_X = base64.b64encode(bytes(range(32))).decode()
_E = base64.b64encode(bytes(range(32, 64))).decode()


def test_roundtrip():
    code = identity.encode_identity("alice", _X, _E)
    assert code.startswith("HELU1:")
    out = identity.decode_identity(code)
    assert out["username"] == "alice"
    assert out["x25519_pub"] == _X
    assert out["ed25519_pub"] == _E
    assert out["fingerprint"] == compute_fingerprint(_X)


def test_rejects_bad_prefix():
    with pytest.raises(ValueError):
        identity.decode_identity("NOPE:abc")


def test_rejects_malformed_base64():
    with pytest.raises(ValueError):
        identity.decode_identity("HELU1:!!!not base64!!!")


def test_rejects_missing_fields():
    import json
    raw = base64.urlsafe_b64encode(json.dumps({"u": "x"}).encode()).decode()
    with pytest.raises(ValueError):
        identity.decode_identity("HELU1:" + raw)


def test_rejects_fingerprint_mismatch():
    import json
    bad = {"u": "alice", "x": _X, "e": _E, "f": "00 00 00 00"}
    raw = base64.urlsafe_b64encode(json.dumps(bad).encode()).decode()
    with pytest.raises(ValueError):
        identity.decode_identity("HELU1:" + raw)


def test_qr_png_base64_renders():
    b64 = identity.qr_png_base64("HELU1:test")
    assert isinstance(b64, str) and len(b64) > 50
    assert base64.b64decode(b64)[:8] == b"\x89PNG\r\n\x1a\n"
