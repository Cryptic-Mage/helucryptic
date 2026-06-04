"""Tests for the HELU-INV1 room invite codec (invites.py)."""
import base64

import pytest

import invites


def test_roundtrip_minimal():
    code = invites.encode_invite("ROOM-AB12", "ws://1.2.3.4:8000")
    assert code.startswith("HELU-INV1:")
    out = invites.decode_invite(code)
    assert out["room_id"] == "ROOM-AB12"
    assert out["signaling_url"] == "ws://1.2.3.4:8000"
    assert out["password"] is None
    assert out["psk"] is None
    assert out["creator_ed25519_pub"] is None
    assert out["version"] == 1


def test_roundtrip_full():
    psk = invites.generate_psk()
    code = invites.encode_invite(
        "ROOM-ZZ99", "wss://signal.example.com",
        password="hunter2", psk=psk, creator_ed25519_pub="ZWQyNTUxOXB1Yg==",
    )
    out = invites.decode_invite(code)
    assert out["room_id"] == "ROOM-ZZ99"
    assert out["signaling_url"] == "wss://signal.example.com"
    assert out["password"] == "hunter2"
    assert out["psk"] == psk
    assert out["creator_ed25519_pub"] == "ZWQyNTUxOXB1Yg=="


def test_password_optional_excluded():
    code = invites.encode_invite("ROOM-AB12", "ws://h:8000")  # no password
    assert invites.decode_invite(code)["password"] is None


def test_room_id_normalised_uppercase():
    out = invites.decode_invite(invites.encode_invite("room-ab12", "ws://h:8000"))
    assert out["room_id"] == "ROOM-AB12"


def test_generate_psk_is_32_bytes():
    assert len(base64.b64decode(invites.generate_psk())) == 32


def test_invalid_room_rejected_on_encode():
    with pytest.raises(ValueError):
        invites.encode_invite("NOTAROOM", "ws://h:8000")


def test_invalid_url_rejected_on_encode():
    with pytest.raises(ValueError):
        invites.encode_invite("ROOM-AB12", "ftp://h:8000")


def test_bad_psk_rejected_on_encode():
    with pytest.raises(ValueError):
        invites.encode_invite("ROOM-AB12", "ws://h:8000", psk="not-32-bytes")


def test_wrong_prefix_rejected():
    with pytest.raises(ValueError):
        invites.decode_invite("HELU1:abc")


def test_tampered_code_rejected():
    code = invites.encode_invite("ROOM-AB12", "ws://h:8000", password="secret")
    body = code[len("HELU-INV1:"):]
    # Flip a character in the middle of the base64 body.
    i = len(body) // 2
    flipped = body[:i] + ("A" if body[i] != "A" else "B") + body[i + 1:]
    with pytest.raises(ValueError):
        invites.decode_invite("HELU-INV1:" + flipped)


def test_garbage_rejected():
    with pytest.raises(ValueError):
        invites.decode_invite("HELU-INV1:!!!notbase64!!!")


def test_ephemeral_flag_roundtrip():
    code = invites.encode_invite("ROOM-AB12", "ws://h:8000", ephemeral=True)
    assert invites.decode_invite(code)["ephemeral"] is True
    # default is False, returned as a real bool
    code2 = invites.encode_invite("ROOM-AB12", "ws://h:8000")
    assert invites.decode_invite(code2)["ephemeral"] is False
