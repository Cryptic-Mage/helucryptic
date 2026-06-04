"""Tests for membership certificates (feature D) — crypto core."""
import crypto


def _keys(tmp_path, name, monkeypatch):
    monkeypatch.setattr(crypto, "DATA_DIR", tmp_path / name)
    return crypto.generate_and_save_keys()


def test_valid_cert_verifies(tmp_path, monkeypatch):
    creator = _keys(tmp_path, "creator", monkeypatch)
    member = _keys(tmp_path, "member", monkeypatch)
    cert = crypto.issue_membership_cert(
        creator["ed25519_private"], creator["ed25519_public"],
        "ROOM-AB12", "bob", member["ed25519_public"])
    assert crypto.verify_membership_cert(
        cert, creator["ed25519_public"], "ROOM-AB12", "bob", member["ed25519_public"])


def test_cert_bound_to_room(tmp_path, monkeypatch):
    creator = _keys(tmp_path, "creator", monkeypatch)
    member = _keys(tmp_path, "member", monkeypatch)
    cert = crypto.issue_membership_cert(
        creator["ed25519_private"], creator["ed25519_public"],
        "ROOM-AB12", "bob", member["ed25519_public"])
    # same cert, different room → rejected
    assert not crypto.verify_membership_cert(
        cert, creator["ed25519_public"], "ROOM-ZZ99", "bob", member["ed25519_public"])


def test_cert_bound_to_member_key(tmp_path, monkeypatch):
    creator = _keys(tmp_path, "creator", monkeypatch)
    member = _keys(tmp_path, "member", monkeypatch)
    other = _keys(tmp_path, "other", monkeypatch)
    cert = crypto.issue_membership_cert(
        creator["ed25519_private"], creator["ed25519_public"],
        "ROOM-AB12", "bob", member["ed25519_public"])
    # an impostor presenting bob's cert but a different key → rejected
    assert not crypto.verify_membership_cert(
        cert, creator["ed25519_public"], "ROOM-AB12", "bob", other["ed25519_public"])


def test_cert_from_wrong_creator_rejected(tmp_path, monkeypatch):
    creator = _keys(tmp_path, "creator", monkeypatch)
    impostor = _keys(tmp_path, "impostor", monkeypatch)
    member = _keys(tmp_path, "member", monkeypatch)
    # cert signed by an impostor, verified against the real creator's key → rejected
    forged = crypto.issue_membership_cert(
        impostor["ed25519_private"], impostor["ed25519_public"],
        "ROOM-AB12", "bob", member["ed25519_public"])
    assert not crypto.verify_membership_cert(
        forged, creator["ed25519_public"], "ROOM-AB12", "bob", member["ed25519_public"])


def test_garbage_cert_rejected(tmp_path, monkeypatch):
    creator = _keys(tmp_path, "creator", monkeypatch)
    assert not crypto.verify_membership_cert(
        "not-a-token", creator["ed25519_public"], "ROOM-AB12", "bob", "k")
    assert not crypto.verify_membership_cert(
        "", creator["ed25519_public"], "ROOM-AB12", "bob", "k")
