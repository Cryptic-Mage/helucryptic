import pytest
from pathlib import Path
import base64
import crypto

@pytest.fixture(autouse=True)
def patch_data_dir(tmp_path, monkeypatch):
    # Redirect DATA_DIR to tmp_path so it doesn't alter user's keys
    monkeypatch.setattr(crypto, "DATA_DIR", tmp_path)

def test_generate_and_save_keys():
    keys = crypto.generate_and_save_keys()
    assert "x25519_private" in keys
    assert "x25519_public" in keys
    assert "ed25519_private" in keys
    assert "ed25519_public" in keys
    
    # Check if file keys.json was created
    keys_file = crypto.DATA_DIR / "keys.json"
    assert keys_file.exists()

def test_load_or_create_keys():
    # First load should generate new keys
    keys1 = crypto.load_or_create_keys()
    assert (crypto.DATA_DIR / "keys.json").exists()
    
    # Second load should read existing keys
    keys2 = crypto.load_or_create_keys()
    assert keys1["x25519_public"] == keys2["x25519_public"]

def test_session_key_derivation():
    # Generate keys for A and B
    keys_a = crypto.generate_and_save_keys()
    
    # Generate B keys
    import cryptography.hazmat.primitives.asymmetric.x25519 as x25519
    import cryptography.hazmat.primitives.serialization as ser
    priv_b = x25519.X25519PrivateKey.generate()
    pub_b_bytes = priv_b.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    priv_b_bytes = priv_b.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    
    priv_b_b64 = base64.b64encode(priv_b_bytes).decode()
    pub_b_b64 = base64.b64encode(pub_b_bytes).decode()
    
    # A derives key using A's private and B's public
    key_a = crypto.derive_session_key(keys_a["x25519_private"], pub_b_b64)
    
    # B derives key using B's private and A's public
    key_b = crypto.derive_session_key(priv_b_b64, keys_a["x25519_public"])
    
    assert len(key_a) == 32
    assert key_a == key_b

def test_derive_history_key():
    keys = crypto.generate_and_save_keys()
    history_key = crypto.derive_history_key(keys["ed25519_private"])
    assert len(history_key) == 32

def test_paseto_sign_and_verify():
    keys = crypto.generate_and_save_keys()
    payload = {"username": "alice", "test": "data"}
    token = crypto.paseto_sign(payload, keys["ed25519_private"], keys["ed25519_public"])
    assert isinstance(token, str)
    
    # Verify signature
    decoded = crypto.paseto_verify(token, keys["ed25519_public"])
    assert decoded["username"] == "alice"
    assert decoded["test"] == "data"

def test_paseto_encrypt_and_decrypt():
    sym_key = b"0" * 32
    payload = {"secret": "hello group call"}
    token = crypto.paseto_encrypt(payload, sym_key)
    
    decoded = crypto.paseto_decrypt(token, sym_key)
    assert decoded["secret"] == "hello group call"

def test_compute_fingerprint():
    keys = crypto.generate_and_save_keys()
    fp = crypto.compute_fingerprint(keys["x25519_public"])
    # Fingerprint should be formatted with spaces between 4-char hex groups
    assert len(fp) > 0
    assert " " in fp

def test_load_keys_corrupted():
    crypto.ensure_data_dir()
    path = crypto.DATA_DIR / "keys.json"
    path.write_text("invalid json")
    with pytest.raises(RuntimeError) as exc_info:
        crypto.load_or_create_keys()
    assert "corrupted and could not be read" in str(exc_info.value)

def test_load_keys_missing_fields():
    crypto.ensure_data_dir()
    path = crypto.DATA_DIR / "keys.json"
    path.write_text('{"x25519_private": "key"}')  # Missing other fields
    with pytest.raises(RuntimeError) as exc_info:
        crypto.load_or_create_keys()
    assert "missing required fields" in str(exc_info.value)

def test_derive_session_key_empty_args():
    with pytest.raises(ValueError) as exc_info:
        crypto.derive_session_key("", "pub_key")
    assert "before hello handshake complete" in str(exc_info.value)
