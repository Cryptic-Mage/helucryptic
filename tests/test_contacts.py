
import pytest

import contacts


@pytest.fixture(autouse=True)
def patch_contacts_dir(tmp_path, monkeypatch):
    # Patch both DATA_DIR and the path to contacts.json so they run in tmp_path
    monkeypatch.setattr(contacts, "DATA_DIR", tmp_path)
    monkeypatch.setattr(contacts, "_CONTACTS_PATH", tmp_path / "contacts.json")

def test_upsert_contact_new():
    # Insert new contact
    c = contacts.upsert_contact("alice", x25519_pub="dGVzdF94MjU1MTlfcHVibGljX2tleQ==", ed25519_pub="dGVzdF9lZDI1NTE5X3B1YmxpY19rZXk=")
    assert c.username == "alice"
    assert c.x25519_pub == "dGVzdF94MjU1MTlfcHVibGljX2tleQ=="
    assert c.ed25519_pub == "dGVzdF9lZDI1NTE5X3B1YmxpY19rZXk="
    assert c.fingerprint != ""
    assert c.verified is False

    # Check if saved to file
    all_contacts = contacts.load_contacts()
    assert len(all_contacts) == 1
    assert all_contacts[0].username == "alice"

def test_upsert_contact_existing():
    contacts.upsert_contact("alice", x25519_pub="dGVzdF94MjU1MTlfcHVibGljX2tleQ==")

    # Update existing contact with same key (should not drop verified status if it was True, but here it's False)
    c = contacts.upsert_contact("alice", x25519_pub="dGVzdF94MjU1MTlfcHVibGljX2tleQ==")
    assert c.username == "alice"
    assert c.x25519_pub == "dGVzdF94MjU1MTlfcHVibGljX2tleQ=="

    all_contacts = contacts.load_contacts()
    assert len(all_contacts) == 1
    assert all_contacts[0].x25519_pub == "dGVzdF94MjU1MTlfcHVibGljX2tleQ=="

def test_upsert_contact_key_change_drops_verification():
    # Valid base64 strings:
    # "old_key_12345678" -> "b2xkX2tleV8xMjM0NTY3OA=="
    # "new_key_12345678" -> "bmV3X2tleV8xMjM0NTY3OA=="
    # "old_ed_key_12345" -> "b2xkX2VkX2tleV8xMjM0NQ=="
    # "new_ed_key_12345" -> "bmV3X2VkX2tleV8xMjM0NQ=="

    # Create contact and verify it
    contacts.upsert_contact("alice", x25519_pub="b2xkX2tleV8xMjM0NTY3OA==", ed25519_pub="b2xkX2VkX2tleV8xMjM0NQ==")
    contacts.set_verified("alice", True)
    assert contacts.get_contact("alice").verified is True

    # Update with new x25519 key - should set verified to False
    contacts.upsert_contact("alice", x25519_pub="bmV3X2tleV8xMjM0NTY3OA==", ed25519_pub="b2xkX2VkX2tleV8xMjM0NQ==")
    assert contacts.get_contact("alice").verified is False

    # Reset verified and test ed25519 key change
    contacts.set_verified("alice", True)
    assert contacts.get_contact("alice").verified is True

    contacts.upsert_contact("alice", x25519_pub="bmV3X2tleV8xMjM0NTY3OA==", ed25519_pub="bmV3X2VkX2tleV8xMjM0NQ==")
    assert contacts.get_contact("alice").verified is False

def test_get_contact():
    contacts.upsert_contact("bob")
    c = contacts.get_contact("bob")
    assert c is not None
    assert c.username == "bob"

    c_none = contacts.get_contact("nonexistent")
    assert c_none is None

def test_delete_contact():
    contacts.upsert_contact("alice")
    contacts.upsert_contact("bob")

    contacts.delete_contact("alice")
    all_contacts = contacts.load_contacts()
    assert len(all_contacts) == 1
    assert all_contacts[0].username == "bob"

def test_set_verified():
    contacts.upsert_contact("alice")
    contacts.set_verified("alice", True)

    c = contacts.get_contact("alice")
    assert c.verified is True

def test_rename_contact():
    contacts.upsert_contact("alice")
    contacts.rename_contact("alice", "Alice Cooper")

    c = contacts.get_contact("alice")
    assert c.nickname == "Alice Cooper"


def test_corrupted_contacts_file_backup(patch_contacts_dir):
    contacts.DATA_DIR.mkdir(exist_ok=True)
    contacts._CONTACTS_PATH.write_text("this is not valid json")
    with pytest.raises(RuntimeError) as exc_info:
        contacts.load_contacts()
    assert "corrupted" in str(exc_info.value).lower()
    assert contacts._CONTACTS_PATH.with_name("contacts.json.corrupted").exists()
