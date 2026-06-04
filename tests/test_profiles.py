"""Tests for multi-profile compartmentalisation (feature G)."""
import pytest

import paths
import profiles


@pytest.fixture
def root(tmp_path, monkeypatch):
    # Pin the data root so profiles live under tmp_path/profiles.
    monkeypatch.setattr(paths, "_root_dir", lambda base=None: tmp_path)
    return tmp_path


def test_create_and_list(root):
    assert profiles.list_profiles() == []
    profiles.create_profile("Work")
    profiles.create_profile("Personal")
    assert profiles.list_profiles() == ["Personal", "Work"]


def test_set_active_changes_resolved_dir(root):
    assert profiles.active_name() is None
    assert paths.resolve_data_dir() == root          # no pointer → root
    profiles.set_active("Work")
    assert profiles.active_name() == "Work"
    assert profiles.active_dir() == root / "profiles" / "Work"
    assert paths.resolve_data_dir() == root / "profiles" / "Work"


def test_clear_active_returns_to_root(root):
    profiles.set_active("Work")
    profiles.clear_active()
    assert profiles.active_name() is None
    assert paths.resolve_data_dir() == root


def test_delete_active_profile_clears_pointer(root):
    profiles.set_active("Temp")
    profiles.delete_profile("Temp")
    assert "Temp" not in profiles.list_profiles()
    assert profiles.active_name() is None


def test_invalid_name_rejected(root):
    with pytest.raises(ValueError):
        profiles.create_profile("///")


def test_repoint_updates_every_module(root, tmp_path):
    import backup
    import contacts
    import crypto
    import history
    import settings

    snapshot = {
        "paths": paths.DATA_DIR, "crypto": crypto.DATA_DIR, "backup": backup.DATA_DIR,
        "settings_dir": settings.DATA_DIR, "settings_path": settings._SETTINGS_PATH,
        "contacts_dir": contacts.DATA_DIR, "contacts_path": contacts._CONTACTS_PATH,
        "history_dir": history.DATA_DIR, "history_path": history._DB_PATH,
    }
    try:
        target = tmp_path / "profiles" / "X"
        profiles.repoint_data_dir(target)
        assert paths.DATA_DIR == target
        assert crypto.DATA_DIR == target
        assert backup.DATA_DIR == target
        assert settings._SETTINGS_PATH == target / "settings.json"
        assert contacts._CONTACTS_PATH == target / "contacts.json"
        assert history._DB_PATH == target / "history.db"
    finally:
        paths.DATA_DIR = snapshot["paths"]; crypto.DATA_DIR = snapshot["crypto"]
        backup.DATA_DIR = snapshot["backup"]
        settings.DATA_DIR = snapshot["settings_dir"]; settings._SETTINGS_PATH = snapshot["settings_path"]
        contacts.DATA_DIR = snapshot["contacts_dir"]; contacts._CONTACTS_PATH = snapshot["contacts_path"]
        history.DATA_DIR = snapshot["history_dir"]; history._DB_PATH = snapshot["history_path"]
