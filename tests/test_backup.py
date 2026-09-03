import pytest

import backup
import secure_store


def _seed(dirpath):
    (dirpath / "keys.json").write_text('{"k":1}')
    (dirpath / "contacts.json").write_text('[{"u":"bob"}]')
    (dirpath / "settings.json").write_text('{"s":2}')
    (dirpath / "history.db").write_bytes(b"SQLITEDATA")
    (dirpath / "unrelated.txt").write_text("keep me")


def test_export_import_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "DATA_DIR", tmp_path)
    _seed(tmp_path)
    blob = backup.export_backup("hunter2", include_history=True)
    # wipe the live files, then restore
    (tmp_path / "keys.json").write_text("CLOBBERED")
    restored = backup.import_backup(blob, "hunter2")
    assert "keys.json" in restored and "history.db" in restored
    # keys.json is re-wrapped with the OS keystore on restore; unwrap to compare.
    assert secure_store.unprotect((tmp_path / "keys.json").read_bytes()) == b'{"k":1}'
    assert (tmp_path / "history.db").read_bytes() == b"SQLITEDATA"
    # existing file was backed up before overwrite
    assert (tmp_path / "keys.json.bak").read_text() == "CLOBBERED"


def test_export_excludes_history_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "DATA_DIR", tmp_path)
    _seed(tmp_path)
    payload = backup.validate_and_decrypt(backup.export_backup("pw"), "pw")
    assert "history.db" not in payload["files"]
    assert "keys.json" in payload["files"]


def test_wrong_passphrase_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "DATA_DIR", tmp_path)
    _seed(tmp_path)
    blob = backup.export_backup("correct")
    with pytest.raises(ValueError):
        backup.validate_and_decrypt(blob, "wrong")


def test_tampered_backup_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "DATA_DIR", tmp_path)
    _seed(tmp_path)
    blob = bytearray(backup.export_backup("pw"))
    blob[-5] ^= 0xFF  # corrupt the token
    with pytest.raises(ValueError):
        backup.validate_and_decrypt(bytes(blob), "pw")


def test_import_validates_before_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "DATA_DIR", tmp_path)
    _seed(tmp_path)
    blob = backup.export_backup("right")
    (tmp_path / "keys.json").write_text("ORIGINAL")
    with pytest.raises(ValueError):
        backup.import_backup(blob, "wrong")
    # wrong passphrase must NOT have touched the live file or created a .bak
    assert (tmp_path / "keys.json").read_text() == "ORIGINAL"
    assert not (tmp_path / "keys.json.bak").exists()


def test_emergency_wipe_only_targets(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "DATA_DIR", tmp_path)
    _seed(tmp_path)
    (tmp_path / "history.db-wal").write_text("wal")
    removed = backup.emergency_wipe()
    assert "keys.json" in removed and "history.db" in removed
    assert not (tmp_path / "keys.json").exists()
    assert not (tmp_path / "history.db").exists()
    assert not (tmp_path / "history.db-wal").exists()
    assert (tmp_path / "unrelated.txt").read_text() == "keep me"  # untouched


def test_import_backup_cleans_and_restores_sidecars(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "DATA_DIR", tmp_path)
    _seed(tmp_path)

    # Write initial sidecars
    (tmp_path / "history.db-wal").write_text("old-wal")
    (tmp_path / "history.db-shm").write_text("old-shm")

    blob = backup.export_backup("hunter2", include_history=True)

    # Clear live files, and write new dummy sidecar files that should be clobbered
    (tmp_path / "history.db-wal").write_text("live-wal")
    (tmp_path / "history.db-shm").write_text("live-shm")

    # Restore backup
    restored = backup.import_backup(blob, "hunter2")
    assert "history.db" in restored

    # Sidecars should be unlinked/deleted so SQLite doesn't recovery-fail
    assert not (tmp_path / "history.db-wal").exists()
    assert not (tmp_path / "history.db-shm").exists()

    # Check that backup files for sidecars were created
    assert (tmp_path / "history.db-wal.bak").read_text() == "live-wal"
    assert (tmp_path / "history.db-shm.bak").read_text() == "live-shm"

    # Test rollback: corrupt the data and try to restore, which should trigger rollback
    # We will simulate a failure by mocking shutil.copy2 or os.replace to raise an exception
    original_replace = backup.os.replace
    def mock_replace(src, dst):
        if "history.db" in str(dst):
            raise OSError("Mock write error")
        return original_replace(src, dst)

    monkeypatch.setattr(backup.os, "replace", mock_replace)

    # Re-create sidecars to test rollback
    (tmp_path / "history.db-wal").write_text("current-wal")
    (tmp_path / "history.db-shm").write_text("current-shm")

    # Remove old .bak files so we can verify if new ones are created during the failed restore
    if (tmp_path / "history.db-wal.bak").exists():
        (tmp_path / "history.db-wal.bak").unlink()
    if (tmp_path / "history.db-shm.bak").exists():
        (tmp_path / "history.db-shm.bak").unlink()

    with pytest.raises(ValueError):
        backup.import_backup(blob, "hunter2")

    # After failed restore, live sidecars should be restored
    assert (tmp_path / "history.db-wal").read_text() == "current-wal"
    assert (tmp_path / "history.db-shm").read_text() == "current-shm"

