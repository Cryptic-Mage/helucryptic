from pathlib import Path

import paths


def test_home_when_no_flag(tmp_path):
    # No portable.flag beside base -> use the per-user home dir.
    out = paths.resolve_data_dir(tmp_path)
    assert out == Path.home() / ".helucryptic"


def test_portable_when_flag_present(tmp_path):
    (tmp_path / "portable.flag").write_text("")
    out = paths.resolve_data_dir(tmp_path)
    assert out == tmp_path / "data"


def test_is_portable_true(tmp_path):
    (tmp_path / "portable.flag").write_text("")
    assert paths.is_portable(tmp_path) is True


def test_is_portable_false(tmp_path):
    assert paths.is_portable(tmp_path) is False


def test_write_private_bytes_creates_file(tmp_path):
    target = tmp_path / "secret.bin"
    paths.write_private_bytes(target, b"hello")
    assert target.exists()
    assert target.read_bytes() == b"hello"


def test_write_private_text_creates_file(tmp_path):
    target = tmp_path / "secret.txt"
    paths.write_private_text(target, "hello world")
    assert target.exists()
    assert target.read_text() == "hello world"


def test_harden_dir_noop(tmp_path):
    paths.harden_dir(tmp_path)
