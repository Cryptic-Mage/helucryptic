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
