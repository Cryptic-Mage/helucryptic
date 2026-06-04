"""Tests for the pure command-palette filter (framework-agnostic)."""
from commands import filter_commands

CMDS = [
    {"id": "connect", "title": "Connect to signaling", "keywords": "online join"},
    {"id": "call", "title": "Start voice call", "keywords": "audio mic"},
    {"id": "share", "title": "Share screen", "keywords": "present screen"},
    {"id": "mute", "title": "Toggle mute", "keywords": "microphone silence"},
    {"id": "settings", "title": "Open settings", "keywords": "preferences config"},
]


def _ids(rows):
    return [r["id"] for r in rows]


def test_empty_query_returns_all_in_order():
    assert _ids(filter_commands(CMDS, "")) == ["connect", "call", "share", "mute", "settings"]
    assert _ids(filter_commands(CMDS, "   ")) == _ids(filter_commands(CMDS, ""))


def test_prefix_match_ranks_first():
    rows = filter_commands(CMDS, "open")
    assert rows[0]["id"] == "settings"


def test_substring_match_included():
    rows = filter_commands(CMDS, "screen")
    assert "share" in _ids(rows)


def test_non_match_excluded():
    rows = filter_commands(CMDS, "zzzzz")
    assert rows == []


def test_keyword_match_works():
    rows = filter_commands(CMDS, "microphone")
    assert "mute" in _ids(rows)


def test_case_insensitive():
    assert _ids(filter_commands(CMDS, "CALL")) == _ids(filter_commands(CMDS, "call"))


def test_word_start_beats_mid_substring():
    # "voice" starts a word in "Start voice call"; "call" is also a word.
    rows = filter_commands(CMDS, "voice")
    assert rows[0]["id"] == "call"


def test_subsequence_match_is_last_resort():
    # "ssc" is a subsequence of "Share screen" (S..s.c) but not a substring.
    rows = filter_commands(CMDS, "shrscr")
    assert "share" in _ids(rows)
