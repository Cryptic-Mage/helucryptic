"""Tests for pure UI-state helpers (framework-agnostic, no Flet)."""
from ui_state import summarize_peer_states


def test_idle_when_no_peers():
    r = summarize_peer_states({})
    assert r["level"] == "idle"
    assert r["connected"] == 0 and r["total"] == 0


def test_single_peer_connected_one_to_one():
    r = summarize_peer_states({"bob": "connected"}, group=False)
    assert r["level"] == "connected"
    assert r["label"] == "Connected"


def test_single_peer_connecting_one_to_one():
    r = summarize_peer_states({"bob": "connecting"}, group=False)
    assert r["level"] == "connecting"
    assert r["label"] == "Connecting"


def test_single_peer_failed_one_to_one():
    r = summarize_peer_states({"bob": "failed"}, group=False)
    assert r["level"] == "disconnected"
    assert r["label"] == "Disconnected"


def test_group_all_connected_uses_counts():
    r = summarize_peer_states({"a": "connected", "b": "connected"}, group=True)
    assert r["level"] == "connected"
    assert r["connected"] == 2 and r["total"] == 2
    assert r["label"] == "2 connected"


def test_group_partial_is_partial_with_fraction():
    r = summarize_peer_states({"a": "connected", "b": "connecting", "c": "failed"}, group=True)
    assert r["level"] == "partial"
    assert r["connected"] == 1 and r["total"] == 3
    assert r["label"] == "1/3 connected"


def test_group_none_connected_but_some_connecting():
    r = summarize_peer_states({"a": "connecting", "b": "new"}, group=True)
    assert r["level"] == "connecting"
    assert r["connected"] == 0


def test_group_all_failed_is_disconnected():
    r = summarize_peer_states({"a": "failed", "b": "closed"}, group=True)
    assert r["level"] == "disconnected"
    assert r["connected"] == 0


def test_new_state_counts_as_connecting():
    r = summarize_peer_states({"a": "new"}, group=False)
    assert r["level"] == "connecting"
