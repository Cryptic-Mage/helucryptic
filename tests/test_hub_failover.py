"""Tests for dynamic hub failover (feature F): a dropped relay hub is forgotten
and the room re-elects the next-best peer."""
import pytest

import webrtc_engine
from webrtc_engine import elect_hub


class _Settings:
    security_mode = "e2ee"
    push_to_talk_key = ""


_KEYS = {
    "x25519_private": "dGVzdF94MjU1MTlfcHJpdmF0ZV9rZXk=",
    "x25519_public": "dGVzdF94MjU1MTlfcHVibGljX2tleQ==",
    "ed25519_private": "dGVzdF9lZDI1NTE5X3ByaXZhdGVfa2V5",
    "ed25519_public": "dGVzdF9lZDI1NTE5X3B1YmxpY19rZXk=",
}


def _engine(name="me"):
    return webrtc_engine.WebRTCEngine(name, _Settings(), _KEYS)


def test_elect_hub_reelects_after_hub_leaves():
    members = {"alice": 3, "bob": 2, "carol": 0}
    assert elect_hub(members, creator="carol") == "alice"   # highest tier
    del members["alice"]                                     # hub leaves
    assert elect_hub(members, creator="carol") == "bob"      # next best


def test_forget_capability_triggers_reelection():
    e = _engine("me")
    e.room_id = "ROOM-AB12"
    e._room_creator_name = "carol"
    e.record_capability("alice", 3, 1)
    e.record_capability("bob", 2, 1)
    e.record_capability("carol", 1, 1)
    assert e.current_hub() == "alice"          # tier-3 peer is the hub
    e.forget_peer_capability("alice")          # hub drops
    assert e.current_hub() == "bob"            # re-elected to the next best
    assert "alice" not in e._cap_tier


def test_purge_secrets_wipes_session_material():
    # Feature H: ephemeral rooms purge all crypto material from RAM on leave.
    e = _engine("me")
    e.session_keys["alice"] = b"k" * 32
    e.group_key = b"g" * 32
    e._eph_priv["alice"] = "priv"
    e.set_room_psk(__import__("invites").generate_psk())
    e.purge_secrets()
    assert e.session_keys == {}
    assert e.group_key is None
    assert e._eph_priv == {}
    assert e.room_psk is None


@pytest.mark.asyncio
async def test_remove_peer_forgets_capability_and_psk():
    e = _engine("me")
    e.record_capability("alice", 3, 1)
    e._psk_authed["alice"] = True
    e._psk_my_nonce["alice"] = "n"
    e._pending_call_start.add("alice")
    await e.remove_peer("alice")
    assert "alice" not in e._cap_tier
    assert "alice" not in e._cap_epoch
    assert "alice" not in e._psk_authed
    assert "alice" not in e._psk_my_nonce
    assert "alice" not in e._pending_call_start


def test_elect_hub_empty_members_returns_creator():
    assert elect_hub({}, creator="alice") == "alice"


def test_elect_hub_best_is_zero_returns_creator():
    assert elect_hub({"bob": 0, "carol": 0}, creator="alice") == "alice"


def test_elect_hub_creator_wins_ties():
    # Tie between alice and bob at tier 3. alice is creator, so she should win.
    assert elect_hub({"alice": 3, "bob": 3}, creator="alice") == "alice"
    # Even if bob is alphabetically first, alice wins because she is the creator and is in the top tier
    assert elect_hub({"bob": 3, "alice": 3}, creator="alice") == "alice"


def test_elect_hub_alphabetical_tie_breaker():
    # Tie between bob and carol at tier 3. alice is creator but at tier 1.
    # The tie-breaker should choose alphabetically: "bob" before "carol".
    assert elect_hub({"bob": 3, "carol": 3, "alice": 1}, creator="alice") == "bob"

