import pytest
from unittest.mock import AsyncMock, patch

from webrtc_engine import reachability_tier, elect_hub
import webrtc_engine


class S:  # minimal settings stand-in
    def __init__(self, turn="", pf=False, port=0):
        self.turn_url = turn
        self.port_forward_enabled = pf
        self.forwarded_port = port


# ---------------------------------------------------------------------------
# Task 1: reachability_tier
# ---------------------------------------------------------------------------

def test_tier_forwarded_port_is_2():
    assert reachability_tier(S(pf=True, port=55000), current_port=55000) == 2

def test_tier_current_port_alone_is_2():
    assert reachability_tier(S(), current_port=55000) == 2

def test_tier_turn_only_is_1():
    assert reachability_tier(S(turn="turn:host:3478"), current_port=None) == 1

def test_tier_none_is_0():
    assert reachability_tier(S(), current_port=None) == 0


# ---------------------------------------------------------------------------
# Task 2: elect_hub
# ---------------------------------------------------------------------------

def test_highest_tier_wins():
    assert elect_hub({"alice": 0, "bob": 2, "carol": 1}, creator="alice") == "bob"

def test_tie_creator_wins():
    assert elect_hub({"alice": 2, "bob": 2}, creator="bob") == "bob"

def test_tie_no_creator_in_tier_lowest_username():
    assert elect_hub({"alice": 1, "bob": 2, "carol": 2}, creator="alice") == "bob"

def test_all_tier0_returns_creator():
    assert elect_hub({"alice": 0, "bob": 0, "carol": 0}, creator="bob") == "bob"


# ---------------------------------------------------------------------------
# Task 3: capability tracking + epoch convergence
# ---------------------------------------------------------------------------

class MockSettings:
    security_mode = "e2ee"
    turn_url = ""
    port_forward_enabled = False
    forwarded_port = 0


def _engine(name="alice"):
    return webrtc_engine.WebRTCEngine(name, MockSettings(), {
        "x25519_private": "x", "x25519_public": "x",
        "ed25519_private": "e", "ed25519_public": "e"})


def test_record_capability_and_elect():
    e = _engine("alice")
    e.set_room("ROOM", is_creator=True)        # alice is creator
    # current_hub() injects self (alice) automatically; only remote peers are recorded.
    e.record_capability("bob", tier=2, epoch=1)
    assert e.current_hub() == "bob"


def test_current_hub_falls_back_to_lowest_username_when_creator_unknown():
    # Non-creator peer that hasn't yet learned the creator's name: election must
    # still be deterministic (alphabetically lowest known member).
    e = _engine("bob")
    e.set_room("ROOM", is_creator=False)       # _room_creator_name stays None
    e.record_capability("carol", tier=0, epoch=1)
    assert e.current_hub() == "bob"            # all tier 0 -> lowest of {bob, carol}


def test_stale_epoch_discarded():
    e = _engine("alice")
    e.set_room("ROOM", is_creator=True)
    e.record_capability("bob", tier=2, epoch=5)
    e.record_capability("bob", tier=0, epoch=3)  # stale -> ignored
    assert e.current_hub() == "bob"


# ---------------------------------------------------------------------------
# Task 4: star-topology reconcile_room_connections
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@patch("webrtc_engine.RTCPeerConnection")
async def test_non_hub_connects_only_to_hub(mock_pc):
    e = _engine("alice")                 # uses existing _engine() helper in this file
    e.set_room("ROOM", is_creator=False)
    e.record_capability("bob", tier=2, epoch=1)    # bob is the hub (tier 2)
    e.record_capability("carol", tier=0, epoch=1)
    ws = AsyncMock()
    with patch.object(e, "create_offer", new=AsyncMock()) as off:
        await e.reconcile_room_connections(["bob", "carol"], ws)
        off.assert_awaited_once_with("bob", ws)    # offers only to the hub


@pytest.mark.asyncio
async def test_hub_does_not_offer(monkeypatch):
    e = _engine("zoe")
    e.set_room("ROOM", is_creator=False)
    # When this engine is itself the elected hub, it stays a pure responder and
    # never offers. Force the election result directly to isolate that branch.
    monkeypatch.setattr(e, "current_hub", lambda: "zoe")
    called = {"n": 0}
    async def fake_offer(*a, **k): called["n"] += 1
    monkeypatch.setattr(e, "create_offer", fake_offer)
    await e.reconcile_room_connections(["bob"], AsyncMock())
    assert called["n"] == 0


# ---------------------------------------------------------------------------
# Task 10a: capability_payload bumps epoch and encodes creator flag
# ---------------------------------------------------------------------------

def test_capability_payload_bumps_epoch():
    import webrtc_engine
    class MS: security_mode="e2ee"; turn_url=""; port_forward_enabled=False; forwarded_port=0
    e = webrtc_engine.WebRTCEngine("alice", MS(), {"x25519_private":"x","x25519_public":"x","ed25519_private":"e","ed25519_public":"e"})
    e.set_room("ROOM", is_creator=True)
    p1 = e.capability_payload(); p2 = e.capability_payload()
    assert p2["epoch"] == p1["epoch"] + 1
    assert p1["creator"] is True and "tier" in p1
