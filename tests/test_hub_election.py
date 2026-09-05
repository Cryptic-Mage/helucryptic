from unittest.mock import AsyncMock, patch

import pytest

import webrtc_engine
from webrtc_engine import elect_hub, reachability_tier


class S:  # minimal settings stand-in
    def __init__(self, turn="", pf=False, port=0, manual=True):
        self.turn_url = turn
        self.port_forward_enabled = pf
        self.forwarded_port = port
        self.forwarded_port_manual = manual


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


def test_current_hub_defers_when_creator_unknown_and_all_tier_0():
    """No hub beats "the wrong hub".

    With every member at tier 0 the creator is the tie-break, so a peer that has
    not yet seen the creator's announcement cannot decide. Guessing the
    alphabetically lowest member (the old behaviour) made peers disagree - see
    test_hub_is_consistent_across_peers_that_disagree_about_the_creator.
    """
    e = _engine("bob")
    e.set_room("ROOM", is_creator=False)       # _room_creator_name stays None
    e.record_capability("carol", tier=0, epoch=1)
    assert e.current_hub() == ""


def test_current_hub_elects_a_lone_best_tier_peer_without_knowing_the_creator():
    """A single member above tier 0 is the hub whether or not it is the creator."""
    e = _engine("bob")
    e.set_room("ROOM", is_creator=False)
    e.record_capability("carol", tier=2, epoch=1)
    assert e.current_hub() == "carol"


def test_hub_is_consistent_across_peers_that_disagree_about_the_creator():
    """The property the old alphabetical fallback broke.

    Two peers with identical capability data must never name different relays
    just because one has heard from the creator and the other has not.
    """
    knows = _engine("alice")
    knows.set_room("ROOM", is_creator=False)
    knows.set_room_creator("carol")
    knows.record_capability("bob", tier=0, epoch=1)
    knows.record_capability("carol", tier=0, epoch=1)

    waiting = _engine("bob")
    waiting.set_room("ROOM", is_creator=False)
    waiting.record_capability("alice", tier=0, epoch=1)
    waiting.record_capability("carol", tier=0, epoch=1)

    # "" means "not yet decided", never a competing answer.
    assert waiting.current_hub() == ""
    assert knows.current_hub() == "carol"


def test_restarted_peer_can_update_its_capability():
    """Epoch counters restart at 1 when a peer's process does.

    Someone who restarts *with* port forwarding must be able to become the hub;
    treating their fresh epoch as stale froze them at their old capability.
    """
    e = _engine("alice")
    e.set_room("ROOM", is_creator=True)
    for epoch in (1, 2, 3, 4, 5):
        e.record_capability("bob", tier=0, epoch=epoch)
    assert e.current_hub() == "alice"

    e.record_capability("bob", tier=2, epoch=1)   # bob restarted, now forwarded
    assert e.current_hub() == "bob"


def test_dead_auto_mapping_does_not_claim_tier_2():
    """A persisted auto-discovered port is only credible while it is mapped.

    Otherwise a peer whose NAT-PMP lease died keeps winning the election and the
    room relays through someone nobody can reach.
    """
    auto = S(pf=True, port=54097, manual=False)
    assert reachability_tier(auto, current_port=None) == 0
    assert reachability_tier(auto, current_port=54097) == 2

    # A hand-configured static forward has no live mapping to check, so it
    # stays trusted.
    manual = S(pf=True, port=54097, manual=True)
    assert reachability_tier(manual, current_port=None) == 2


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


def test_injection_skips_a_candidate_aioice_already_gathered():
    """A forwarded port crosses the NAT unchanged, so STUN reflects that exact
    address - injecting it again advertised the same candidate twice."""
    from webrtc_engine import inject_predicted_srflx
    sdp = (
        "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        "a=candidate:1 1 udp 2130706431 10.2.0.2 54097 typ host\r\n"
        "a=candidate:2 1 udp 1694498815 146.70.142.86 54097 typ srflx "
        "raddr 10.2.0.2 rport 54097\r\n"
    )
    assert inject_predicted_srflx(sdp, "146.70.142.86", 54097) == sdp
    # A different port is still a genuinely new candidate.
    assert "146.70.142.86 45000" in inject_predicted_srflx(sdp, "146.70.142.86", 45000)
