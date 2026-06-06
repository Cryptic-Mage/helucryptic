"""
Task 12 — 3-peer localhost integration test for the star/SFU group-call engine.

Topology
--------
  aaa ──► hub ──► bbb
  aaa ──► hub (voice call)
  hub forwards aaa's audio track to bbb, labeling it with origin "aaa"
  bbb must end up with _origin_map mapping the forwarded track-id to "aaa"

Assertion path used: CONTROL-PLANE
  We assert that B's _origin_map contains "aaa" as a value (i.e., B received
  the track_origin data-channel frame from the hub) AND that the hub's
  _forwarded["aaa"] has a dest entry for "bbb".

  Why not the audio-flow path (_play_chunks["aaa"])?
  _handle_incoming_audio calls _ensure_output_stream() which we no-op, and then
  enters a recv() loop pulling frames from the forwarded AudioStreamTrack. The
  synthetic aiortc.mediastreams.AudioStreamTrack generates silence frames, but
  the actual audio-decode loop requires DTLS-SRTP to be fully up on the
  hub->bbb renegotiated connection AND for the relay to start pumping frames
  before the 10-second poll window expires. That second renegotiation is the
  slow step on localhost: aiortc gathers new ICE for the re-offer and DTLS
  re-handshakes. Under CI/test conditions this reliably completes, but the
  data-channel track_origin frame arrives BEFORE audio frames flow (the hub
  sends it immediately when it calls _relay_track_to_others, before the
  renegotiation finishes). The control-plane assertion therefore proves the
  core goal—origin keying is correct—without depending on DTLS-SRTP timing.
"""

import asyncio
import os
import sys

import pytest

# Ensure repo root is on the path for direct imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from aiortc.mediastreams import AudioStreamTrack

from webrtc_engine import WebRTCEngine

# ---------------------------------------------------------------------------
# Minimal settings for the test — DTLS only (no crypto keys needed for hello)
# ---------------------------------------------------------------------------

class _Settings:
    security_mode = "dtls"
    turn_url = ""
    port_forward_enabled = False
    forwarded_port = 0
    screen_max_w = 1280
    screen_max_h = 720
    screen_fps = 10
    jpeg_quality = 55
    tile_render_fps = 10


_DUMMY_KEYS = {
    "x25519_private": "x", "x25519_public": "x",
    "ed25519_private": "e", "ed25519_public": "e",
}

ROOM_ID = "TEST_ROOM"


# ---------------------------------------------------------------------------
# In-process signaling router
# ---------------------------------------------------------------------------

def make_router(engines: dict):
    """Return a make_ws_send factory that routes signaling messages in-process.

    Each engine's _send_ws is fixed to make_ws_send(engine.my_username) so
    that renegotiation offers from the hub always carry 'hub' as the sender,
    regardless of which peer last called handle_offer on the hub.
    """
    def make_ws_send(sender_name: str):
        async def ws_send(payload: dict):
            target = payload["target"]
            typ    = payload["type"]
            data   = payload.get("data")
            dst    = engines[target]
            if typ == "offer":
                # The answer ws_send must carry sender=target so the answerer's
                # reply routes back to the offer-sender (the engine at `target`).
                await dst.handle_offer(sender_name, data, make_ws_send(target))
            elif typ == "answer":
                await dst.handle_answer(data, sender=sender_name)
            elif typ == "ice-candidate":
                await dst.handle_ice(data, sender=sender_name)
        return ws_send
    return make_ws_send


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hub_star_origin_keying():
    """
    Three engines connect in a star topology.  aaa starts a voice call to hub;
    hub must forward aaa's audio track to bbb with origin label "aaa".

    The test asserts the CONTROL-PLANE result:
      • hub._forwarded["aaa"] contains a dest entry for "bbb"
      • "aaa" appears in bbb._origin_map.values()

    This is sufficient to prove: (a) the SFU relay logic ran, (b) the hub
    correctly sent a track_origin frame to bbb, and (c) bbb stored the
    correct origin identity.
    """
    settings = _Settings()

    hub_eng = WebRTCEngine("hub", settings, _DUMMY_KEYS)
    a_eng   = WebRTCEngine("aaa", settings, _DUMMY_KEYS)
    b_eng   = WebRTCEngine("bbb", settings, _DUMMY_KEYS)

    engines = {"hub": hub_eng, "aaa": a_eng, "bbb": b_eng}
    make_ws_send = make_router(engines)

    # ------------------------------------------------------------------
    # Monkeypatching: no hardware needed
    # ------------------------------------------------------------------
    for eng in engines.values():
        # No speaker output
        eng._ensure_output_stream = lambda: None
        # Deterministic hub election: "hub" always wins
        eng.current_hub = lambda: "hub"
        # Synthetic mic — return a NEW track each call so relay subscribes work
        eng._get_mic_source = lambda: AudioStreamTrack()

    # Pre-assign each engine's _send_ws so renegotiation offers carry the
    # correct sender name (see module docstring for why this matters).
    hub_eng._send_ws = make_ws_send("hub")
    a_eng._send_ws   = make_ws_send("aaa")
    b_eng._send_ws   = make_ws_send("bbb")

    # ------------------------------------------------------------------
    # Room setup
    # ------------------------------------------------------------------
    hub_eng.set_room(ROOM_ID, is_creator=True)
    a_eng.set_room(ROOM_ID, is_creator=False)
    b_eng.set_room(ROOM_ID, is_creator=False)

    # Override current_hub AFTER set_room (set_room sets _room_creator_name)
    for eng in engines.values():
        eng.current_hub = lambda: "hub"

    # ------------------------------------------------------------------
    # Connect aaa -> hub  and  bbb -> hub
    # ------------------------------------------------------------------
    await a_eng.create_offer("hub", make_ws_send("aaa"))
    await b_eng.create_offer("hub", make_ws_send("bbb"))

    # Poll until both non-hub PCs reach "connected"
    deadline = asyncio.get_event_loop().time() + 20.0
    while True:
        a_state = a_eng.pcs.get("hub") and a_eng.pcs["hub"].connectionState
        b_state = b_eng.pcs.get("hub") and b_eng.pcs["hub"].connectionState
        if a_state == "connected" and b_state == "connected":
            break
        if asyncio.get_event_loop().time() > deadline:
            # Collect diagnostics for a useful failure message
            a_pc = a_eng.pcs.get("hub")
            b_pc = b_eng.pcs.get("hub")
            hub_pcs = {k: v.connectionState for k, v in hub_eng.pcs.items()}
            pytest.fail(
                f"PCs did not reach 'connected' within 20s.\n"
                f"  aaa->hub: connectionState={getattr(a_pc,'connectionState','MISSING')} "
                f"iceConnectionState={getattr(a_pc,'iceConnectionState','?')}\n"
                f"  bbb->hub: connectionState={getattr(b_pc,'connectionState','MISSING')} "
                f"iceConnectionState={getattr(b_pc,'iceConnectionState','?')}\n"
                f"  hub pcs: {hub_pcs}\n"
                f"  hub last_error: {hub_eng.last_error!r}\n"
                f"  aaa last_error: {a_eng.last_error!r}\n"
                f"  bbb last_error: {b_eng.last_error!r}"
            )
        await asyncio.sleep(0.1)

    # Sanity: hub must have PCs for both non-hub peers
    assert "aaa" in hub_eng.pcs, "hub missing PC for aaa"
    assert "bbb" in hub_eng.pcs, "hub missing PC for bbb"

    # ------------------------------------------------------------------
    # aaa starts a voice call to hub
    # ------------------------------------------------------------------
    await a_eng.start_voice_call("hub")

    # ------------------------------------------------------------------
    # Wait for control-plane evidence: hub forwarded to bbb and labeled it
    # ------------------------------------------------------------------
    # We need two things to be true:
    #   1. hub._forwarded["aaa"] has an entry with dest "bbb"
    #   2. "aaa" appears in bbb._origin_map.values()
    #
    # (2) requires the hub to have sent the track_origin data-channel message
    # AND the renegotiation offer to reach bbb (so bbb's data channel is open
    # enough to receive the message).  We poll up to 15 s.

    deadline2 = asyncio.get_event_loop().time() + 15.0
    hub_forwarded_ok = False
    bbb_origin_ok    = False

    while not (hub_forwarded_ok and bbb_origin_ok):
        # Check hub forwarding bookkeeping
        fwd_entries = hub_eng._forwarded.get("aaa", [])
        hub_forwarded_ok = any(dest == "bbb" for dest, _sub, _sub_id in fwd_entries)

        # Check bbb received the track_origin frame
        bbb_origin_ok = "aaa" in b_eng._origin_map.values()

        if asyncio.get_event_loop().time() > deadline2:
            break
        await asyncio.sleep(0.1)

    # ------------------------------------------------------------------
    # Assertions
    # ------------------------------------------------------------------
    fwd_entries = hub_eng._forwarded.get("aaa", [])
    assert any(dest == "bbb" for dest, _sub, _sid in fwd_entries), (
        f"hub._forwarded['aaa'] has no entry for 'bbb'. "
        f"Got: {[(d,sid) for d,_,sid in fwd_entries]}. "
        f"hub pcs: {list(hub_eng.pcs.keys())}. "
        f"aaa voice_peers: {a_eng._voice_peers}"
    )

    assert "aaa" in b_eng._origin_map.values(), (
        f"bbb._origin_map does not contain 'aaa'. "
        f"Got: {dict(b_eng._origin_map)}. "
        f"hub data_channels readyStates: "
        f"{ {p: getattr(ch,'readyState','?') for p,ch in hub_eng.data_channels.items()} }. "
        f"bbb._origin_waiters: {list(b_eng._origin_waiters.keys())}"
    )

    # Bonus: if audio frames also arrived, great — but not required
    if "aaa" in b_eng._play_chunks and len(b_eng._play_chunks["aaa"]) > 0:
        print(f"\n[integration] BONUS: bbb._play_chunks['aaa'] has "
              f"{len(b_eng._play_chunks['aaa'])} chunk(s) — audio flow confirmed")

    # Teardown: close all PeerConnections
    # ------------------------------------------------------------------
    all_engines = [hub_eng, a_eng, b_eng]
    for eng in all_engines:
        for peer, pc in list(eng.pcs.items()):
            try:
                await pc.close()
            except Exception:
                pass


@pytest.mark.asyncio
async def test_router_routes_offer():
    calls = []
    class DummyEngine:
        async def handle_offer(self, sender, data, ws_send):
            calls.append(("offer", sender, data))

    engines = {"bob": DummyEngine()}
    ws_send = make_router(engines)("alice")
    
    await ws_send({"target": "bob", "type": "offer", "data": "sdp_data"})
    assert calls == [("offer", "alice", "sdp_data")]


@pytest.mark.asyncio
async def test_router_routes_answer():
    calls = []
    class DummyEngine:
        async def handle_answer(self, data, sender):
            calls.append(("answer", data, sender))

    engines = {"bob": DummyEngine()}
    ws_send = make_router(engines)("alice")
    
    await ws_send({"target": "bob", "type": "answer", "data": "sdp_data"})
    assert calls == [("answer", "sdp_data", "alice")]


@pytest.mark.asyncio
async def test_router_routes_ice_candidate():
    calls = []
    class DummyEngine:
        async def handle_ice(self, data, sender):
            calls.append(("ice", data, sender))

    engines = {"bob": DummyEngine()}
    ws_send = make_router(engines)("alice")
    
    await ws_send({"target": "bob", "type": "ice-candidate", "data": "ice_data"})
    assert calls == [("ice", "ice_data", "alice")]


@pytest.mark.asyncio
async def test_router_unregistered_target_raises_key_error():
    engines = {}
    ws_send = make_router(engines)("alice")
    with pytest.raises(KeyError):
        await ws_send({"target": "bob", "type": "offer"})


def test_integration_settings_defaults():
    settings = _Settings()
    assert settings.security_mode == "dtls"
    assert settings.turn_url == ""
    assert settings.port_forward_enabled is False

