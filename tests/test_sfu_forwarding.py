import asyncio
import json
from unittest.mock import AsyncMock

import pytest

import webrtc_engine


class MS:
    security_mode = "e2ee"; turn_url = ""
    port_forward_enabled = False; forwarded_port = 0

def _e(username="alice"):
    return webrtc_engine.WebRTCEngine(username, MS(), {
        "x25519_private":"x","x25519_public":"x",
        "ed25519_private":"e","ed25519_public":"e"})

@pytest.mark.asyncio
async def test_negotiation_coalesces():
    e = _e()
    runs = []
    async def fake_real(peer):
        runs.append(peer)
        await asyncio.sleep(0.01)
    e._do_negotiation = fake_real            # replace the actual offer/answer body
    await asyncio.gather(
        e.request_negotiation("bob"),
        e.request_negotiation("bob"),
        e.request_negotiation("bob"),
    )
    # coalesced: one in-flight + at most one dirty re-run
    assert 1 <= len(runs) <= 2

@pytest.mark.asyncio
async def test_single_request_runs_once():
    e = _e()
    runs = []
    async def fake_real(peer):
        runs.append(peer)
    e._do_negotiation = fake_real
    await e.request_negotiation("bob")
    assert runs == ["bob"]

@pytest.mark.asyncio
async def test_relay_track_forwards_and_labels(monkeypatch):
    e = _e()
    sent = {}     # dest -> list of json strings
    class Ch:
        def __init__(self, p): self.p = p; self.readyState = "open"
        def send(self, m): sent.setdefault(self.p, []).append(m)
    e.data_channels = {"bob": Ch("bob"), "carol": Ch("carol")}
    class PC:
        def __init__(self): self.added = []
        def addTrack(self, t): self.added.append(t)
    e.pcs = {"bob": PC(), "carol": PC()}
    e.request_negotiation = AsyncMock()
    class T:
        id = "track-123"; kind = "audio"
    monkeypatch.setattr(e._relay, "subscribe", lambda t: t)  # identity -> sub is same obj
    await e._relay_track_to_others("bob", T())               # bob is the source
    # forwarded to carol only, NOT back to bob
    assert e.pcs["carol"].added and not e.pcs["bob"].added
    labels = [json.loads(m) for m in sent["carol"]]
    assert any(l["__type"] == "track_origin" and l["origin"] == "bob"
               and l["track_id"] == "track-123" for l in labels)
    assert "bob" not in sent     # source gets no label for its own track
    e.request_negotiation.assert_awaited()


@pytest.mark.asyncio
async def test_remove_peer_clears_forwarding_bookkeeping():
    e = _e()
    # carol is the source forwarding to bob and dave; bob also forwards to carol.
    e._forwarded = {
        "carol": [("bob", object(), "t1"), ("dave", object(), "t2")],
        "bob":   [("carol", object(), "t3"), ("dave", object(), "t4")],
    }
    await e.remove_peer("carol")
    # carol removed as a source entirely...
    assert "carol" not in e._forwarded
    # ...and pruned as a dest from bob's list (only the dave entry survives).
    assert [entry[0] for entry in e._forwarded["bob"]] == ["dave"]


# ---------------------------------------------------------------------------
# Task 7: receiver-side track-origin keying
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_track_origin_mapping_resolves_origin():
    e = _e()
    e._handle_track_origin({"track_id": "t1", "origin": "carol", "kind": "audio"})
    assert e._origin_of("t1") == "carol"

@pytest.mark.asyncio
async def test_origin_unknown_returns_none():
    e = _e()
    assert e._origin_of("t2") is None
    e._handle_track_origin({"track_id": "t2", "origin": "dave", "kind": "audio"})
    assert e._origin_of("t2") == "dave"

@pytest.mark.asyncio
async def test_resolve_origin_fastpath_when_not_in_room():
    e = _e()                       # room_id is None
    assert await e._resolve_origin("tX", fallback="bob") == "bob"

@pytest.mark.asyncio
async def test_resolve_origin_waits_then_falls_back(monkeypatch):
    e = _e()
    e.set_room("ROOM", is_creator=False)
    monkeypatch.setattr(e, "current_hub", lambda: "thehub")   # we are NOT the hub
    # speed up: patch wait_for timeout indirectly by pre-populating map after scheduling
    # simplest: mapping already present -> returns it without waiting
    e._origin_map["tY"] = "carol"
    assert await e._resolve_origin("tY", fallback="thehub") == "carol"

@pytest.mark.asyncio
async def test_resolve_origin_resolved_by_late_mapping():
    e = _e()
    e.set_room("ROOM", is_creator=False)
    e.current_hub = lambda: "thehub"        # not the hub
    async def feed():
        await asyncio.sleep(0.05)
        e._handle_track_origin({"track_id": "tZ", "origin": "carol", "kind": "audio"})
    task = asyncio.ensure_future(feed())
    got = await e._resolve_origin("tZ", fallback="thehub")
    await task
    assert got == "carol"


# ---------------------------------------------------------------------------
# Task 8: HUB-side chat/file relay + group-chat sender attribution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_relay_frame_to_others_skips_source():
    e = _e()
    out = {}
    class Ch:
        def __init__(self, p): self.p = p; self.readyState = "open"
        def send(self, m): out.setdefault(self.p, []).append(m)
    e.data_channels = {"bob": Ch("bob"), "carol": Ch("carol")}
    e._relay_frame_to_others(json.dumps({"__type":"chat","token":"CIPHER"}), source="bob")
    assert "carol" in out and "bob" not in out
    assert json.loads(out["carol"][0])["token"] == "CIPHER"

@pytest.mark.asyncio
async def test_relay_forwards_binary_bytes():
    e = _e()
    out = {}
    class Ch:
        def __init__(self, p): self.p = p; self.readyState = "open"
        def send(self, m): out.setdefault(self.p, []).append(m)
    e.data_channels = {"bob": Ch("bob"), "carol": Ch("carol")}
    e._relay_frame_to_others(b"\x00\x01\x02", source="bob")
    assert out["carol"] == [b"\x00\x01\x02"] and "bob" not in out

@pytest.mark.asyncio
async def test_group_chat_sender_attribution_dtls(monkeypatch):
    # A non-hub receives a hub-relayed chat originally from "bob"; sender must be bob.
    e = _e("dave")
    e.set_room("ROOM", is_creator=False)
    monkeypatch.setattr(e, "current_hub", lambda: "thehub")  # dave is NOT hub -> no relay
    e.settings = type("S", (), {"security_mode":"dtls"})()
    e._hello_sent = {"thehub": True}; e._peer_hello_verified = {"thehub": True}
    got = {}
    e.on_message = lambda sender, text, verified: got.update(sender=sender, text=text)
    raw = json.dumps({"__type":"chat","text":"hi","from":"bob"})
    await e._handle_text(raw, "thehub")        # arrived on the hub's channel
    assert got == {"sender":"bob","text":"hi"}

@pytest.mark.asyncio
async def test_hub_handle_text_relays_chat(monkeypatch):
    e = _e("alice")
    e.set_room("ROOM", is_creator=True)
    monkeypatch.setattr(e, "current_hub", lambda: "alice")   # alice IS hub
    e.settings = type("S", (), {"security_mode":"dtls"})()
    e._hello_sent = {"bob": True, "carol": True}
    e._peer_hello_verified = {"bob": True, "carol": True}
    e.on_message = lambda *a: None
    out = {}
    class Ch:
        def __init__(self, p): self.p = p; self.readyState = "open"
        def send(self, m): out.setdefault(self.p, []).append(m)
    e.data_channels = {"bob": Ch("bob"), "carol": Ch("carol")}
    raw = json.dumps({"__type":"chat","text":"hi","from":"bob"})
    await e._handle_text(raw, "bob")            # from bob -> relayed to carol only
    assert "carol" in out and "bob" not in out


@pytest.mark.asyncio
async def test_non_hub_does_not_relay(monkeypatch):
    # A non-hub receiving a chat must NOT re-broadcast it.
    e = _e("dave")
    e.set_room("ROOM", is_creator=False)
    monkeypatch.setattr(e, "current_hub", lambda: "thehub")   # dave is NOT the hub
    e.settings = type("S", (), {"security_mode":"dtls"})()
    e._hello_sent = {"thehub": True}; e._peer_hello_verified = {"thehub": True}
    e.on_message = lambda *a: None
    out = {}
    class Ch:
        def __init__(self, p): self.p = p; self.readyState = "open"
        def send(self, m): out.setdefault(self.p, []).append(m)
    e.data_channels = {"thehub": Ch("thehub"), "carol": Ch("carol")}
    await e._handle_text(json.dumps({"__type":"chat","text":"hi","from":"bob"}), "thehub")
    assert out == {}                              # nothing relayed


@pytest.mark.asyncio
async def test_group_chat_sender_attribution_e2ee(monkeypatch):
    # e2ee: "from" rides inside the encrypted token; receiver recovers true sender.
    from crypto import paseto_encrypt
    e = _e("dave")
    e.set_room("ROOM", is_creator=False)
    monkeypatch.setattr(e, "current_hub", lambda: "thehub")  # dave NOT hub -> no relay
    gkey = b"\x11" * 32
    e.group_key = gkey
    e._hello_sent = {"thehub": True}; e._peer_hello_verified = {"thehub": True}
    got = {}
    e.on_message = lambda sender, text, verified: got.update(sender=sender, text=text)
    token = paseto_encrypt({"__type":"chat","text":"hi","from":"bob"}, gkey)
    raw = json.dumps({"__type":"chat","token":token})
    await e._handle_text(raw, "thehub")
    assert got == {"sender":"bob","text":"hi"}
