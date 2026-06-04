import asyncio
import base64 as _b64
import hashlib
import hmac
import json
import os
import tempfile
import threading
from collections import deque
from typing import Callable, Optional

import numpy as np
import mss
import sounddevice as sd
from PIL import Image
from av import AudioFrame, VideoFrame

try:
    import cv2
except ImportError:
    cv2 = None

# Pillow's BOX resampling is area-averaging — the equivalent of cv2.INTER_AREA
# used for downscaling. Pillow replaces opencv here to keep the binary small.
_BOX = getattr(Image, "Resampling", Image).BOX
from aiortc import (
    RTCConfiguration,
    RTCIceCandidate,
    RTCIceServer,
    RTCPeerConnection,
    RTCSessionDescription,
    AudioStreamTrack,
    VideoStreamTrack,
)
from aiortc.contrib.media import MediaRelay

import config
from crypto import (
    derive_session_key_v2,
    generate_ephemeral_x25519,
    issue_membership_cert,
    paseto_decrypt,
    paseto_encrypt,
    paseto_sign,
    paseto_verify,
    verify_membership_cert,
)
from contacts import get_contact, upsert_contact


_STUN_SERVERS = [
    RTCIceServer(urls=["stun:stun.l.google.com:19302"]),
    RTCIceServer(urls=["stun:stun1.l.google.com:19302"]),
]

MAX_PRE_HELLO_FRAMES = 64
MAX_PRE_HELLO_BYTES = 1 * 1024 * 1024
MAX_INCOMING_FILE_SIZE = 2 * 1024 * 1024 * 1024

# Reject a signed hello whose timestamp is implausibly far from now. Generous
# enough to tolerate badly-set clocks; the real replay defence is the ephemeral
# DH (a replayed hello carries a stale ephemeral the attacker can't complete).
MAX_HELLO_SKEW_SECONDS = 24 * 3600


# --- VPN/router forwarded-port ICE binding (Approach A) ---------------------
# When a user has a genuinely reachable forwarded port (e.g. Proton VPN P2P
# port forwarding), we bind aioice's host socket to that port instead of a
# random one. aioice hardcodes ``local_addr=(address, 0)`` (aioice/ice.py) and
# exposes no port knob, so we wrap the event loop's create_datagram_endpoint
# once and rewrite ONLY that exact bind. The bound socket is a normal host
# socket, so aioice's existing STUN step auto-advertises the public mapping
# (ExitIP:forwarded_port) as a srflx candidate — no candidate injection. The
# feature is purely additive: if the bind fails (e.g. port already in use by
# another peer connection), aioice's own ``except OSError`` skips it and normal
# gathering continues.
_forward_active = False
_vpn_ip: str | None = None
_forward_port = 0
_forward_pool: list = []     # available mapped ports to assign, in order
_forward_used: int = 0       # how many pool ports already assigned this gather cycle


def set_forwarded_ports(vpn_ip: str, ports) -> None:
    """Publish a pool of forwarded ports; each new matching ICE bind takes the next one."""
    global _forward_active, _vpn_ip, _forward_pool, _forward_used, _forward_port
    _vpn_ip = vpn_ip
    _forward_pool = list(ports)
    _forward_used = 0
    _forward_active = bool(_forward_pool)
    _forward_port = _forward_pool[0] if _forward_pool else 0   # keep single-port field meaningful


def set_forwarded_port(vpn_ip: str, port: int) -> None:
    """Back-compat shim: a one-element pool."""
    set_forwarded_ports(vpn_ip, [int(port)])


def clear_forwarded_port() -> None:
    """Disable forwarded-port binding; new gathers fall back to normal ports."""
    global _forward_active, _vpn_ip, _forward_port, _forward_pool, _forward_used
    _forward_active, _vpn_ip, _forward_port = False, None, 0
    _forward_pool, _forward_used = [], 0


def _make_bind_wrapper(orig):
    async def wrapped(protocol_factory, *args, local_addr=None, **kwargs):
        global _forward_used
        if _forward_active and local_addr == (_vpn_ip, 0) and _forward_used < len(_forward_pool):
            local_addr = (_vpn_ip, _forward_pool[_forward_used])
            _forward_used += 1
        return await orig(protocol_factory, *args, local_addr=local_addr, **kwargs)
    return wrapped


def install_forward_patch(loop) -> None:
    """Wrap the loop's create_datagram_endpoint once (idempotent)."""
    if getattr(loop, "_helu_forward_patched", False):
        return
    loop.create_datagram_endpoint = _make_bind_wrapper(loop.create_datagram_endpoint)
    loop._helu_forward_patched = True


# ---------------------------------------------------------------------------
# Hub-election helpers (pure, deterministic — no I/O)
# ---------------------------------------------------------------------------

def reachability_tier(settings, current_port=None) -> int:
    """0=behind NAT, 1=TURN reachable, 2=directly reachable (forwarded port)."""
    if (current_port and current_port > 0) or (
            getattr(settings, "port_forward_enabled", False)
            and getattr(settings, "forwarded_port", 0)):
        return 2
    if getattr(settings, "turn_url", ""):
        return 1
    return 0


def elect_hub(member_tiers: dict, creator: str) -> str:
    """Deterministic hub election. Same inputs -> same hub on every client."""
    if not member_tiers:
        return creator
    best = max(member_tiers.values())
    if best == 0:
        return creator
    top = sorted(u for u, t in member_tiers.items() if t == best)
    if creator in top:
        return creator
    return top[0]


async def test_turn(turn_url: str, username: str = "", password: str = "") -> tuple[bool, str]:
    """Validate a TURN URL then probe for a relay candidate. Never logs creds."""
    url = (turn_url or "").strip()
    if not (url.startswith("turn:") or url.startswith("turns:")):
        return (False, "URL must start with turn: or turns:")
    pc = RTCPeerConnection(RTCConfiguration(iceServers=[
        RTCIceServer(urls=[url], username=username or None, credential=password or None)
    ]))
    try:
        pc.createDataChannel("probe")
        # setLocalDescription starts ICE gathering.
        await pc.setLocalDescription(await pc.createOffer())
        
        # Wait for ICE gathering to complete (timeout at 8s).
        if isinstance(pc.iceGatheringState, str) and pc.iceGatheringState != "complete":
            async def wait_gathering():
                while pc.iceGatheringState != "complete":
                    await asyncio.sleep(0.05)
            await asyncio.wait_for(wait_gathering(), timeout=8.0)
            
        sdp = pc.localDescription.sdp if pc.localDescription else ""
        if "typ relay" in sdp:
            return (True, "Relay reachable")
        return (False, "No relay candidate — check URL/credentials")
    except asyncio.TimeoutError:
        return (False, "Timed out contacting TURN server")
    except Exception as ex:
        return (False, f"Error: {type(ex).__name__}")
    finally:
        try:
            await pc.close()
        except Exception:
            pass


def test_forwarded_port(vpn_ip: str, port: int,
                        stun_host: str = "stun.l.google.com",
                        stun_port: int = 19302) -> tuple[bool, str]:
    """Bind the forwarded port and confirm STUN sees the same public port.

    Verifies the forward actually works: that we can bind ``vpn_ip:port`` and
    that the VPN/router preserves the port (so the public srflx candidate will
    be ``ExitIP:port`` and reachable). A mismatch means split-tunnel or a NAT
    that doesn't preserve the port.
    """
    import secrets as _secrets
    import socket as _socket

    from aioice import stun

    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.settimeout(3.0)
    except OSError as ex:
        return (False, f"Socket error: {type(ex).__name__}")
    try:
        try:
            s.bind((vpn_ip, port))
        except OSError as ex:
            return (False, f"Can't bind {vpn_ip}:{port} ({type(ex).__name__})")
        req = stun.Message(
            message_method=stun.Method.BINDING,
            message_class=stun.Class.REQUEST,
            transaction_id=_secrets.token_bytes(12),
        )
        s.sendto(bytes(req), (stun_host, stun_port))
        data, _ = s.recvfrom(1024)
        resp = stun.parse_message(data)
        ext_ip, ext_port = resp.attributes["XOR-MAPPED-ADDRESS"]
        if ext_port == port:
            return (True, f"Reachable: {ext_ip}:{ext_port}")
        return (False, f"Public port {ext_port} ≠ forwarded {port} "
                       "(split-tunnel or NAT not preserving port)")
    except Exception as ex:
        return (False, f"Error: {type(ex).__name__}")
    finally:
        try:
            s.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Media tracks
# ---------------------------------------------------------------------------

class ScreenShareTrack(VideoStreamTrack):
    kind = "video"

    def __init__(self, max_width: int | None = None, max_height: int | None = None,
                 target_fps: int | None = None):
        super().__init__()
        # mss instances are thread-affine; create lazily INSIDE recv() so it
        # binds to the thread that actually grabs frames.
        self._sct     = None
        self._monitor = None
        self._last_ts = 0.0
        self._logged  = False
        # Downscale caps keep the (software) encoder load sane on old CPUs —
        # encoding a native 4K frame 15x/sec will peg a weak machine.
        self._max_w   = max_width  or config.SCREEN_MAX_WIDTH
        self._max_h   = max_height or config.SCREEN_MAX_HEIGHT
        self.target_fps = target_fps or config.SCREEN_FPS

    def _ensure(self):
        if self._sct is None:
            self._sct     = mss.mss()
            self._monitor = self._sct.monitors[1]

    async def recv(self):
        pts, time_base = await self.next_timestamp()
        loop     = asyncio.get_event_loop()
        elapsed  = loop.time() - self._last_ts
        interval = 1.0 / self.target_fps
        if elapsed < interval:
            await asyncio.sleep(interval - elapsed)
        self._last_ts = loop.time()
        try:
            self._ensure()
            # mss returns BGRA; drop alpha + make contiguous (from_ndarray needs it).
            img = np.ascontiguousarray(np.array(self._sct.grab(self._monitor))[:, :, :3])
            # Downscale to fit within the caps (preserve aspect ratio) BEFORE
            # the frame reaches the encoder. INTER_AREA is best for shrinking.
            h0, w0 = img.shape[:2]
            scale  = min(self._max_w / w0, self._max_h / h0, 1.0)
            if scale < 1.0:
                if cv2 is not None:
                    img = cv2.resize(img, (int(w0 * scale), int(h0 * scale)), interpolation=cv2.INTER_AREA)
                else:
                    # Channel order is irrelevant to a per-channel resize, so the
                    # BGR array stays BGR through Pillow.
                    img = np.asarray(Image.fromarray(img).resize(
                        (int(w0 * scale), int(h0 * scale)), _BOX))
            # Even dimensions keep video encoders happy.
            h, w = img.shape[0] & ~1, img.shape[1] & ~1
            img = np.ascontiguousarray(img[:h, :w])
            if not self._logged:
                print(f"[screen] capturing {w0}x{h0} -> {w}x{h} @ {self.target_fps}fps", flush=True)
                self._logged = True
        except Exception as ex:
            print(f"[screen] capture error: {type(ex).__name__}: {ex}", flush=True)
            img = np.zeros((480, 640, 3), dtype=np.uint8)
            self._sct = None  # force re-create next time
        frame = VideoFrame.from_ndarray(img, format="bgr24")
        frame.pts       = pts
        frame.time_base = time_base
        return frame

    def stop(self):
        try:
            if self._sct is not None:
                self._sct.close()
        except Exception:
            pass
        self._sct = None


class MicrophoneTrack(AudioStreamTrack):
    kind = "audio"

    def __init__(self, push_to_talk: bool = False):
        super().__init__()
        import fractions
        self._ptt    = push_to_talk
        self._active = not push_to_talk
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=50)
        self._loop = asyncio.get_event_loop()
        self._timestamp = 0
        self._sample_rate = 48000
        self._time_base = fractions.Fraction(1, self._sample_rate)
        # Fixed 20 ms blocks (960 samples @ 48 kHz) so each frame is a clean,
        # consistent size for the Opus encoder (variable blocks => garbled audio).
        self._stream = sd.InputStream(
            samplerate=self._sample_rate, channels=1, dtype="int16",
            blocksize=960,
            callback=self._audio_callback,
        )
        self._stream.start()

    def _audio_callback(self, indata, frames, time_info, status):
        if self._active:
            self._loop.call_soon_threadsafe(self._queue_put, indata.copy())

    def _queue_put(self, data) -> None:
        try:
            self._queue.put_nowait(data)
        except asyncio.QueueFull:
            pass

    def set_active(self, active: bool) -> None:
        self._active = active

    async def recv(self):
        from aiortc.mediastreams import MediaStreamError
        if self.readyState != "live":
            raise MediaStreamError

        data  = await self._queue.get()
        frame = AudioFrame.from_ndarray(data.T, format="s16", layout="mono")
        frame.pts         = self._timestamp
        frame.time_base   = self._time_base
        frame.sample_rate = self._sample_rate
        
        self._timestamp += frame.samples
        return frame

    def stop(self) -> None:
        self._stream.stop()
        self._stream.close()


# ---------------------------------------------------------------------------
# Mesh WebRTC engine
# ---------------------------------------------------------------------------

class WebRTCEngine:
    def __init__(self, my_username: str, settings, keys: dict):
        self.my_username = my_username
        self.settings    = settings
        self.keys        = keys

        # Per-peer collections (keyed by peer username)
        self.pcs:                  dict[str, RTCPeerConnection] = {}
        self.data_channels:        dict                         = {}
        self.session_keys:         dict[str, bytes]             = {}
        self._hello_sent:          dict[str, bool]              = {}
        self._peer_hello_verified: dict[str, bool]              = {}
        self._eph_priv:            dict[str, str]               = {}  # peer -> our per-session ephemeral X25519 priv (b64)
        self._pre_hello_buffers:   dict[str, deque]             = {}
        self._pre_hello_bytes:     dict[str, int]               = {}
        self._is_negotiating:      dict[str, bool]              = {}
        self._neg_dirty:           dict[str, bool]              = {}
        # Peers we tried to call before their data channel was open — the
        # "call_start" ping is (re)sent from _bind_channel once it opens so the
        # callee actually rings instead of silently missing the call.
        self._pending_call_start:  set[str]                     = set()
        # PSK channel authentication (feature C). When room_psk is set, peers must
        # prove knowledge of the pre-shared key (HMAC challenge) BEFORE the hello
        # — a room becomes invisible to anyone without the PSK from the invite.
        self.room_psk:             Optional[str]                = None   # base64 32-byte
        self._psk_authed:          dict[str, bool]              = {}
        self._psk_my_nonce:        dict[str, str]               = {}
        # Membership PKI (feature D, advisory). The creator vouches for members by
        # signing a cert; peers verify it against the creator's key but never drop
        # the connection (PSK already gates access) — they just flag membership.
        self.room_creator_pubkey:  Optional[str]                = None   # creator ed25519 pub
        self.my_membership_cert:   Optional[str]                = None   # our creator-signed cert
        self._peer_is_member:      dict[str, bool]              = {}
        self._file_buffers:        dict[str, dict]              = {}
        self._forwarded:           dict[str, list]              = {}  # source_peer -> [(dest, sub, sub_id)]
        self._origin_map:          dict[str, str]               = {}  # track_id -> origin username
        self._origin_waiters:      dict[str, asyncio.Future]    = {}  # track_id -> Future waiting for origin

        # Shared media sources fanned out to every peer via a relay so the mic
        # is only captured once and the screen is only grabbed once, regardless
        # of how many peers are in the call.
        self._relay         = MediaRelay()
        self._mic_source    = None   # single MicrophoneTrack capturing the mic
        self._screen_source = None   # single ScreenShareTrack grabbing the screen
        self._voice_peers:  set[str] = set()   # peers we've added a mic track to
        self._screen_peers: set[str] = set()   # peers we've added a screen track to
        # RTP senders kept so a track can be REMOVED (stop sharing/voice) without
        # tearing down the whole call — screen and voice are independent streams.
        self._screen_senders: dict[str, object] = {}
        self._voice_senders:  dict[str, object] = {}
        self._incoming_audio_active: set[str] = set()  # peers whose audio we play

        # Group call state
        self.group_key:             Optional[bytes] = None
        self.is_room_creator:       bool            = False
        self.room_id:               Optional[str]   = None
        self._pre_group_key_buffer: deque           = deque()
        self._send_ws:              Optional[Callable] = None

        # Hub-election state
        self._cap_tier:          dict[str, int] = {}
        self._cap_epoch:         dict[str, int] = {}
        self._my_epoch:          int            = 0   # bumped in client before each hub_capability broadcast
        self._room_creator_name: Optional[str]  = None

        # 1-to-1 compat: target_peer is set by create_offer / handle_offer
        self.target_peer: str = ""

        # Callbacks set by client.py — on_state_change(peer, state)
        self.on_state_change:  Optional[Callable] = None  # (peer: str, state: str)
        self.on_message:       Optional[Callable] = None  # (sender, text, verified)
        self.on_file_chunk:    Optional[Callable] = None
        self.on_file_complete: Optional[Callable] = None
        self.on_call_incoming: Optional[Callable] = None
        self.on_call_accepted: Optional[Callable] = None
        self.on_call_rejected: Optional[Callable] = None
        self.on_hangup:        Optional[Callable] = None
        self.on_video_frame:   Optional[Callable] = None  # (sender: str, img: np.ndarray)
        self.on_key_change:    Optional[Callable] = None  # (peer: str) — verified key changed
        self.on_session_ready: Optional[Callable] = None  # (peer: str) — hello verified, channel usable
        self.on_history_request:  Optional[Callable] = None  # (peer, room_id, since)
        self.on_history_response: Optional[Callable] = None  # (peer, room_id, messages)
        self.on_membership_change: Optional[Callable] = None  # (peer, is_member)

        # Audio playback: a single callback-driven output stream. Incoming
        # decoded frames are appended to per-peer numpy buffers; sounddevice's
        # audio thread pulls + mixes them in _play_callback (NOT the asyncio
        # loop — a blocking write in the loop starves playback and freezes UI).
        self._output_stream = None
        # Per-peer queue of decoded int16 chunks (deque of ndarrays). Using a
        # deque + partial-head consumption avoids the O(n) full-buffer copy that
        # np.concatenate did on every 20 ms frame (GC churn on weak hardware).
        self._play_chunks: dict[str, deque] = {}
        self._play_lock = threading.Lock()

        # Diagnostics state (read by get_diagnostics; cheap, no secrets).
        self._ice_states:      dict[str, str] = {}
        self.last_error:       str = ""
        self.signaling_status: str = "idle"

    # ------------------------------------------------------------------
    # ICE / TURN configuration (from settings — env only seeds first run)
    # ------------------------------------------------------------------

    def _ice_servers(self) -> list:
        servers = list(_STUN_SERVERS)
        url = getattr(self.settings, "turn_url", "") or ""
        # A TURN relay (if configured) is what makes connections succeed behind
        # symmetric / carrier-grade NAT where STUN alone fails.
        if url:
            servers.append(RTCIceServer(
                urls=[url],
                username=getattr(self.settings, "turn_username", "") or None,
                credential=getattr(self.settings, "turn_password", "") or None,
            ))
        return servers

    def _ice_config(self) -> RTCConfiguration:
        return RTCConfiguration(iceServers=self._ice_servers())

    def get_diagnostics(self) -> dict:
        """Redacted connection snapshot for the diagnostics UI — never includes
        passwords, keys, SDP, or ICE candidate strings."""
        peers = []
        for peer, pc in self.pcs.items():
            dc = self.data_channels.get(peer)
            peers.append({
                "peer":          peer,
                "connection":    pc.connectionState,
                "signaling":     pc.signalingState,
                "ice":           self._ice_states.get(peer, pc.iceConnectionState),
                "ice_gathering": pc.iceGatheringState,
                "datachannel":   getattr(dc, "readyState", "—") if dc else "none",
                "hello_sent":    bool(self._hello_sent.get(peer)),
                "hello_ok":      bool(self._peer_hello_verified.get(peer)),
                "session_key":   peer in self.session_keys,
            })
        try:
            hub = self.current_hub() if self.room_id else ""
        except Exception:
            hub = "?"
        return {
            "signaling":       self.signaling_status,
            "my_username":     self.my_username,
            "room_id":         self.room_id or "",
            "hub":             hub,
            "security_mode":   getattr(self.settings, "security_mode", ""),
            "turn_configured": bool(getattr(self.settings, "turn_url", "")),
            "num_peers":       len(self.pcs),
            "last_error":      self.last_error,
            "peers":           peers,
        }

    # ------------------------------------------------------------------
    # 1-to-1 backward-compat properties
    # ------------------------------------------------------------------

    @property
    def pc(self):
        return self.pcs.get(self.target_peer)

    @property
    def data_channel(self):
        return self.data_channels.get(self.target_peer)

    # ------------------------------------------------------------------
    # Room setup
    # ------------------------------------------------------------------

    def set_room(self, room_id: str, is_creator: bool) -> None:
        self.room_id        = room_id
        self.is_room_creator = is_creator
        if is_creator:
            self.group_key = os.urandom(32)
        self._room_creator_name = self.my_username if is_creator else None

    def set_room_creator(self, name: str) -> None:
        """Called on non-creator peers once the creator's username is known."""
        self._room_creator_name = name

    def record_capability(self, peer: str, tier: int, epoch: int) -> None:
        """Store a peer's reachability tier for hub election; stale epochs are ignored."""
        if epoch <= self._cap_epoch.get(peer, 0):
            return
        self._cap_epoch[peer] = epoch
        self._cap_tier[peer] = tier

    def forget_peer_capability(self, peer: str) -> None:
        """Drop a peer from hub election (used on hub failover so a dead relay
        isn't re-elected before the topology is rebuilt)."""
        self._cap_tier.pop(peer, None)
        self._cap_epoch.pop(peer, None)

    def _my_tier(self) -> int:
        """Return this engine's own reachability tier using current module-global state."""
        cur = _forward_port if _forward_active else None
        return reachability_tier(self.settings, current_port=cur)

    def capability_payload(self) -> dict:
        """Build this peer's hub-election capability announcement (bumps epoch)."""
        self._my_epoch += 1
        return {"tier": self._my_tier(), "epoch": self._my_epoch,
                "creator": self.is_room_creator}

    def current_hub(self) -> str:
        """Return the elected hub username given current capability records."""
        members = dict(self._cap_tier)
        members[self.my_username] = self._my_tier()   # always include self
        creator = self._room_creator_name or min([self.my_username, *members.keys()])
        return elect_hub(members, creator)

    # ------------------------------------------------------------------
    # Track-origin helpers (receiver-side SFU origin keying)
    # ------------------------------------------------------------------

    def _origin_of(self, track_id: str):
        return self._origin_map.get(track_id)

    async def _handle_track_origin(self, frame: dict, peer: str) -> None:
        tid = frame["track_id"]
        self._origin_map[tid] = frame["origin"]
        fut = self._origin_waiters.pop(tid, None)
        if fut is not None and not fut.done():
            fut.set_result(frame["origin"])

    async def _resolve_origin(self, track_id: str, fallback: str) -> str:
        # 1-to-1, or the hub receiving ORIGINAL (non-forwarded) member tracks:
        # there is no origin label, so key by the signaling peer immediately
        # (no waiting -> no audio latency).
        if not self.room_id or self.current_hub() == self.my_username:
            return fallback
        if track_id in self._origin_map:
            return self._origin_map[track_id]
        fut = self._origin_waiters.get(track_id)
        if fut is None:
            fut = asyncio.get_running_loop().create_future()
            self._origin_waiters[track_id] = fut
        try:
            return await asyncio.wait_for(asyncio.shield(fut), timeout=3.0)
        except asyncio.TimeoutError:
            return fallback

    # ------------------------------------------------------------------
    # Per-peer PC init
    # ------------------------------------------------------------------

    def _init_pc(self, peer: str) -> None:
        # Ensure the forwarded-port bind wrapper is installed on this loop
        # before aiortc gathers ICE (idempotent, no-op when feature is off).
        try:
            install_forward_patch(asyncio.get_event_loop())
        except Exception:
            pass
        pc = RTCPeerConnection(configuration=self._ice_config())
        self.pcs[peer]                  = pc
        self._hello_sent[peer]          = False
        self._peer_hello_verified[peer] = False
        self._psk_authed[peer]          = False   # fresh PSK auth per connection
        self._psk_my_nonce.pop(peer, None)
        self._eph_priv.pop(peer, None)   # fresh ephemeral per connection
        self._pre_hello_buffers[peer]   = deque()
        self._pre_hello_bytes[peer]     = 0
        self._is_negotiating[peer]      = False

        # NOTE: aiortc gathers ICE non-trickle — all candidates are embedded in
        # the SDP offer/answer, and it never emits a browser-style "icecandidate"
        # event. So there is deliberately no outbound trickle handler here.
        # handle_ice() still accepts inbound candidates defensively (e.g. from a
        # future browser peer that does trickle).

        @pc.on("connectionstatechange")
        def on_state():
            state = pc.connectionState
            print(f"[rtc] {self.my_username}: pc[{peer}] connection -> {state}", flush=True)
            if self.on_state_change:
                self.on_state_change(peer, state)
            
            # Clean up automatically when the connection fails or closes
            if state in ("closed", "failed"):
                # Asynchronously clean up the dead peer connection
                asyncio.ensure_future(self.remove_peer(peer))

        @pc.on("iceconnectionstatechange")
        def on_ice_state():
            self._ice_states[peer] = pc.iceConnectionState
            print(f"[rtc] {self.my_username}: pc[{peer}] ICE -> {pc.iceConnectionState}", flush=True)

        @pc.on("icegatheringstatechange")
        def on_gather_state():
            print(f"[rtc] {self.my_username}: pc[{peer}] gathering -> {pc.iceGatheringState}", flush=True)

        @pc.on("datachannel")
        def on_dc(channel):
            self.data_channels[peer] = channel
            self._bind_channel(channel, peer)

        # NOTE: aiortc does NOT reliably emit "negotiationneeded" the way
        # browsers do, so we drive negotiation EXPLICITLY (after creating the
        # data channel and after addTrack). Do not rely on the event here.

        @pc.on("track")
        def on_track(track):
            if track.kind == "video":
                asyncio.ensure_future(self._render_video(track, peer))
            elif track.kind == "audio":
                asyncio.ensure_future(self._handle_incoming_audio(track, peer))
            if self.room_id and self.current_hub() == self.my_username:
                asyncio.ensure_future(self._relay_track_to_others(peer, track))

    # ------------------------------------------------------------------
    # DataChannel binding
    # ------------------------------------------------------------------

    def _bind_channel(self, channel, peer: str) -> None:
        async def _on_open():
            if self.room_psk:
                # PSK-protected room: prove knowledge of the pre-shared key FIRST.
                # The hello (and everything after) is gated until the peer answers
                # our challenge correctly (see _handle_psk → _start_session).
                self._psk_authed[peer] = False
                nonce = _b64.b64encode(os.urandom(16)).decode()
                self._psk_my_nonce[peer] = nonce
                try:
                    channel.send(json.dumps({"__type": "psk_challenge", "nonce": nonce}))
                    print(f"[psk] {self.my_username}: sent PSK challenge to {peer}", flush=True)
                except Exception:
                    pass
            else:
                await self._start_session(peer)
            # If a call was requested before this channel opened, ring now.
            if peer in self._pending_call_start:
                self._pending_call_start.discard(peer)
                try:
                    channel.send(json.dumps({"__type": "call_start"}))
                    print(f"[rtc] {self.my_username}: sent deferred call_start to {peer}", flush=True)
                except Exception as ex:
                    print(f"[rtc] {self.my_username}: deferred call_start to {peer} failed: {ex}", flush=True)

        @channel.on("open")
        async def on_open():
            await _on_open()

        @channel.on("message")
        async def on_msg(data):
            if isinstance(data, bytes):
                await self._handle_binary(data, peer)
            else:
                await self._handle_text(data, peer)

        # On the responder side the channel arrives via on_datachannel and may
        # ALREADY be open, so the "open" event above would never fire. Run the
        # open logic immediately in that case.
        if getattr(channel, "readyState", None) == "open":
            asyncio.ensure_future(_on_open())

    # ------------------------------------------------------------------
    # PSK channel authentication (feature C)
    # ------------------------------------------------------------------

    def set_room_psk(self, psk: Optional[str]) -> None:
        """Set (or clear with None) the room's pre-shared key. When set, every
        peer must prove knowledge of it before any identity/media is exchanged."""
        self.room_psk = psk or None
        if not self.room_psk:
            self._psk_authed.clear()
            self._psk_my_nonce.clear()

    def adopt_creator_identity(self) -> None:
        """Creator becomes the membership root: it is its own first member and
        the trust anchor every other member's cert is verified against."""
        self.room_creator_pubkey = self.keys["ed25519_public"]
        self.my_membership_cert = issue_membership_cert(
            self.keys["ed25519_private"], self.keys["ed25519_public"],
            self.room_id, self.my_username, self.keys["ed25519_public"])

    def set_room_creator_pubkey(self, pub: Optional[str]) -> None:
        """Member side: trust anchor (creator's key) from the invite. Our own
        cert is unknown until the creator issues one."""
        self.room_creator_pubkey = pub or None
        self.my_membership_cert = None

    def is_member(self, peer: str) -> bool:
        return self._peer_is_member.get(peer, False)

    def purge_secrets(self) -> None:
        """Wipe all session/room cryptographic material from RAM (feature H —
        ephemeral rooms purge on leave so nothing survives the session)."""
        self.session_keys.clear()
        self.group_key = None
        self._eph_priv.clear()
        try:
            self._pre_group_key_buffer.clear()
        except Exception:
            pass
        self._psk_authed.clear()
        self._psk_my_nonce.clear()
        self.room_psk = None
        self.my_membership_cert = None
        self.room_creator_pubkey = None
        self._peer_is_member.clear()

    def _psk_proof(self, nonce: str) -> str:
        """HMAC-SHA256 over (nonce | room_id) keyed by the PSK — proves the
        sender holds the PSK without revealing it. Both sides bind to room_id so
        a proof from one room can't be replayed into another."""
        key = _b64.b64decode(self.room_psk)
        msg = (nonce + "|" + (self.room_id or "")).encode()
        return hmac.new(key, msg, hashlib.sha256).hexdigest()

    async def _handle_psk(self, kind: str, frame: dict, peer: str) -> None:
        if not self.room_psk:
            return  # not a PSK room — ignore stray PSK frames
        ch = self.data_channels.get(peer)
        if kind == "psk_challenge":
            # Answer the peer's challenge with a proof over THEIR nonce.
            proof = self._psk_proof(frame.get("nonce", ""))
            if ch and ch.readyState == "open":
                try:
                    ch.send(json.dumps({"__type": "psk_response", "proof": proof}))
                except Exception:
                    pass
        elif kind == "psk_response":
            # Verify the peer's proof over OUR nonce (constant-time).
            expected = self._psk_proof(self._psk_my_nonce.get(peer, ""))
            if hmac.compare_digest(expected, str(frame.get("proof", ""))):
                if not self._psk_authed.get(peer):
                    self._psk_authed[peer] = True
                    print(f"[psk] {self.my_username}: {peer} passed PSK auth", flush=True)
                    await self._start_session(peer)
            else:
                print(f"[psk] {self.my_username}: {peer} FAILED PSK auth — aborting", flush=True)
                await self.remove_peer(peer)

    # ------------------------------------------------------------------
    # Hello handshake
    # ------------------------------------------------------------------

    async def _start_session(self, peer: str) -> None:
        """Begin the identity/session phase once any PSK gate has passed: send the
        signed hello (E2EE) or mark the peer ready (DTLS-only)."""
        if self.settings.security_mode == "e2ee":
            await self._send_hello(peer)
        else:
            self._hello_sent[peer]          = True
            self._peer_hello_verified[peer] = True
            await self._flush_pre_hello_buffer(peer)
            if self.on_session_ready:
                self.on_session_ready(peer)

    def _ephemeral_pub(self, peer: str) -> str:
        """Return our per-session ephemeral X25519 public key for `peer`,
        generating (and storing the private half) on first use. Stable for the
        life of the connection so both _send_hello and _handle_hello agree."""
        priv_b64 = self._eph_priv.get(peer)
        if priv_b64 is None:
            priv_b64, pub_b64 = generate_ephemeral_x25519()
            self._eph_priv[peer] = priv_b64
            return pub_b64
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        priv = X25519PrivateKey.from_private_bytes(_b64.b64decode(priv_b64))
        return _b64.b64encode(
            priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()

    async def _send_hello(self, peer: str) -> None:
        from datetime import datetime, timezone
        payload = {
            "username":    self.my_username,
            "x25519_pub":  self.keys["x25519_public"],
            "ed25519_pub": self.keys["ed25519_public"],
            "eph_x25519_pub": self._ephemeral_pub(peer),
            "iat":         datetime.now(timezone.utc).isoformat(),
        }
        token = paseto_sign(payload, self.keys["ed25519_private"], self.keys["ed25519_public"])
        hello = {"__type": "hello", "token": token}
        if self.my_membership_cert:            # feature D: present our membership cert
            hello["cert"] = self.my_membership_cert
        self.data_channels[peer].send(json.dumps(hello))
        self._hello_sent[peer] = True

    def _hello_iat_fresh(self, iat: str) -> bool:
        """Defence-in-depth: reject a signed hello with an implausible timestamp."""
        if not iat:
            return False
        from datetime import datetime, timezone
        try:
            ts = datetime.fromisoformat(iat)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return False
        skew = abs((datetime.now(timezone.utc) - ts).total_seconds())
        return skew <= MAX_HELLO_SKEW_SECONDS

    async def _handle_hello(self, frame: dict, peer: str) -> None:
        if self._peer_hello_verified.get(peer):
            return
        if self.settings.security_mode == "e2ee":
            prior = get_contact(peer)
            # The hello's signed payload always carries the sender's self-claimed
            # ed25519 key. Pull it out so we can tell a genuine key rotation (a
            # different but internally-consistent identity) apart from garbage.
            try:
                parts = frame["token"].split(".")
                claimed_pub = json.loads(
                    _b64.urlsafe_b64decode(parts[2] + "==")[:-64]
                )["ed25519_pub"]
            except Exception:
                claimed_pub = None

            # SEC-01: Verify against the pre-stored public key if we already know
            # this contact. Only use the self-claimed key for new contacts (TOFU).
            if prior and prior.ed25519_pub:
                verify_pub = prior.ed25519_pub
            else:
                verify_pub = claimed_pub
                if verify_pub is None:
                    return

            try:
                payload = paseto_verify(frame["token"], verify_pub)
            except Exception:
                # The hello didn't verify against the key we have pinned. Decide
                # whether the peer simply re-keyed (reinstalled / regenerated) by
                # checking the hello against the key it claims for itself. A valid
                # signature there means a real identity — just a different one than
                # we pinned — i.e. a key rotation, not noise.
                rotation = bool(
                    claimed_pub and prior and prior.ed25519_pub
                    and claimed_pub != prior.ed25519_pub
                )
                if rotation:
                    try:
                        payload = paseto_verify(frame["token"], claimed_pub)
                    except Exception:
                        rotation = False
                if not rotation:
                    print(f"[crypto] Signature verification failed for peer {peer}.", flush=True)
                    return
                # A VERIFIED contact's signing key changing is a security event
                # (possible MITM): alert the user and abort — never auto-accept.
                if prior.verified:
                    print(f"[crypto] KEY CHANGED for verified contact {peer}! Aborting connection.", flush=True)
                    if self.on_key_change:
                        self.on_key_change(peer)
                    asyncio.create_task(self.remove_peer(peer))
                    return
                # An UNVERIFIED (trust-on-first-use) contact re-keyed. Don't drop
                # their frames silently — surface the change AND re-pin the new key
                # (the success path below calls upsert_contact) so chat and calls
                # keep working after the peer regenerated its identity.
                print(f"[crypto] Unverified contact {peer} re-keyed — re-pinning (TOFU).", flush=True)
                if self.on_key_change:
                    self.on_key_change(peer)
                # `payload` is set from the claimed-key verification; fall through.

            # Bind the claimed identity to the signaling peer name. A peer
            # connected to signaling as `peer` must not be able to assert a
            # different username (which would poison another contact's entry).
            if payload.get("username") != peer:
                return

            # SEC-02: If the contact is verified and their key has changed, abort
            # the connection. Checked first so the user is always alerted to a
            # possible MITM, regardless of timestamp/ephemeral structural checks.
            if prior and prior.verified:
                key_changed = bool(
                    (prior.x25519_pub and prior.x25519_pub != payload["x25519_pub"]) or
                    (prior.ed25519_pub and prior.ed25519_pub != payload["ed25519_pub"])
                )
                if key_changed:
                    print(f"[crypto] KEY CHANGED for verified contact {peer}! Aborting connection.", flush=True)
                    if self.on_key_change:
                        self.on_key_change(peer)
                    # Tear down the peer connection immediately
                    asyncio.create_task(self.remove_peer(peer))
                    return

            # SEC-03: Reject a hello whose signed timestamp is wildly stale/future.
            if not self._hello_iat_fresh(payload.get("iat", "")):
                print(f"[crypto] Stale/implausible hello timestamp from {peer}; rejecting.", flush=True)
                return

            # SEC-04 (forward secrecy): the hello carries a signed ephemeral
            # X25519 public key. Without one the peer is an old client; refuse
            # rather than silently fall back to non-PFS static-key derivation.
            peer_eph_pub = payload.get("eph_x25519_pub")
            if not peer_eph_pub:
                print(f"[crypto] Hello from {peer} lacks an ephemeral key; rejecting.", flush=True)
                return

            # Ensure our own ephemeral exists even if the peer's hello beat ours.
            self._ephemeral_pub(peer)
            self.session_keys[peer] = derive_session_key_v2(
                self.keys["x25519_private"], self._eph_priv[peer],
                payload["x25519_pub"], peer_eph_pub,
            )
            upsert_contact(peer,
                           x25519_pub=payload["x25519_pub"],
                           ed25519_pub=payload["ed25519_pub"])
            # Creator sends group key to this peer
            if self.is_room_creator and self.group_key:
                await self._send_group_key_to(peer)

        self._peer_hello_verified[peer] = True
        await self._flush_pre_hello_buffer(peer)
        if self.on_session_ready:
            self.on_session_ready(peer)
        # Feature D (advisory membership): flag whether the peer holds a valid
        # creator-signed cert; if I'm the creator and they don't, issue one.
        if self.room_id:
            is_member = self._evaluate_membership(peer, frame.get("cert"))
            if not is_member and self.is_room_creator:
                await self._send_cert_grant(peer, payload["username"], payload["ed25519_pub"])
                self._set_member(peer, True)

    # ------------------------------------------------------------------
    # Membership PKI (feature D, advisory — never drops connections)
    # ------------------------------------------------------------------

    def _set_member(self, peer: str, ok: bool) -> None:
        self._peer_is_member[peer] = ok
        if self.on_membership_change:
            self.on_membership_change(peer, ok)

    def _evaluate_membership(self, peer: str, cert: Optional[str]) -> bool:
        c = get_contact(peer)
        peer_pub = c.ed25519_pub if c else None
        ok = bool(
            cert and self.room_creator_pubkey and self.room_id and peer_pub
            and verify_membership_cert(cert, self.room_creator_pubkey,
                                       self.room_id, peer, peer_pub)
        )
        self._set_member(peer, ok)
        return ok

    async def _send_cert_grant(self, peer: str, member_username: str,
                               member_ed25519_pub: str) -> None:
        if not self.is_room_creator:
            return
        cert = issue_membership_cert(
            self.keys["ed25519_private"], self.keys["ed25519_public"],
            self.room_id, member_username, member_ed25519_pub)
        frame = self._encrypt_frame_for({"__type": "cert_grant", "cert": cert}, peer)
        ch = self.data_channels.get(peer)
        if ch and ch.readyState == "open":
            try:
                ch.send(json.dumps(frame))
                print(f"[membership] {self.my_username}: issued cert to {member_username}", flush=True)
            except Exception:
                pass

    async def _handle_cert_grant(self, frame: dict, peer: str) -> None:
        d = self._decrypt_with_session(frame, peer)
        cert = d.get("cert")
        if not cert:
            return
        self.my_membership_cert = cert
        print(f"[membership] {self.my_username}: received membership cert from {peer}", flush=True)
        # Tell everyone we're now a vouched member so they upgrade our badge.
        for p in list(self.data_channels.keys()):
            ch = self.data_channels.get(p)
            if ch and ch.readyState == "open":
                mf = self._encrypt_frame_for({"__type": "membership", "cert": cert}, p)
                try:
                    ch.send(json.dumps(mf))
                except Exception:
                    pass

    async def _handle_membership(self, frame: dict, peer: str) -> None:
        d = self._decrypt_with_session(frame, peer)
        self._evaluate_membership(peer, d.get("cert"))

    async def _flush_pre_hello_buffer(self, peer: str) -> None:
        buf = self._pre_hello_buffers.get(peer, deque())
        while buf:
            kind, data = buf.popleft()
            if kind == "text":
                await self._handle_text(data, peer)
            else:
                await self._handle_binary(data, peer)
        self._pre_hello_bytes[peer] = 0

    def _buffer_pre_hello(self, peer: str, kind: str, data) -> None:
        buf = self._pre_hello_buffers.setdefault(peer, deque())
        size = len(data.encode("utf-8") if isinstance(data, str) else data)
        total = self._pre_hello_bytes.get(peer, 0) + size
        if len(buf) >= MAX_PRE_HELLO_FRAMES or total > MAX_PRE_HELLO_BYTES:
            buf.clear()
            self._pre_hello_bytes[peer] = 0
            return
        buf.append((kind, data))
        self._pre_hello_bytes[peer] = total

    def _close_file_state(self, state: dict, delete: bool = False) -> None:
        try:
            state["file"].flush()
            os.fsync(state["file"].fileno())
        except Exception:
            pass
        try:
            state["file"].close()
        except Exception:
            pass
        if delete:
            self._delete_tmp_file(state.get("path", ""))

    def _delete_tmp_file(self, path: str) -> None:
        try:
            if path:
                os.unlink(path)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Message handling
    # ------------------------------------------------------------------

    async def _handle_text(self, raw: str, peer: str) -> None:
        try:
            frame = json.loads(raw)
        except Exception:
            return
        t = frame.get("__type")
        if t in ("psk_challenge", "psk_response"):
            await self._handle_psk(t, frame, peer)
            return
        if t == "hello":
            # In a PSK-protected room, ignore a hello until the peer has proven
            # the pre-shared key — no identity is exchanged with an unauthorised peer.
            if self.room_psk and not self._psk_authed.get(peer):
                print(f"[psk] {self.my_username}: dropping hello from {peer} (PSK not yet proven)", flush=True)
                return
            await self._handle_hello(frame, peer)
            return
        if not (self._hello_sent.get(peer) and self._peer_hello_verified.get(peer)):
            self._buffer_pre_hello(peer, "text", raw)
            return
        await self._dispatch_frame(frame, peer)
        if (self.room_id and self.current_hub() == self.my_username
                and frame.get("__type") in ("chat", "file_meta", "file_end")):
            await self._relay_frame_to_others(raw, source=peer)

    async def _handle_binary(self, data: bytes, peer: str) -> None:
        if not (self._hello_sent.get(peer) and self._peer_hello_verified.get(peer)):
            self._buffer_pre_hello(peer, "binary", data)
            return
        state = self._file_buffers.get(peer, {}).get("_current")
        if state:
            remaining = state["size"] - state["received"]
            block = data[:max(0, remaining)]
            if block:
                state["file"].write(block)
                state["sha"].update(block)
                state["received"] += len(block)
            received = state["received"]
            if self.on_file_chunk:
                self.on_file_chunk(state["filename"], received, state["size"])
        if (self.room_id and self.current_hub() == self.my_username
                and self._file_buffers.get(peer, {}).get("_current")):
            await self._relay_frame_to_others(data, source=peer)

    async def _dispatch_frame(self, frame: dict, peer: str) -> None:
        t = frame.get("__type")

        if t == "track_origin":
            await self._handle_track_origin(frame, peer)
            return

        if t == "group_key":
            await self._handle_group_key(frame, peer)
            return

        if t == "history_request":
            d = self._decrypt_with_session(frame, peer)
            if self.on_history_request:
                self.on_history_request(peer, d.get("room_id", ""), d.get("since", ""))
            return

        if t == "history_response":
            d = self._decrypt_with_session(frame, peer)
            if self.on_history_response:
                self.on_history_response(peer, d.get("room_id", ""), d.get("messages") or [])
            return

        if t == "cert_grant":
            await self._handle_cert_grant(frame, peer)
            return

        if t == "membership":
            await self._handle_membership(frame, peer)
            return

        if t == "chat":
            sender = peer
            if self.settings.security_mode == "e2ee":
                key = self.group_key if self.room_id else self.session_keys.get(peer)
                if not key:
                    return
                try:
                    payload = paseto_decrypt(frame["token"], key)
                    text = payload.get("text", "")
                    sender = payload.get("from") or peer
                except Exception:
                    text = "[decryption failed]"
            else:
                text = frame.get("text", "")
                sender = frame.get("from") or peer
            if self.on_message:
                self.on_message(sender, text, frame.get("verified", False))

        elif t == "file_meta":
            meta  = self._decrypt_dict(frame, peer)
            fname = os.path.basename(str(meta.get("filename", "file"))) or "file"
            try:
                size = int(meta.get("size", 0))
            except (TypeError, ValueError):
                return
            sha_hex = str(meta.get("sha256", ""))
            if size < 0 or size > MAX_INCOMING_FILE_SIZE or len(sha_hex) != 64:
                return
            old = self._file_buffers.get(peer, {}).get("_current")
            if old:
                self._close_file_state(old, delete=True)
            fd, tmp_name = tempfile.mkstemp(prefix="helucryptic-recv-", suffix=".part")
            tmp_file = os.fdopen(fd, "wb")
            state = {
                "filename": fname,
                "size": size,
                "sha256": sha_hex,
                "received": 0,
                "path": tmp_name,
                "file": tmp_file,
                "sha": hashlib.sha256(),
            }
            self._file_buffers.setdefault(peer, {})
            self._file_buffers[peer][fname]      = state
            self._file_buffers[peer]["_current"] = state
            if self.on_file_chunk:
                self.on_file_chunk(fname, 0, size)

        elif t == "file_end":
            meta  = self._decrypt_dict(frame, peer)
            fname = os.path.basename(str(meta.get("filename", "file"))) or "file"
            state = self._file_buffers.get(peer, {}).pop(fname, None)
            current = self._file_buffers.get(peer, {}).get("_current")
            if current is state:
                self._file_buffers.get(peer, {}).pop("_current", None)
            if not state:
                return
            self._close_file_state(state, delete=False)
            expected = str(meta.get("sha256", state.get("sha256", "")))
            ok = (
                state["received"] == state["size"]
                and state["sha"].hexdigest() == expected == state["sha256"]
            )
            if self.on_file_complete:
                self.on_file_complete(fname, state["path"], ok)
            elif not ok:
                self._delete_tmp_file(state["path"])

        elif t == "call_start":
            if self.on_call_incoming:
                self.on_call_incoming(peer)
        elif t == "call_accept":
            if self.on_call_accepted:
                self.on_call_accepted()
        elif t == "call_reject":
            if self.on_call_rejected:
                self.on_call_rejected()
        elif t == "hangup":
            # Remote hung up — tear down our side immediately (stop sending +
            # stop playing them), then notify the UI.
            self.end_call_from_peer(peer)
            if self.on_hangup:
                self.on_hangup(peer)

    # ------------------------------------------------------------------
    # Hub relay primitive
    # ------------------------------------------------------------------

    async def _relay_frame_to_others(self, payload, source: str) -> None:
        """Hub relay: forward a chat/file frame (str) or binary chunk (bytes) to
        every member except the source. Ciphertext is forwarded untouched."""
        for dest, ch in list(self.data_channels.items()):
            if dest in (source, self.my_username):
                continue  # never echo to the source or loop back to self
            if getattr(ch, "readyState", None) == "open":
                ch.send(payload)

    # ------------------------------------------------------------------
    # Encrypt / decrypt helpers
    # ------------------------------------------------------------------

    def _decrypt_dict(self, frame: dict, peer: str) -> dict:
        if self.settings.security_mode == "e2ee" and "token" in frame:
            key = self.group_key if self.room_id else self.session_keys.get(peer)
            if key:
                try:
                    return paseto_decrypt(frame["token"], key)
                except Exception:
                    return {}
        return frame

    def _decrypt_with_session(self, frame: dict, peer: str) -> dict:
        """Decrypt a per-peer frame with the 1-to-1 session key (NOT the group
        key). Used for point-to-point control like history sync, which is sent
        with _encrypt_frame_for (per-peer) even inside a room."""
        if self.settings.security_mode == "e2ee" and "token" in frame:
            key = self.session_keys.get(peer)
            if key:
                try:
                    return paseto_decrypt(frame["token"], key)
                except Exception:
                    return {}
        return frame

    def _encrypt_frame_for(self, payload: dict, peer: str) -> dict:
        frame = {"__type": payload["__type"]}
        if self.settings.security_mode == "e2ee":
            key = self.session_keys.get(peer)
            if key:
                frame["token"] = paseto_encrypt(payload, key)
                return frame
        frame.update(payload)
        return frame

    def _encrypt_group_frame(self, payload: dict) -> dict:
        frame = {"__type": payload["__type"]}
        if self.settings.security_mode == "e2ee" and self.group_key:
            frame["token"] = paseto_encrypt(payload, self.group_key)
            return frame
        frame.update(payload)
        return frame

    # ------------------------------------------------------------------
    # Group key
    # ------------------------------------------------------------------

    async def _send_group_key_to(self, peer: str) -> None:
        import base64 as b64mod
        if not self.group_key or peer not in self.session_keys:
            return
        token = paseto_encrypt(
            {"group_key": b64mod.b64encode(self.group_key).decode()},
            self.session_keys[peer],
        )
        self.data_channels[peer].send(json.dumps({"__type": "group_key", "token": token}))

    async def _handle_group_key(self, frame: dict, peer: str) -> None:
        import base64 as b64mod
        if self.group_key:
            return
        # SEC-05: only accept the group key from the room creator once we know
        # who that is. A non-creator member must not be able to race a key of
        # their choosing onto the room. When the creator is not yet known
        # (bootstrap/failover), fall back to first-trusted-peer behaviour.
        if self._room_creator_name and peer != self._room_creator_name:
            print(f"[crypto] Ignoring group_key from non-creator {peer}.", flush=True)
            return
        session_key = self.session_keys.get(peer)
        if not session_key:
            return
        try:
            payload = paseto_decrypt(frame["token"], session_key)
            self.group_key = b64mod.b64decode(payload["group_key"])
        except Exception:
            return
        await self._flush_group_buffer()

    async def _flush_group_buffer(self) -> None:
        # Drain queued outgoing group messages once a group key exists and at
        # least one channel is open to carry them.
        if not self.group_key:
            return
        open_channels = [ch for ch in self.data_channels.values() if ch.readyState == "open"]
        if not open_channels:
            return
        while self._pre_group_key_buffer:
            text = self._pre_group_key_buffer.popleft()
            await self._send_group_chat(text)

    async def _send_group_chat(self, text: str) -> None:
        frame = self._encrypt_group_frame({"__type": "chat", "text": text, "from": self.my_username})
        for ch in self.data_channels.values():
            if ch.readyState == "open":
                ch.send(json.dumps(frame))

    # ------------------------------------------------------------------
    # Send helpers (public)
    # ------------------------------------------------------------------

    async def send_chat(self, text: str) -> None:
        if self.room_id:
            if self.settings.security_mode == "e2ee" and not self.group_key:
                self._pre_group_key_buffer.append(text)
                return
            await self._send_group_chat(text)
        else:
            frame = self._encrypt_frame_for(
                {"__type": "chat", "text": text}, self.target_peer
            )
            self.data_channels[self.target_peer].send(json.dumps(frame))

    # ------------------------------------------------------------------
    # Peer-assisted history sync (feature E) — encrypted over the session channel
    # ------------------------------------------------------------------

    HISTORY_SYNC_MAX = 200

    async def send_history_request(self, peer: str, room_id: str, since: str) -> None:
        ch = self.data_channels.get(peer)
        if not (ch and ch.readyState == "open"):
            return
        frame = self._encrypt_frame_for(
            {"__type": "history_request", "room_id": room_id, "since": since or ""}, peer)
        try:
            ch.send(json.dumps(frame))
        except Exception:
            pass

    async def send_history_response(self, peer: str, room_id: str, messages: list) -> None:
        ch = self.data_channels.get(peer)
        if not (ch and ch.readyState == "open"):
            return
        frame = self._encrypt_frame_for(
            {"__type": "history_response", "room_id": room_id,
             "messages": list(messages)[: self.HISTORY_SYNC_MAX]}, peer)
        try:
            ch.send(json.dumps(frame))
        except Exception:
            pass

    async def send_file(self, path: str, target: Optional[str] = None) -> None:
        # Stream from disk in chunks (never load the whole file into RAM) and
        # respect the channel's send-buffer so a big file can't balloon memory
        # or stall the event loop on a weak machine.
        CHUNK   = 64 * 1024
        BUF_CAP = 1 * 1024 * 1024   # pause sending above ~1 MB buffered
        peer    = target or self.target_peer
        ch      = self.data_channels[peer]
        fname   = os.path.basename(path)
        size    = os.path.getsize(path)
        if self.room_id and self.settings.security_mode == "e2ee" and not self.group_key:
            raise RuntimeError("Cannot send a room file before the group key is ready")

        # First pass: hash on disk so the receiver gets the checksum up front.
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(CHUNK), b""):
                sha.update(block)
        sha_hex = sha.hexdigest()

        payload = {"__type": "file_meta", "filename": fname, "size": size, "sha256": sha_hex}
        meta = self._encrypt_group_frame(payload) if self.room_id else self._encrypt_frame_for(payload, peer)
        ch.send(json.dumps(meta))

        # Second pass: send the bytes with backpressure.
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(CHUNK), b""):
                while getattr(ch, "bufferedAmount", 0) > BUF_CAP:
                    await asyncio.sleep(0.05)
                ch.send(block)
                await asyncio.sleep(0)

        payload = {"__type": "file_end", "filename": fname, "sha256": sha_hex}
        end = self._encrypt_group_frame(payload) if self.room_id else self._encrypt_frame_for(payload, peer)
        ch.send(json.dumps(end))

    # ------------------------------------------------------------------
    # Renegotiation
    # ------------------------------------------------------------------

    async def _do_negotiation(self, peer: str) -> None:
        if peer not in self.pcs:
            print(f"[rtc] {self.my_username}: skip negotiation for {peer} (no-pc)", flush=True)
            return
        print(f"[rtc] {self.my_username}: creating OFFER for {peer} (gathering ICE…)", flush=True)
        offer = await self.pcs[peer].createOffer()
        await self.pcs[peer].setLocalDescription(offer)

        # Wait for ICE gathering to complete before sending the SDP (non-trickle ICE)
        pc = self.pcs[peer]
        if isinstance(pc.iceGatheringState, str) and pc.iceGatheringState != "complete":
            try:
                for _ in range(100):
                    if pc.iceGatheringState == "complete":
                        break
                    await asyncio.sleep(0.05)
            except Exception as ex:
                print(f"[rtc] Error waiting for ICE gathering: {ex}", flush=True)

        await self._send_ws({
            "target": peer,
            "type":   "offer",
            "data":   {"sdp": self.pcs[peer].localDescription.sdp, "type": "offer"},
        })
        print(f"[rtc] {self.my_username}: SENT offer to {peer}", flush=True)

    async def request_negotiation(self, peer: str) -> None:
        if self._is_negotiating.get(peer):
            self._neg_dirty[peer] = True
            return
        self._is_negotiating[peer] = True
        try:
            await self._do_negotiation(peer)
        finally:
            self._is_negotiating[peer] = False
            if self._neg_dirty.pop(peer, False):
                await self.request_negotiation(peer)

    # ------------------------------------------------------------------
    # Public API — signaling events
    # ------------------------------------------------------------------

    async def create_offer(self, target: str, ws_send: Callable) -> None:
        self.target_peer = target
        self._send_ws    = ws_send
        self._init_pc(target)
        dc = self.pcs[target].createDataChannel("chat", ordered=True)
        self.data_channels[target] = dc
        self._bind_channel(dc, target)
        await self.request_negotiation(target)

    async def handle_offer(self, sender: str, data: dict, ws_send: Callable) -> None:
        print(f"[rtc] {self.my_username}: RECEIVED offer from {sender}", flush=True)
        self.target_peer = sender
        self._send_ws    = ws_send
        if sender in self.pcs:
            if self.pcs[sender].connectionState in ("closed", "failed"):
                await self.remove_peer(sender)

        if sender not in self.pcs:
            self._init_pc(sender)
        pc = self.pcs[sender]

        # Perfect-negotiation glare handling. add_peer makes the alphabetically
        # LOWER username the designated offerer; the other side is "polite". If an
        # offer arrives while our pc isn't "stable", both sides offered at once (a
        # collision): the offerer keeps its own offer and ignores theirs; the
        # polite peer discards its half-built offer and accepts theirs. Without
        # this, setRemoteDescription(offer) raises InvalidStateError and the
        # connection is stuck at "connecting" forever (no answer, ICE never runs).
        if pc.signalingState != "stable":
            polite = self.my_username > sender
            print(f"[rtc] {self.my_username}: offer GLARE with {sender} "
                  f"(state={pc.signalingState}, polite={polite})",
                  flush=True)
            if not polite:
                # Impolite peer keeps its own offer; ignore their offer.
                print(f"[rtc] {self.my_username}: ignoring colliding offer from {sender} (offerer)", flush=True)
                return
            # Polite peer: recreate the peer connection to resolve glare (since aiortc lacks rollback).
            # This resets the signaling state cleanly to stable, allowing us to accept the incoming offer.
            print(f"[rtc] {self.my_username}: polite peer recreating PC to resolve glare", flush=True)
            await self.remove_peer(sender)
            self._init_pc(sender)
            pc = self.pcs[sender]

        try:
            await pc.setRemoteDescription(
                RTCSessionDescription(sdp=data["sdp"], type="offer")
            )
            answer = await pc.createAnswer()
            await pc.setLocalDescription(answer)

            # Wait for ICE gathering to complete before sending the SDP (non-trickle ICE)
            if isinstance(pc.iceGatheringState, str) and pc.iceGatheringState != "complete":
                try:
                    for _ in range(100):
                        if pc.iceGatheringState == "complete":
                            break
                        await asyncio.sleep(0.05)
                except Exception as ex:
                    print(f"[rtc] Error waiting for ICE gathering: {ex}", flush=True)

            await ws_send({
                "target": sender,
                "type":   "answer",
                "data":   {"sdp": pc.localDescription.sdp, "type": "answer"},
            })
            print(f"[rtc] {self.my_username}: SENT answer to {sender}", flush=True)
        except Exception as ex:
            self.last_error = f"offer from {sender}: {type(ex).__name__}: {ex}"
            print(f"[rtc] {self.my_username}: handle_offer FAILED for {sender}: {type(ex).__name__}: {ex}", flush=True)

    async def handle_answer(self, data: dict, sender: str = "") -> None:
        peer = sender or self.target_peer
        print(f"[rtc] {self.my_username}: RECEIVED answer from {peer}", flush=True)
        if peer in self.pcs:
            try:
                await self.pcs[peer].setRemoteDescription(
                    RTCSessionDescription(sdp=data["sdp"], type="answer")
                )
                print(f"[rtc] {self.my_username}: applied answer from {peer}", flush=True)
            except Exception as ex:
                self.last_error = f"answer from {peer}: {type(ex).__name__}"
                print(f"[rtc] {self.my_username}: handle_answer FAILED for {peer}: {type(ex).__name__}: {ex}", flush=True)

    async def handle_ice(self, data: dict, sender: str = "") -> None:
        peer = sender or self.target_peer
        if peer in self.pcs:
            candidate = RTCIceCandidate(
                sdpMid=data.get("sdpMid"),
                sdpMLineIndex=data.get("sdpMLineIndex"),
                candidate=data.get("candidate", ""),
            )
            await self.pcs[peer].addIceCandidate(candidate)

    # ------------------------------------------------------------------
    # Mesh peer management
    # ------------------------------------------------------------------

    async def add_peer(self, username: str, ws_send: Callable) -> None:
        self._send_ws = ws_send
        # If we already have a PC to this peer, only rebuild it when it's dead.
        # An in-progress / live connection must NOT be torn down — otherwise two
        # peers initiating at once (both selecting each other, or re-entry) would
        # keep resetting each other and never connect.
        existing = self.pcs.get(username)
        if existing is not None:
            if existing.connectionState in ("failed", "closed", "disconnected"):
                await self.remove_peer(username)
            else:
                return
        self._init_pc(username)
        # Tie-break: alphabetically lower username creates the data channel and
        # drives the initial offer. aiortc won't auto-negotiate, so do it now.
        if self.my_username < username:
            dc = self.pcs[username].createDataChannel("chat", ordered=True)
            self.data_channels[username] = dc
            self._bind_channel(dc, username)
            await self.request_negotiation(username)
        # else: wait for incoming offer from the other peer

    async def _relay_track_to_others(self, source_peer: str, track) -> None:
        """Hub SFU fan-out: re-publish source_peer's track to every other member,
        labeling each forwarded track with its true origin over the data channel."""
        for dest, pc in list(self.pcs.items()):
            if dest == source_peer:
                continue
            sub = self._relay.subscribe(track)
            pc.addTrack(sub)
            # Broadcast sub.id (what the receiver sees), NOT the source track.id —
            # relay.subscribe() assigns a new id (confirmed by spike).
            self._forwarded.setdefault(source_peer, []).append((dest, sub, sub.id))
            ch = self.data_channels.get(dest)
            if ch and getattr(ch, "readyState", None) == "open":
                ch.send(json.dumps({"__type": "track_origin",
                                    "track_id": sub.id, "origin": source_peer,
                                    "kind": sub.kind}))
            await self.request_negotiation(dest)

    async def remove_peer(self, username: str) -> None:
        pc = self.pcs.pop(username, None)
        if pc:
            try:
                await pc.close()
            except Exception:
                pass
        self.data_channels.pop(username, None)
        self.session_keys.pop(username, None)
        self._hello_sent.pop(username, None)
        self._peer_hello_verified.pop(username, None)
        self._eph_priv.pop(username, None)
        self._pre_hello_buffers.pop(username, None)
        self._pre_hello_bytes.pop(username, None)
        self._is_negotiating.pop(username, None)
        self._neg_dirty.pop(username, None)
        file_states = self._file_buffers.pop(username, {})
        for state in list(file_states.values()):
            if isinstance(state, dict):
                self._close_file_state(state, delete=True)
        self._ice_states.pop(username, None)
        self._voice_peers.discard(username)
        self._screen_peers.discard(username)
        self._voice_senders.pop(username, None)
        self._screen_senders.pop(username, None)
        # Drop SFU forwarding bookkeeping for/to this peer: entries where it was
        # the source, and entries in other sources' lists where it was the dest.
        self._forwarded.pop(username, None)
        for source in list(self._forwarded.keys()):
            self._forwarded[source] = [
                entry for entry in self._forwarded[source]
                if entry[0] != username
            ]
        # Forget per-peer auth + election bookkeeping so a gone peer is neither
        # re-elected as hub nor left half-authenticated.
        self._cap_tier.pop(username, None)
        self._cap_epoch.pop(username, None)
        self._psk_authed.pop(username, None)
        self._psk_my_nonce.pop(username, None)
        self._peer_is_member.pop(username, None)
        self._pending_call_start.discard(username)
        # Release shared capture devices / mixer if no peers need them anymore
        self._teardown_media_if_idle()

        # Creator-leaves key handoff: am I now the alphabetically lowest peer?
        if self.room_id and not self.is_room_creator:
            remaining = sorted(list(self.pcs.keys()) + [self.my_username])
            if remaining and remaining[0] == self.my_username:
                self.is_room_creator = True
                if self.group_key is None:
                    # Orphaned: the original creator left before we ever received
                    # the group key. Establish a fresh key and distribute it so
                    # the survivors can keep talking (and any stuck buffer flushes).
                    self.group_key = os.urandom(32)
                    for p in list(self.pcs.keys()):
                        if p in self.session_keys:
                            await self._send_group_key_to(p)
                await self._flush_group_buffer()

    async def reconcile_room_connections(self, members: list, ws_send) -> None:
        """Star topology: non-hub connects only to the hub; the hub waits for offers."""
        self._send_ws = ws_send
        hub = self.current_hub()
        if hub == self.my_username:
            return  # hub is a pure responder; it answers incoming offers
        # Non-hub: ensure exactly one live PC -> hub, drop any others.
        for peer in list(self.pcs.keys()):
            if peer != hub:
                await self.remove_peer(peer)
        if hub and hub != self.my_username and hub not in self.pcs:
            await self.create_offer(hub, ws_send)

    # ------------------------------------------------------------------
    # Voice / screen
    # ------------------------------------------------------------------

    def _get_mic_source(self) -> "MicrophoneTrack":
        # One real microphone capture, shared across every peer via the relay.
        # Mic starts active (audio flows immediately); the UI exposes a mute toggle.
        if self._mic_source is None:
            self._mic_source = MicrophoneTrack(push_to_talk=False)
        return self._mic_source

    def _get_screen_source(self) -> "ScreenShareTrack":
        # One real screen grab, shared across every peer via the relay. Caps come
        # from the active performance profile (settings), so a new share picks up
        # whatever profile is currently selected.
        if self._screen_source is None:
            self._screen_source = ScreenShareTrack(
                max_width=getattr(self.settings, "screen_max_w", None),
                max_height=getattr(self.settings, "screen_max_h", None),
                target_fps=getattr(self.settings, "screen_fps", None),
            )
        return self._screen_source

    async def start_voice_call(self, peer: Optional[str] = None, ring: bool = True) -> None:
        """Add our mic to the call with `peer`. `ring=True` means we are the one
        STARTING the call, so notify them (call_start → their phone rings).
        `ring=False` is used when ANSWERING — we add our mic but must NOT ring the
        caller back (that produced a duplicate incoming-call prompt)."""
        p = peer or self.target_peer
        if p not in self.pcs or p in self._voice_peers:
            return
        src = self._get_mic_source()
        self._voice_senders[p] = self.pcs[p].addTrack(self._relay.subscribe(src))
        self._voice_peers.add(p)
        if ring:
            ch = self.data_channels.get(p)
            if ch and ch.readyState == "open":
                try:
                    ch.send(json.dumps({"__type": "call_start"}))
                    print(f"[rtc] {self.my_username}: sent call_start to {p}", flush=True)
                except Exception as ex:
                    print(f"[rtc] {self.my_username}: call_start to {p} failed: {ex}", flush=True)
            else:
                # Channel not open yet — defer the ring so the callee isn't missed.
                self._pending_call_start.add(p)
                print(f"[rtc] {self.my_username}: call_start to {p} deferred (channel not open)", flush=True)
        # aiortc won't auto-negotiate the added track — re-offer explicitly.
        # If we are the callee (ring=False), we only initiate renegotiation if we've already
        # applied the caller's offer (meaning we have a remote audio track). Otherwise, we wait
        # for their offer to arrive, and our answer will automatically negotiate both tracks.
        has_remote_audio = any(r.track and r.track.kind == "audio" for r in self.pcs[p].getReceivers())
        if ring or has_remote_audio:
            await self.request_negotiation(p)

    async def start_screen_share(self, peer: Optional[str] = None) -> None:
        # Screen share is VIDEO ONLY and independent of voice. To talk while
        # sharing, also start a voice call — the two streams are decoupled so one
        # never cuts the other out (and sharing won't silently hot-mic you).
        p = peer or self.target_peer
        if p not in self.pcs or p in self._screen_peers:
            return
        screen = self._get_screen_source()
        self._screen_senders[p] = self.pcs[p].addTrack(self._relay.subscribe(screen))
        self._screen_peers.add(p)
        await self.request_negotiation(p)

    async def stop_screen_share(self, peer: Optional[str] = None) -> None:
        """Stop sharing our screen with `peer` (or everyone) WITHOUT ending the
        call: remove just the screen track and renegotiate; voice keeps flowing."""
        targets = [peer] if peer else list(self._screen_peers)
        changed = []
        for p in targets:
            sender = self._screen_senders.pop(p, None)
            self._screen_peers.discard(p)
            pc = self.pcs.get(p)
            if sender is not None and pc is not None:
                try:
                    if hasattr(pc, "removeTrack"):
                        pc.removeTrack(sender)
                    else:
                        for transceiver in pc.getTransceivers():
                            if transceiver.sender == sender:
                                await transceiver.stop()
                                break
                    changed.append(p)
                except Exception as ex:
                    print(f"[rtc] {self.my_username}: removeTrack(screen) for {p} failed: {ex}", flush=True)
        self._teardown_media_if_idle()
        for p in changed:
            await self.request_negotiation(p)

    def accept_call(self, peer: Optional[str] = None) -> None:
        p  = peer or self.target_peer
        ch = self.data_channels.get(p)
        if ch and ch.readyState == "open":
            try:
                ch.send(json.dumps({"__type": "call_accept"}))
            except Exception as ex:
                print(f"[rtc] {self.my_username}: call_accept to {p} failed: {ex}", flush=True)
        # We are ANSWERING: add our mic but don't ring the caller back.
        asyncio.ensure_future(self.start_voice_call(p, ring=False))

    def reject_call(self, peer: Optional[str] = None) -> None:
        p  = peer or self.target_peer
        ch = self.data_channels.get(p)
        if ch and ch.readyState == "open":
            try:
                ch.send(json.dumps({"__type": "call_reject"}))
            except Exception as ex:
                print(f"[rtc] {self.my_username}: call_reject to {p} failed: {ex}", flush=True)

    def hangup(self, peer: Optional[str] = None) -> None:
        # Local hangup: notify the peer(s) AND tear down our own call media.
        targets = [peer] if peer else list(self.data_channels.keys())
        for p in targets:
            ch = self.data_channels.get(p)
            if ch and ch.readyState == "open":
                ch.send(json.dumps({"__type": "hangup"}))
            self._end_call_local(p)

    def end_call_from_peer(self, peer: str) -> None:
        # The remote side hung up — tear down our side WITHOUT echoing a hangup.
        self._end_call_local(peer)

    def _end_call_local(self, peer: str) -> None:
        # Stop sending to this peer and stop playing their audio.
        self._voice_peers.discard(peer)
        self._screen_peers.discard(peer)
        self._voice_senders.pop(peer, None)
        self._screen_senders.pop(peer, None)
        self._incoming_audio_active.discard(peer)
        self._teardown_media_if_idle()

    def _teardown_media_if_idle(self) -> None:
        # Release capture devices + the audio output once nothing needs them.
        if not self._voice_peers and self._mic_source is not None:
            try:
                self._mic_source.stop()
            except Exception:
                pass
            self._mic_source = None
        if not self._screen_peers and self._screen_source is not None:
            try:
                self._screen_source.stop()
            except Exception:
                pass
            self._screen_source = None
        # Stop playback when we're no longer playing anyone's audio.
        if not self._incoming_audio_active and self._output_stream is not None:
            try:
                self._output_stream.stop()
                self._output_stream.close()
            except Exception:
                pass
            self._output_stream = None

    def set_mic_muted(self, muted: bool) -> None:
        # Mute/unmute the single shared microphone source.
        if self._mic_source is not None:
            self._mic_source.set_active(not muted)

    # ------------------------------------------------------------------
    # Audio playback (callback-driven; runs off the asyncio loop)
    # ------------------------------------------------------------------

    def _play_callback(self, outdata, frames, time_info, status):
        # Runs in sounddevice's audio thread. Pull up to `frames` samples from
        # each peer's chunk queue and mix them; missing audio plays as silence
        # (no underrun stall). Only the consumed head is copied, never the whole
        # backlog.
        mix = np.zeros(frames, dtype=np.int32)
        with self._play_lock:
            for peer in list(self._play_chunks.keys()):
                dq    = self._play_chunks[peer]
                need  = frames
                taken = 0
                while need > 0 and dq:
                    chunk = dq[0]
                    if len(chunk) <= need:
                        mix[taken:taken + len(chunk)] += chunk.astype(np.int32)
                        taken += len(chunk)
                        need  -= len(chunk)
                        dq.popleft()
                    else:
                        mix[taken:taken + need] += chunk[:need].astype(np.int32)
                        dq[0]  = chunk[need:]
                        taken += need
                        need   = 0
        np.clip(mix, -32768, 32767, out=mix)
        outdata[:, 0] = mix.astype(np.int16)

    def _ensure_output_stream(self) -> None:
        if self._output_stream is None:
            self._output_stream = sd.OutputStream(
                samplerate=48000, channels=1, dtype="int16",
                blocksize=960, callback=self._play_callback,
            )
            self._output_stream.start()

    async def _handle_incoming_audio(self, track, peer: str) -> None:
        MAX_BUFFERED = 48000   # ~1 s @ 48 kHz; drop oldest beyond this
        key = await self._resolve_origin(track.id, peer)
        self._incoming_audio_active.add(key)
        with self._play_lock:
            self._play_chunks[key] = deque()
        self._ensure_output_stream()

        # Initialize the resampler to output packed s16, mono layout, 48000Hz rate.
        # This handles dynamic format, sample rate, or channel count changes (e.g. if the
        # Opus decoder outputs stereo, or negotiates a lower rate) and guarantees we play
        # back normal-pitched mono audio without sample layout doubling/pitch shifts.
        try:
            from av.audio.resampler import AudioResampler
        except ImportError:
            from av import AudioResampler
        resampler = AudioResampler(format="s16", layout="mono", rate=48000)

        while key in self._incoming_audio_active:
            try:
                frame = await track.recv()
                resampled_frames = resampler.resample(frame)
                for f in resampled_frames:
                    # Flatten the resampled mono s16 frame to a 1-D int16 samples vector
                    samples = f.to_ndarray().reshape(-1).astype(np.int16)
                    with self._play_lock:
                        dq = self._play_chunks.get(key)
                        if dq is None:
                            break
                        dq.append(samples)
                        # Bound the backlog so we never drift far behind: drop oldest
                        # whole chunks until under the cap.
                        total = sum(len(c) for c in dq)
                        while total > MAX_BUFFERED and len(dq) > 1:
                            total -= len(dq.popleft())
            except Exception:
                break
        self._incoming_audio_active.discard(key)
        with self._play_lock:
            self._play_chunks.pop(key, None)
        self._teardown_media_if_idle()

    # ------------------------------------------------------------------
    # Video rendering
    # ------------------------------------------------------------------

    async def _render_video(self, track, peer: str) -> None:
        print(f"[screen] {self.my_username}: receiving video track from {peer}", flush=True)
        origin = await self._resolve_origin(track.id, peer)
        q: asyncio.Queue = asyncio.Queue(maxsize=2)
        self._got_frame = False

        async def fetch():
            while True:
                try:
                    frame = await track.recv()
                    img   = frame.to_ndarray(format="bgr24")
                    if not self._got_frame:
                        print(f"[screen] {self.my_username}: first frame from {peer} (origin={origin}) {img.shape[1]}x{img.shape[0]}", flush=True)
                        self._got_frame = True
                    if q.full():
                        try:
                            q.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                    await q.put(img)
                except Exception:
                    break

        asyncio.ensure_future(fetch())
        while True:
            try:
                img = await asyncio.wait_for(q.get(), timeout=5.0)
                if self.on_video_frame:
                    self.on_video_frame(origin, img)
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
