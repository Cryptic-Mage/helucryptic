import asyncio
import base64 as _b64
import hashlib
import json
import os
import threading
from collections import deque
from typing import Callable, Optional

import numpy as np
import mss
import sounddevice as sd
from PIL import Image
from av import AudioFrame, VideoFrame

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
    derive_session_key,
    paseto_decrypt,
    paseto_encrypt,
    paseto_sign,
    paseto_verify,
)
from contacts import get_contact, upsert_contact


_STUN_SERVERS = [
    RTCIceServer(urls=["stun:stun.l.google.com:19302"]),
    RTCIceServer(urls=["stun:stun1.l.google.com:19302"]),
]


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
        # setLocalDescription blocks until (non-trickle) ICE gathering completes.
        await asyncio.wait_for(pc.setLocalDescription(await pc.createOffer()), timeout=8)
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
        self._pre_hello_buffers:   dict[str, deque]             = {}
        self._is_negotiating:      dict[str, bool]              = {}
        self._file_buffers:        dict[str, dict]              = {}

        # Shared media sources fanned out to every peer via a relay so the mic
        # is only captured once and the screen is only grabbed once, regardless
        # of how many peers are in the call.
        self._relay         = MediaRelay()
        self._mic_source    = None   # single MicrophoneTrack capturing the mic
        self._screen_source = None   # single ScreenShareTrack grabbing the screen
        self._voice_peers:  set[str] = set()   # peers we've added a mic track to
        self._screen_peers: set[str] = set()   # peers we've added a screen track to
        self._incoming_audio_active: set[str] = set()  # peers whose audio we play

        # Group call state
        self.group_key:             Optional[bytes] = None
        self.is_room_creator:       bool            = False
        self.room_id:               Optional[str]   = None
        self._pre_group_key_buffer: deque           = deque()
        self._send_ws:              Optional[Callable] = None

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
        peers = [
            {"peer": peer, "connection": pc.connectionState,
             "ice": self._ice_states.get(peer, "new")}
            for peer, pc in self.pcs.items()
        ]
        return {
            "signaling": self.signaling_status,
            "turn_configured": bool(getattr(self.settings, "turn_url", "")),
            "last_error": self.last_error,
            "peers": peers,
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

    # ------------------------------------------------------------------
    # Per-peer PC init
    # ------------------------------------------------------------------

    def _init_pc(self, peer: str) -> None:
        pc = RTCPeerConnection(configuration=self._ice_config())
        self.pcs[peer]                  = pc
        self._hello_sent[peer]          = False
        self._peer_hello_verified[peer] = False
        self._pre_hello_buffers[peer]   = deque()
        self._is_negotiating[peer]      = False

        # NOTE: aiortc gathers ICE non-trickle — all candidates are embedded in
        # the SDP offer/answer, and it never emits a browser-style "icecandidate"
        # event. So there is deliberately no outbound trickle handler here.
        # handle_ice() still accepts inbound candidates defensively (e.g. from a
        # future browser peer that does trickle).

        @pc.on("connectionstatechange")
        def on_state():
            print(f"[rtc] {self.my_username}: pc[{peer}] connection -> {pc.connectionState}", flush=True)
            if self.on_state_change:
                self.on_state_change(peer, pc.connectionState)

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

    # ------------------------------------------------------------------
    # DataChannel binding
    # ------------------------------------------------------------------

    def _bind_channel(self, channel, peer: str) -> None:
        async def _on_open():
            if self.settings.security_mode == "e2ee":
                await self._send_hello(peer)
            else:
                self._hello_sent[peer]          = True
                self._peer_hello_verified[peer] = True
                await self._flush_pre_hello_buffer(peer)

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
    # Hello handshake
    # ------------------------------------------------------------------

    async def _send_hello(self, peer: str) -> None:
        from datetime import datetime, timezone
        payload = {
            "username":    self.my_username,
            "x25519_pub":  self.keys["x25519_public"],
            "ed25519_pub": self.keys["ed25519_public"],
            "iat":         datetime.now(timezone.utc).isoformat(),
        }
        token = paseto_sign(payload, self.keys["ed25519_private"], self.keys["ed25519_public"])
        self.data_channels[peer].send(json.dumps({"__type": "hello", "token": token}))
        self._hello_sent[peer] = True

    async def _handle_hello(self, frame: dict, peer: str) -> None:
        if self._peer_hello_verified.get(peer):
            return
        if self.settings.security_mode == "e2ee":
            prior = get_contact(peer)
            try:
                # Unverified peek only to recover the claimed signing key, then
                # verify against it. Use the VERIFIED payload (not the peek) for
                # everything afterwards.
                parts        = frame["token"].split(".")
                raw          = _b64.urlsafe_b64decode(parts[2] + "==")
                claimed_pub  = json.loads(raw[:-64])["ed25519_pub"]
            except Exception:
                # For a previously-known contact, fall back to the stored
                # signing key. This also lets us detect a changed X25519 key
                # when the Ed25519 identity key is still the same.
                if not (prior and prior.ed25519_pub):
                    return
                claimed_pub = prior.ed25519_pub
            try:
                payload = paseto_verify(frame["token"], claimed_pub)
            except Exception:
                return
            # Bind the claimed identity to the signaling peer name. A peer
            # connected to signaling as `peer` must not be able to assert a
            # different username (which would poison another contact's entry).
            if payload.get("username") != peer:
                return
            # Detect a changed key on a previously-verified contact so the UI can
            # warn (possible MITM). upsert_contact also drops the verified flag.
            key_changed = bool(
                prior and prior.verified and prior.x25519_pub
                and prior.x25519_pub != payload["x25519_pub"]
            )
            self.session_keys[peer] = derive_session_key(
                self.keys["x25519_private"], payload["x25519_pub"]
            )
            upsert_contact(peer,
                           x25519_pub=payload["x25519_pub"],
                           ed25519_pub=payload["ed25519_pub"])
            if key_changed and self.on_key_change:
                self.on_key_change(peer)
            # Creator sends group key to this peer
            if self.is_room_creator and self.group_key:
                await self._send_group_key_to(peer)

        self._peer_hello_verified[peer] = True
        await self._flush_pre_hello_buffer(peer)

    async def _flush_pre_hello_buffer(self, peer: str) -> None:
        buf = self._pre_hello_buffers.get(peer, deque())
        while buf:
            kind, data = buf.popleft()
            if kind == "text":
                await self._handle_text(data, peer)
            else:
                await self._handle_binary(data, peer)

    # ------------------------------------------------------------------
    # Message handling
    # ------------------------------------------------------------------

    async def _handle_text(self, raw: str, peer: str) -> None:
        try:
            frame = json.loads(raw)
        except Exception:
            return
        if frame.get("__type") == "hello":
            await self._handle_hello(frame, peer)
            return
        if not (self._hello_sent.get(peer) and self._peer_hello_verified.get(peer)):
            self._pre_hello_buffers.setdefault(peer, deque()).append(("text", raw))
            return
        await self._dispatch_frame(frame, peer)

    async def _handle_binary(self, data: bytes, peer: str) -> None:
        if not (self._hello_sent.get(peer) and self._peer_hello_verified.get(peer)):
            self._pre_hello_buffers.setdefault(peer, deque()).append(("binary", data))
            return
        fname = self._file_buffers.get(peer, {}).get("_current")
        if fname:
            self._file_buffers[peer][fname].extend(data)
            received = len(self._file_buffers[peer][fname])
            if self.on_file_chunk:
                self.on_file_chunk(fname, received, None)

    async def _dispatch_frame(self, frame: dict, peer: str) -> None:
        t = frame.get("__type")

        if t == "group_key":
            await self._handle_group_key(frame, peer)
            return

        if t == "chat":
            if self.settings.security_mode == "e2ee":
                key = self.group_key if self.room_id else self.session_keys.get(peer)
                if not key:
                    return
                try:
                    text = paseto_decrypt(frame["token"], key).get("text", "")
                except Exception:
                    text = "[decryption failed]"
            else:
                text = frame.get("text", "")
            if self.on_message:
                self.on_message(peer, text, frame.get("verified", False))

        elif t == "file_meta":
            meta  = self._decrypt_dict(frame, peer)
            fname = meta["filename"]
            self._file_buffers.setdefault(peer, {})
            self._file_buffers[peer][fname]      = bytearray()
            self._file_buffers[peer]["_current"] = fname
            if self.on_file_chunk:
                self.on_file_chunk(fname, 0, meta["size"])

        elif t == "file_end":
            meta  = self._decrypt_dict(frame, peer)
            fname = meta["filename"]
            data  = bytes(self._file_buffers.get(peer, {}).pop(fname, b""))
            self._file_buffers.get(peer, {}).pop("_current", None)
            ok = hashlib.sha256(data).hexdigest() == meta.get("sha256", "")
            if self.on_file_complete:
                self.on_file_complete(fname, data, ok)

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
    # Encrypt / decrypt helpers
    # ------------------------------------------------------------------

    def _decrypt_dict(self, frame: dict, peer: str) -> dict:
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
        frame = self._encrypt_group_frame({"__type": "chat", "text": text})
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

        # First pass: hash on disk so the receiver gets the checksum up front.
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(CHUNK), b""):
                sha.update(block)
        sha_hex = sha.hexdigest()

        meta = self._encrypt_frame_for(
            {"__type": "file_meta", "filename": fname, "size": size, "sha256": sha_hex}, peer
        )
        ch.send(json.dumps(meta))

        # Second pass: send the bytes with backpressure.
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(CHUNK), b""):
                while getattr(ch, "bufferedAmount", 0) > BUF_CAP:
                    await asyncio.sleep(0.05)
                ch.send(block)
                await asyncio.sleep(0)

        end = self._encrypt_frame_for(
            {"__type": "file_end", "filename": fname, "sha256": sha_hex}, peer
        )
        ch.send(json.dumps(end))

    # ------------------------------------------------------------------
    # Renegotiation
    # ------------------------------------------------------------------

    async def _execute_negotiation(self, peer: str) -> None:
        if self._is_negotiating.get(peer) or peer not in self.pcs:
            print(f"[rtc] {self.my_username}: skip negotiation for {peer} (busy/no-pc)", flush=True)
            return
        self._is_negotiating[peer] = True
        try:
            print(f"[rtc] {self.my_username}: creating OFFER for {peer} (gathering ICE…)", flush=True)
            offer = await self.pcs[peer].createOffer()
            await self.pcs[peer].setLocalDescription(offer)
            await self._send_ws({
                "target": peer,
                "type":   "offer",
                "data":   {"sdp": self.pcs[peer].localDescription.sdp, "type": "offer"},
            })
            print(f"[rtc] {self.my_username}: SENT offer to {peer}", flush=True)
        finally:
            self._is_negotiating[peer] = False

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
        await self._execute_negotiation(target)

    async def handle_offer(self, sender: str, data: dict, ws_send: Callable) -> None:
        print(f"[rtc] {self.my_username}: RECEIVED offer from {sender}", flush=True)
        self.target_peer = sender
        self._send_ws    = ws_send
        if sender not in self.pcs:
            self._init_pc(sender)
        try:
            await self.pcs[sender].setRemoteDescription(
                RTCSessionDescription(sdp=data["sdp"], type="offer")
            )
            answer = await self.pcs[sender].createAnswer()
            await self.pcs[sender].setLocalDescription(answer)
            await ws_send({
                "target": sender,
                "type":   "answer",
                "data":   {"sdp": self.pcs[sender].localDescription.sdp, "type": "answer"},
            })
            print(f"[rtc] {self.my_username}: SENT answer to {sender}", flush=True)
        except Exception as ex:
            self.last_error = f"offer from {sender}: {type(ex).__name__}"
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
            await self._execute_negotiation(username)
        # else: wait for incoming offer from the other peer

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
        self._pre_hello_buffers.pop(username, None)
        self._is_negotiating.pop(username, None)
        self._file_buffers.pop(username, None)
        self._ice_states.pop(username, None)
        self._voice_peers.discard(username)
        self._screen_peers.discard(username)
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

    async def start_voice_call(self, peer: Optional[str] = None) -> None:
        p = peer or self.target_peer
        if p not in self.pcs or p in self._voice_peers:
            return
        src = self._get_mic_source()
        self.pcs[p].addTrack(self._relay.subscribe(src))
        self._voice_peers.add(p)
        ch = self.data_channels.get(p)
        if ch and ch.readyState == "open":
            ch.send(json.dumps({"__type": "call_start"}))
        # aiortc won't auto-negotiate the added track — re-offer explicitly.
        await self._execute_negotiation(p)

    async def start_screen_share(self, peer: Optional[str] = None) -> None:
        p = peer or self.target_peer
        if p not in self.pcs:
            return
        added = False
        if p not in self._screen_peers:
            screen = self._get_screen_source()
            self.pcs[p].addTrack(self._relay.subscribe(screen))
            self._screen_peers.add(p)
            added = True
        # Screen share carries audio too — add the mic if not already sharing it
        if p not in self._voice_peers:
            src = self._get_mic_source()
            self.pcs[p].addTrack(self._relay.subscribe(src))
            self._voice_peers.add(p)
            added = True
        if added:
            await self._execute_negotiation(p)

    def accept_call(self, peer: Optional[str] = None) -> None:
        p  = peer or self.target_peer
        ch = self.data_channels.get(p)
        if ch:
            ch.send(json.dumps({"__type": "call_accept"}))
        asyncio.ensure_future(self.start_voice_call(p))

    def reject_call(self, peer: Optional[str] = None) -> None:
        p  = peer or self.target_peer
        ch = self.data_channels.get(p)
        if ch:
            ch.send(json.dumps({"__type": "call_reject"}))

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
        self._incoming_audio_active.add(peer)
        with self._play_lock:
            self._play_chunks[peer] = deque()
        self._ensure_output_stream()
        while peer in self._incoming_audio_active:
            try:
                frame = await track.recv()
                # Flatten decoded frame to a 1-D int16 sample vector (mono 48k).
                samples = frame.to_ndarray().reshape(-1).astype(np.int16)
                with self._play_lock:
                    dq = self._play_chunks.get(peer)
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
        self._incoming_audio_active.discard(peer)
        with self._play_lock:
            self._play_chunks.pop(peer, None)
        self._teardown_media_if_idle()

    # ------------------------------------------------------------------
    # Video rendering
    # ------------------------------------------------------------------

    async def _render_video(self, track, peer: str) -> None:
        print(f"[screen] {self.my_username}: receiving video track from {peer}", flush=True)
        q: asyncio.Queue = asyncio.Queue(maxsize=2)
        self._got_frame = False

        async def fetch():
            while True:
                try:
                    frame = await track.recv()
                    img   = frame.to_ndarray(format="bgr24")
                    if not self._got_frame:
                        print(f"[screen] {self.my_username}: first frame from {peer} {img.shape[1]}x{img.shape[0]}", flush=True)
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
                    self.on_video_frame(peer, img)
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
