import asyncio
import base64 as _b64
import concurrent.futures
import hashlib
import hmac
import json
import os
import queue as _queue
import tempfile
import threading
import time as _time
import urllib.error
import urllib.parse
import urllib.request
import uuid as _uuid
from collections import deque
from collections.abc import Callable

import mss
import numpy as np
import sounddevice as sd
from av import AudioFrame, VideoFrame
from PIL import Image

from outbox import Outbox

try:
    import cv2
except ImportError:
    cv2 = None

# Pillow's BOX resampling is area-averaging - the equivalent of cv2.INTER_AREA
_BOX = getattr(Image, "Resampling", Image).BOX
from datetime import datetime, timezone
try:
    from datetime import UTC
except ImportError:
    UTC = timezone.utc

from aiortc import (
    AudioStreamTrack,
    RTCConfiguration,
    RTCIceServer,
    RTCPeerConnection,
    RTCSessionDescription,
    VideoStreamTrack,
)
from aiortc.contrib.media import MediaRelay

import config
from contacts import get_contact, upsert_contact
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

_STUN_SERVERS = [
    # Multiple independent STUN providers (not just Google) so candidate
    # gathering still succeeds if one provider is unreachable/blocked. aiortc
    # gathers IPv6 srflx candidates automatically from these when the host has a
    # routable IPv6 address - and an IPv6 path means NO NAT at all, which is the
    # single biggest non-relay win for "strict NAT" peers.
    # Extra port diversity (80/443) survives firewalls that block 3478/19302 UDP.
    RTCIceServer(urls=["stun:stun.l.google.com:19302"]),
    RTCIceServer(urls=["stun:stun1.l.google.com:19302"]),
    RTCIceServer(urls=["stun:stun.cloudflare.com:3478"]),
    RTCIceServer(urls=["stun:stun.nextcloud.com:3478"]),
    RTCIceServer(urls=["stun:stun.metered.ca:80"]),
    RTCIceServer(urls=["stun:global.stun.twilio.com:3478"]),
]

# Free fallback TURN over TCP/TLS on 443 - traverses strict enterprise NATs that
# only allow 80/443. Used only when NAT discovery says relay-required or no user
# TURN is configured. Public Metered openrelay credentials are the default so
# strict-NAT users connect out-of-box; override via
# HELUCRYPTIC_TURN_FALLBACK_USERNAME / _CREDENTIAL env vars or configure your own
# HELUCRYPTIC_TURN_URL. When fallback creds are empty, the relay will 401 - see
# warning logged at first use.
_FALLBACK_TURN_SERVERS = [
    RTCIceServer(
        urls=["turn:global.relay.metered.ca:80?transport=tcp",
              "turns:global.relay.metered.ca:443?transport=tcp"],
        username=os.getenv("HELUCRYPTIC_TURN_FALLBACK_USERNAME", "openrelayproject"),
        credential=os.getenv("HELUCRYPTIC_TURN_FALLBACK_CREDENTIAL", "openrelayproject"),
    ),
    RTCIceServer(
        urls=["turn:openrelay.metered.ca:80"],
        username=os.getenv("HELUCRYPTIC_TURN_FALLBACK_USERNAME", "openrelayproject"),
        credential=os.getenv("HELUCRYPTIC_TURN_FALLBACK_CREDENTIAL", "openrelayproject"),
    ),
]

# aiortc/aioice honour exactly ONE stun_server and ONE turn_server per
# RTCConfiguration (see aiortc.rtcicetransport.connection_kwargs: every URL after
# the first of each scheme is skipped). Every list above is therefore a *priority
# order*, not a set that gets tried in parallel - _select_for_aiortc below picks
# the single pair that actually reaches the ICE stack, and rotates the TURN pick
# across reconnect attempts so a UDP-blocked network still lands on TCP/TLS.


def _flatten_turn_urls(servers: list) -> list[tuple[str, str | None, str | None]]:
    """(url, username, credential) triples for every TURN URL, in priority order."""
    out: list[tuple[str, str | None, str | None]] = []
    for server in servers:
        urls = server.urls if isinstance(server.urls, list) else [server.urls]
        for url in urls:
            if url.startswith(("turn:", "turns:")):
                out.append((url, server.username, server.credential))
    return out


def _format_sdp_candidates(sdp: str) -> str:
    """Extract candidate lines from SDP for diagnostic logging."""
    items = []
    for line in (sdp or "").splitlines():
        if line.startswith("a=candidate:"):
            parts = line[12:].strip().split()
            if len(parts) >= 8:
                proto = parts[2].lower()
                ip = parts[4]
                port = parts[5]
                typ = parts[7]
                items.append(f"{typ}:{proto}:{ip}:{port}")
            else:
                items.append(line[12:].strip())
    return "[" + ", ".join(items) + "]" if items else "[]"


def _select_for_aiortc(servers: list, attempt: int = 0) -> list:
    """Reduce a priority list to the one STUN + one TURN aiortc will actually use.

    ``attempt`` rotates the TURN choice, so a peer that fails on UDP retries on
    TCP and then TLS/443 instead of hammering the same blocked transport.
    """
    stun = next(
        (s for s in servers
         if any(u.startswith("stun") for u in
                (s.urls if isinstance(s.urls, list) else [s.urls]))),
        None,
    )
    turns = _flatten_turn_urls(servers)
    picked: list = []
    if stun is not None:
        urls = stun.urls if isinstance(stun.urls, list) else [stun.urls]
        first = next(u for u in urls if u.startswith("stun"))
        picked.append(RTCIceServer(urls=[first]))
    if turns:
        url, username, credential = turns[attempt % len(turns)]
        picked.append(RTCIceServer(urls=[url], username=username, credential=credential))
    return picked or list(servers)


def _http_url_for(signaling_url: str) -> str:
    """ws(s):// -> http(s):// base, trailing slash stripped."""
    url = (signaling_url or "").strip().rstrip("/")
    if url.startswith("wss://"):
        return "https://" + url[len("wss://"):]
    if url.startswith("ws://"):
        return "http://" + url[len("ws://"):]
    if url.startswith(("http://", "https://")):
        return url
    return "https://" + url


def _fetch_ice_blocking(signaling_url: str, password: str, timeout: float) -> dict:
    base = _http_url_for(signaling_url)
    query = ("?" + urllib.parse.urlencode({"password": password})) if password else ""
    req = urllib.request.Request(f"{base}/turn{query}", headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


async def fetch_ice_servers(signaling_url: str, password: str = "",
                            timeout: float = 8.0) -> tuple[list, int]:
    """Ask the signaling server for short-lived TURN credentials.

    Behind CGNAT / symmetric NAT there is no direct UDP path between peers, so a
    relay is the only transport that works. Shipping a TURN secret inside the
    client would hand it to anyone with a hex editor, so the server mints
    expiring credentials instead (see turn_provider.py / the Worker's /turn).

    Returns ``(servers, ttl)``; ``([], 0)`` when the server has no TURN provider
    configured or is unreachable. Never raises - the caller falls back to the
    built-in list.
    """
    try:
        payload = await asyncio.to_thread(
            _fetch_ice_blocking, signaling_url, password, timeout)
    except urllib.error.HTTPError as ex:
        if ex.code == 404:
            # The signaling server predates the /turn endpoint, or it has not
            # been redeployed. Name the fix rather than the exception class.
            print("[turn] signaling server has no /turn endpoint (404) - "
                  "deploy the updated server, or set a TURN URL in Settings",
                  flush=True)
        else:
            print(f"[turn] relay credential request rejected: HTTP {ex.code}", flush=True)
        return ([], 0)
    except Exception as ex:
        print(f"[turn] could not fetch relay credentials: {type(ex).__name__}", flush=True)
        return ([], 0)
    servers = []
    for entry in (payload.get("iceServers") or []):
        urls = entry.get("urls") or entry.get("url")
        if isinstance(urls, str):
            urls = [urls]
        if not urls:
            continue
        servers.append(RTCIceServer(
            urls=list(urls),
            username=entry.get("username") or None,
            credential=entry.get("credential") or None,
        ))
    ttl = int(payload.get("ttl") or 0)
    if servers:
        relay_count = len(_flatten_turn_urls(servers))
        print(f"[turn] server provided {relay_count} relay URL(s) "
              f"via '{payload.get('provider', '?')}' (ttl={ttl}s)", flush=True)
    else:
        print("[turn] signaling server has no TURN provider configured", flush=True)
    return (servers, ttl)


MAX_PRE_HELLO_FRAMES = 64
MAX_PRE_HELLO_BYTES = 1 * 1024 * 1024
MAX_INCOMING_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1 GiB cap per file (down from 2 GiB) + per-peer single slot mitigates disk DoS; global total capped at 4 GiB implicitly via 4 peers

# App-layer heartbeat (see docs/WIRE_PROTOCOL.md). Ping cadence + the silence
# window after which an "open" channel is declared dead and self-healed.
HEARTBEAT_INTERVAL_S = 15.0
HEARTBEAT_DEAD_S     = 45.0


# ---------------------------------------------------------------------------
# Symmetric-NAT traversal WITHOUT a relay: predicted-srflx candidate injection
# + UDP birthday-spray pre-punch. Both are additive and best-effort - if they
# don't help, normal ICE / the signaling relay still carry the connection.
# ---------------------------------------------------------------------------

def _srflx_priority(local_pref: int = 65535, component: int = 1) -> int:
    """RFC 8445 candidate priority for a server-reflexive candidate
    (type preference 100)."""
    return (100 << 24) | (local_pref << 8) | (256 - component)


def build_srflx_candidate_line(ip: str, port: int, *, foundation: str = "9",
                               component: int = 1,
                               rel_ip: str = "0.0.0.0", rel_port: int = 0) -> str:
    """One SDP ``a=candidate:`` line advertising ``ip:port`` as a UDP srflx
    candidate. Used to inject a PREDICTED external mapping for a sequential
    symmetric NAT so the peer will try sending there (hole-punch)."""
    prio = _srflx_priority(component=component)
    return (f"candidate:{foundation} {component} udp {prio} {ip} {port} typ srflx "
            f"raddr {rel_ip} rport {rel_port}")


def inject_predicted_srflx(sdp: str, ip: str, port: int) -> str:
    """Append a predicted-srflx candidate to every media section of ``sdp``.

    Inserted right after the last existing ``a=candidate:`` line in each media
    block (or after ``a=end-of-candidates`` / before the next ``m=`` if none
    exist). Idempotent for a given ip:port - never adds a duplicate.
    """
    if not ip or not (0 < port <= 65535):
        return sdp
    line = build_srflx_candidate_line(ip, port)
    if line in sdp:
        return sdp
    lines = sdp.splitlines()

    # Split into the session header (before the first m=) and per-media sections.
    header: list[str] = []
    media_sections: list[list[str]] = []
    cur = header
    for ln in lines:
        if ln.startswith("m="):
            cur = [ln]
            media_sections.append(cur)
        else:
            cur.append(ln)

    rebuilt = list(header)
    for sec in media_sections:
        # find insertion point: after last a=candidate line, else before
        # a=end-of-candidates, else at end of section
        idx_last_cand = max((k for k, s in enumerate(sec)
                             if s.startswith("a=candidate:")), default=-1)
        if idx_last_cand >= 0:
            sec = sec[:idx_last_cand + 1] + ["a=" + line] + sec[idx_last_cand + 1:]
        else:
            idx_eoc = next((k for k, s in enumerate(sec)
                            if s.startswith("a=end-of-candidates")), -1)
            if idx_eoc >= 0:
                sec = sec[:idx_eoc] + ["a=" + line] + sec[idx_eoc:]
            else:
                sec = sec + ["a=" + line]
        rebuilt.extend(sec)
    # Preserve trailing newline style of the input.
    joined = "\r\n".join(rebuilt) if "\r\n" in sdp else "\n".join(rebuilt)
    if sdp.endswith(("\r\n", "\n")) and not joined.endswith("\n"):
        joined += "\r\n" if "\r\n" in sdp else "\n"
    return joined


def birthday_spray_ports(base_port: int, spread: int = 256,
                         max_port: int = 65535) -> list[int]:
    """Ports to pre-open around a predicted external port for the birthday
    paradox punch. Centred on ``base_port`` so a small allocation drift by
    other apps is still covered on both sides."""
    if not (1024 <= base_port <= max_port):
        return []
    half = spread // 2
    lo = max(1024, base_port - half)
    hi = min(max_port, base_port + half)
    return list(range(lo, hi + 1))


def prepunch_mapping(stun_ip: str, stun_port: int, local_port: int = 0,
                     timeout: float = 1.5) -> tuple[str, int] | None:
    """Open a NAT mapping by sending a STUN binding from ``local_port`` and
    return the (external_ip, external_port) the NAT assigned.

    Pre-opening the mapping BEFORE ICE negotiation means the predicted srflx
    candidate we advertise actually has a live pinhole behind it. Best-effort:
    returns None on any failure.
    """
    import secrets as _secrets
    import socket as _socket

    from aioice import stun as _stun
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        try:
            s.bind(("0.0.0.0", local_port))
        except OSError:
            return None
        req = _stun.Message(
            message_method=_stun.Method.BINDING,
            message_class=_stun.Class.REQUEST,
            transaction_id=_secrets.token_bytes(12),
        )
        s.sendto(bytes(req), (stun_ip, stun_port))
        data, _ = s.recvfrom(512)
        resp = _stun.parse_message(data)
        ext_ip, ext_port = resp.attributes["XOR-MAPPED-ADDRESS"]
        return (ext_ip, ext_port)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def punch_countdown_delay(now_ms: int, fire_at_ms: int,
                          min_delay: float = 0.0) -> float:
    """Seconds to sleep so both peers fire their first hole-punch packet at the
    SAME coordinated instant (``fire_at_ms``, agreed over signaling). Negative
    or past targets clamp to ``min_delay`` (fire immediately)."""
    delay = (fire_at_ms - now_ms) / 1000.0
    return max(min_delay, delay)

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
# (ExitIP:forwarded_port) as a srflx candidate - no candidate injection. The
# feature is purely additive: if the bind fails or pool is exhausted, normal
# gathering continues with ephemeral ports.

class PortPoolAllocator:
    """Thread-safe port pool allocator for aioice datagram endpoint bindings.

    Keyed by id(pc) so concurrent PeerConnection gathers do not collide.
    Releases ports on PC closure or close_peer, but retains them through
    connectionstatechange == 'failed' to support subsequent ICE restarts.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._ports: list[int] = []           # every forwarded port, as configured
        self._free: list[int] = []
        self._allocated: dict[int, int] = {}  # id(pc) -> port
        self._active: bool = False
        self._vpn_ip: str | None = None

    def configure(self, vpn_ip: str, ports: list[int]) -> None:
        """Publish the forwarded ports. Idempotent for an unchanged mapping.

        NAT-PMP hands back the SAME external port for every request, so the
        caller's pool arrives as e.g. [54097, 54097, 54097]. Binding one port
        twice fails with EADDRINUSE, so duplicates are collapsed here.

        The renewal loop re-publishes every 45 s. Re-running configure() then
        would hand a live connection's port back out and orphan its bookkeeping,
        so an unchanged mapping is deliberately a no-op.
        """
        deduped = list(dict.fromkeys(int(p) for p in ports if p))
        with self._lock:
            if self._active and self._vpn_ip == vpn_ip and self._ports == deduped:
                return
            self._vpn_ip = vpn_ip
            self._ports = deduped
            self._free = list(deduped)
            self._allocated.clear()
            self._active = bool(self._free)

    def clear(self) -> None:
        with self._lock:
            self._active = False
            self._vpn_ip = None
            self._ports.clear()
            self._free.clear()
            self._allocated.clear()

    def allocate(self, pc_id: int | None = None) -> int | None:
        """Claim a port from the free pool. Returns None if pool is exhausted
        (aioice then falls back to an ephemeral port)."""
        with self._lock:
            if not self._active or not self._free:
                return None
            port = self._free.pop(0)
            if pc_id is not None:
                self._allocated[pc_id] = port
            return port

    def release(self, pc_id: int) -> None:
        """Release a claimed port back into the free list."""
        with self._lock:
            port = self._allocated.pop(pc_id, None)
            if port is not None and port not in self._free:
                self._free.append(port)

    def release_port(self, port: int) -> None:
        """Return a port to the pool by value.

        The bind wrapper cannot see which RTCPeerConnection a socket belongs to,
        so it releases by port when the socket closes. Without this the pool
        drains after a few ICE restarts and every later gather silently falls
        back to an ephemeral port - which on a symmetric NAT means no reachable
        candidate at all.
        """
        with self._lock:
            if port in self._ports and port not in self._free:
                self._free.append(port)

    @property
    def vpn_ip(self) -> str | None:
        return self._vpn_ip

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def current_port(self) -> int:
        """The forwarded port to advertise, independent of allocation state.

        This feeds the injected srflx candidate, which must keep naming the
        forwarded port even while that port is checked out for a live gather.
        """
        with self._lock:
            return self._ports[0] if self._ports else 0


_port_allocator = PortPoolAllocator()
_forward_active = False
_forward_port = 0


def set_forwarded_ports(vpn_ip: str, ports) -> None:
    """Publish a pool of forwarded ports; each new matching ICE bind takes the next one."""
    global _forward_active, _forward_port
    _port_allocator.configure(vpn_ip, list(ports))
    _forward_active = _port_allocator.is_active
    _forward_port = _port_allocator.current_port


def set_forwarded_port(vpn_ip: str, port: int) -> None:
    """Back-compat shim: a one-element pool."""
    set_forwarded_ports(vpn_ip, [int(port)])


def clear_forwarded_port() -> None:
    """Disable forwarded-port binding; new gathers fall back to normal ports."""
    global _forward_active, _forward_port
    _port_allocator.clear()
    _forward_active = False
    _forward_port = 0


def _release_port_on_close(transport, port: int) -> None:
    """Hand ``port`` back to the pool once ``transport`` closes.

    aioice calls create_datagram_endpoint far below any peer-connection context,
    so the wrapper has no pc to key on. The socket's own lifetime is the honest
    signal: while it is open the port is genuinely taken, and once it closes the
    port is free for the next ICE restart.
    """
    released = False

    try:
        orig_close = transport.close

        def close(*a, **kw):
            nonlocal released
            if not released:
                released = True
                _port_allocator.release_port(port)
            return orig_close(*a, **kw)

        transport.close = close
    except (AttributeError, TypeError):
        # A transport that exposes no settable close() cannot tell us when it
        # goes away. Release now: handing the port back early risks a losing
        # bind that falls through to an ephemeral port, while holding it
        # forever drains the pool and silently kills reachability.
        _port_allocator.release_port(port)


def _make_bind_wrapper(orig):
    async def wrapped(protocol_factory, *args, local_addr=None, **kwargs):
        assigned = None
        if _port_allocator.is_active and local_addr == (_port_allocator.vpn_ip, 0):
            assigned = _port_allocator.allocate()
            if assigned is not None:
                local_addr = (_port_allocator.vpn_ip, assigned)
        try:
            transport, protocol = await orig(
                protocol_factory, *args, local_addr=local_addr, **kwargs)
        except OSError:
            if assigned is None:
                raise
            # The forwarded port is busy - a lingering socket from a previous
            # gather, or another application. Falling back to an ephemeral port
            # loses reachability but still gathers; failing the bind would take
            # the whole connection down.
            print(f"[forward] port {assigned} busy - falling back to ephemeral", flush=True)
            _port_allocator.release_port(assigned)
            return await orig(protocol_factory, *args,
                              local_addr=(_port_allocator.vpn_ip, 0), **kwargs)
        if assigned is not None:
            _release_port_on_close(transport, assigned)
        return transport, protocol
    return wrapped


def install_forward_patch(loop) -> None:
    """Wrap the loop's create_datagram_endpoint once (idempotent)."""
    if getattr(loop, "_helu_forward_patched", False):
        return
    loop.create_datagram_endpoint = _make_bind_wrapper(loop.create_datagram_endpoint)
    loop._helu_forward_patched = True


# ---------------------------------------------------------------------------
# Hub-election helpers (pure, deterministic - no I/O)
# ---------------------------------------------------------------------------

def reachability_tier(settings, current_port=None, reflected_host=None) -> int:
    """0=behind NAT  1=has public address (STUN/TURN/reflected)  2=forwarded port."""
    if (current_port and current_port > 0) or (
            getattr(settings, "port_forward_enabled", False)
            and getattr(settings, "forwarded_port", 0)):
        return 2
    if getattr(settings, "turn_url", "") or reflected_host:
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
    if not url.startswith(("turn:", "turns:")):
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
            try:
                await asyncio.wait_for(wait_gathering(), timeout=8.0)
            except (asyncio.TimeoutError, TimeoutError):
                return (False, "Timed out contacting TURN server")

        sdp = pc.localDescription.sdp if pc.localDescription else ""
        if "typ relay" in sdp:
            return (True, "Relay reachable")
        return (False, "No relay candidate - check URL/credentials")
    except (asyncio.TimeoutError, TimeoutError):
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
        return (False, (f"Public port {ext_port} ≠ forwarded {port} "
                       "(split-tunnel or NAT not preserving port)"))
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
        self._sct     = None
        self._monitor = None
        self._last_ts: float | None = None
        self._logged  = False
        self._max_w   = max_width  or config.SCREEN_MAX_WIDTH
        self._max_h   = max_height or config.SCREEN_MAX_HEIGHT
        self.target_fps = target_fps or config.SCREEN_FPS
        # Single-thread executor: mss is thread-affine so every grab must run
        # on the same OS thread. max_workers=1 guarantees that. Running grabs
        # off the asyncio loop also prevents ICE keepalives from being blocked
        # by the 30-150 ms it takes to capture + downscale a 4K/2K frame,
        # which was the cause of the connection-drop-after-first-frame bug.
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

    def _grab_frame(self) -> np.ndarray:
        """Blocking capture + resize - always called from the dedicated grab thread."""
        if self._sct is None:
            self._sct     = mss.mss()
            self._monitor = self._sct.monitors[1]
        img = np.ascontiguousarray(np.array(self._sct.grab(self._monitor))[:, :, :3])
        h0, w0 = img.shape[:2]
        scale  = min(self._max_w / w0, self._max_h / h0, 1.0)
        if scale < 1.0:
            if cv2 is not None:
                img = cv2.resize(img, (int(w0 * scale), int(h0 * scale)),
                                 interpolation=cv2.INTER_AREA)
            else:
                img = np.asarray(Image.fromarray(img).resize(
                    (int(w0 * scale), int(h0 * scale)), _BOX))
        h, w = img.shape[0] & ~1, img.shape[1] & ~1
        img = np.ascontiguousarray(img[:h, :w])
        if not self._logged:
            print(f"[screen] capturing {w0}x{h0} -> {w}x{h} @ {self.target_fps}fps",
                  flush=True)
            self._logged = True
        return img

    def _close_sct(self) -> None:
        """Close mss on the grab thread (maintains thread affinity)."""
        try:
            if self._sct is not None:
                self._sct.close()
        except Exception:
            pass
        self._sct = None

    async def recv(self):
        from aiortc.mediastreams import MediaStreamError
        if self.readyState != "live":
            raise MediaStreamError
        pts, time_base = await self.next_timestamp()
        loop     = asyncio.get_event_loop()
        now      = loop.time()
        interval = 1.0 / self.target_fps
        if self._last_ts is None:
            self._last_ts = now
        else:
            elapsed = now - self._last_ts
            if elapsed < interval:
                await asyncio.sleep(interval - elapsed)
            self._last_ts += interval
            if loop.time() - self._last_ts > interval:
                self._last_ts = loop.time()
        try:
            # Offload the blocking grab + resize to the dedicated thread so the
            # asyncio event loop (ICE keepalives, DTLS, etc.) keeps running.
            img = await loop.run_in_executor(self._executor, self._grab_frame)
        except Exception as ex:
            print(f"[screen] capture error: {type(ex).__name__}: {ex}", flush=True)
            img = np.zeros((480, 640, 3), dtype=np.uint8)
            # Reset mss on its own thread so the next grab gets a fresh instance.
            try:
                self._executor.submit(self._close_sct)
            except Exception:
                pass
        frame = VideoFrame.from_ndarray(img, format="bgr24")
        frame.pts       = pts
        frame.time_base = time_base
        return frame

    def stop(self):
        super().stop()
        # Close mss on the grab thread, then release the executor.
        try:
            self._executor.submit(self._close_sct)
            self._executor.shutdown(wait=False)
        except Exception:
            pass
        self._sct = None


# Frames queued ahead of the denoise worker before it gives up on this frame
# and passes it through raw. 4 frames ~= 80 ms of backlog - past that, keeping
# audio flowing matters more than cleaning it.
_NR_OVERLOAD_FRAMES = 4
# Seconds of low-energy mic audio gathered as the noise profile reduce_noise()
# needs to tell speech from background. Until it's collected (call start, or
# while the mic is quiet) frames pass through un-denoised.
_NR_PROFILE_SECONDS = 0.5
# reduce_noise() attenuates the whole frame, not just the noise, by roughly this
# factor; the denoised frame is scaled back up so voice level is preserved.
_NR_MAKEUP_GAIN = 2.5


def _load_noisereduce():
    """Import noisereduce lazily so it's only a hard dependency when enabled."""
    import noisereduce
    return noisereduce


def _frame_rms(samples) -> float:
    return float(np.sqrt(np.mean(samples.astype(np.float64) ** 2))) if samples.size else 0.0


class _NoiseReducer:
    """Off-thread spectral noise reduction for 20 ms int16 mono mic frames.

    The realtime audio callback hands raw frames to `submit()`; a worker thread
    builds a noise profile from the quietest early frames, then denoises each
    subsequent frame against it and hands the result back to the event loop via
    `sink`. reduce_noise() costs ~13 ms/frame, so it must never run on the
    asyncio loop or the audio thread. Before the profile is ready, or under
    backlog, frames pass through untouched so audio never stalls.
    """

    def __init__(self, sample_rate: int, stationary: bool, sink, loop, nr_module):
        self._sr = sample_rate
        self._stationary = stationary
        self._sink = sink
        self._loop = loop
        self._nr = nr_module
        self._q: _queue.Queue = _queue.Queue(maxsize=32)
        self._running = True
        # Noise-profile state. _boot_frames accumulates raw frames until there
        # are enough to pick a profile from; after that _noise_profile holds the
        # concatenated quiet frames and _profile_frames lets it roll forward.
        self._boot_frames: list = []
        self._boot_target = int(2 * _NR_PROFILE_SECONDS * sample_rate)
        self._profile_frames: deque = deque()
        self._noise_profile = None
        self._thread = threading.Thread(target=self._run, name="mic-denoise", daemon=True)
        self._thread.start()

    def submit(self, data) -> None:
        try:
            self._q.put_nowait(data)
        except _queue.Full:
            pass

    def _run(self) -> None:
        while self._running:
            data = self._q.get()
            if data is None:
                break
            self._emit(data)

    def _emit(self, data) -> None:
        profile = self._update_profile(data)
        if profile is None or self._q.qsize() > _NR_OVERLOAD_FRAMES:
            out = data          # still bootstrapping, or backlogged: pass through
        else:
            out = self._denoise(data, profile)
        self._loop.call_soon_threadsafe(self._sink, out)

    def _update_profile(self, data):
        """Return the current noise profile, or None while still collecting one."""
        samples = data.astype(np.float32).reshape(-1)
        if self._noise_profile is None:
            self._boot_frames.append(samples)
            if sum(len(f) for f in self._boot_frames) < self._boot_target:
                return None
            # Keep the quietest half of the collected frames - the ones least
            # likely to contain speech - as the noise profile.
            ordered = sorted(self._boot_frames, key=_frame_rms)
            keep = ordered[: max(1, len(ordered) // 2)]
            self._profile_frames = deque(keep, maxlen=len(keep))
            self._noise_profile = np.concatenate(list(self._profile_frames))
            self._boot_frames = []
            return self._noise_profile
        # Steady state: fold in frames quiet enough to be background, not speech,
        # so the profile tracks a drifting noise floor.
        if _frame_rms(samples) <= 1.3 * _frame_rms(self._noise_profile):
            self._profile_frames.append(samples)
            self._noise_profile = np.concatenate(list(self._profile_frames))
        return self._noise_profile

    def _denoise(self, data, profile):
        try:
            samples = data.astype(np.float32).reshape(-1)
            reduced = self._nr.reduce_noise(
                y=samples, sr=self._sr, stationary=self._stationary,
                n_fft=512, y_noise=profile,
            )
            return np.clip(
                reduced * _NR_MAKEUP_GAIN, -32768, 32767,
            ).astype(np.int16).reshape(-1, 1)
        except Exception:
            return data

    def stop(self) -> None:
        self._running = False
        try:
            self._q.put_nowait(None)
        except _queue.Full:
            try:
                self._q.get_nowait()
            except _queue.Empty:
                pass
            try:
                self._q.put_nowait(None)
            except _queue.Full:
                pass
        self._thread.join(timeout=1.0)


class MicrophoneTrack(AudioStreamTrack):
    kind = "audio"

    def __init__(self, push_to_talk: bool = False, mic_gain: float = 1.0,
                 noise_reduce: bool = False, noise_reduce_stationary: bool = True):
        super().__init__()
        import fractions
        self._ptt    = push_to_talk
        self._active = not push_to_talk
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=50)
        self._loop = asyncio.get_event_loop()
        self._timestamp = 0
        self._sample_rate = 48000
        self._time_base = fractions.Fraction(1, self._sample_rate)
        self._mic_gain = mic_gain
        self._reducer = None
        if noise_reduce:
            try:
                nr_module = _load_noisereduce()
                self._reducer = _NoiseReducer(
                    self._sample_rate, noise_reduce_stationary,
                    self._queue_put, self._loop, nr_module,
                )
            except Exception as ex:
                print(f"[rtc] noise reduction disabled ({ex}); sending raw mic audio",
                      flush=True)
                self._reducer = None
        self._stream = sd.InputStream(
            samplerate=self._sample_rate, channels=1, dtype="int16",
            blocksize=960,
            callback=self._audio_callback,
        )
        self._stream.start()

    def _audio_callback(self, indata, frames, time_info, status):
        if not self._active:
            return
        if self._reducer is not None:
            # Denoise off-thread; the reducer feeds _queue_put when done.
            self._reducer.submit(indata.copy())
        else:
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
        if data is None:
            raise MediaStreamError
        # Apply configurable gain to mic input (default 1.0 = no boost)
        boosted_data = np.clip(data.astype(np.int32) * self._mic_gain, -32768, 32767).astype(np.int16)
        frame = AudioFrame.from_ndarray(boosted_data.T, format="s16", layout="mono")
        frame.pts         = self._timestamp
        frame.time_base   = self._time_base
        frame.sample_rate = self._sample_rate

        self._timestamp += frame.samples
        return frame

    def stop(self) -> None:
        super().stop()
        if self._reducer is not None:
            self._reducer.stop()
            self._reducer = None
        try:
            self._stream.stop()
            self._stream.close()
        except Exception:
            pass
        self._queue_put(None)


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
        self.data_channels:        dict[str, object] = {}
        self.session_keys:         dict[str, bytes]             = {}
        self._hello_sent:          dict[str, bool]              = {}
        self._peer_hello_verified: dict[str, bool]              = {}
        self._eph_priv:            dict[str, str]               = {}  # peer -> our per-session ephemeral X25519 priv (b64)
        self._pre_hello_buffers:   dict[str, deque]             = {}
        self._pre_hello_bytes:     dict[str, int]               = {}
        self._is_negotiating:      dict[str, bool]              = {}
        self._neg_dirty:           dict[str, bool]              = {}
        # Peers we tried to call before their data channel was open - the
        # "call_start" ping is (re)sent from _bind_channel once it opens so the
        # callee actually rings instead of silently missing the call.
        self._pending_call_start:  set[str]                     = set()
        # PSK channel authentication (feature C). When room_psk is set, peers must
        # prove knowledge of the pre-shared key (HMAC challenge) BEFORE the hello
        # - a room becomes invisible to anyone without the PSK from the invite.
        self.room_psk:             str | None                = None   # base64 32-byte
        self._psk_authed:          dict[str, bool]              = {}
        self._psk_my_nonce:        dict[str, str]               = {}
        # Membership PKI (feature D, advisory). The creator vouches for members by
        # signing a cert; peers verify it against the creator's key but never drop
        # the connection (PSK already gates access) - they just flag membership.
        self.room_creator_pubkey:  str | None                = None   # creator ed25519 pub
        self.my_membership_cert:   str | None                = None   # our creator-signed cert
        self._peer_is_member:      dict[str, bool]              = {}
        self._file_buffers:        dict[str, dict]              = {}
        self._forwarded:           dict[str, list]              = {}  # source_peer -> [(dest, sub, sub_id, src_track_id)]
        self._live_tracks:         dict[str, list]              = {}  # source_peer -> [live incoming MediaStreamTrack]
        self._origin_map:          dict[str, str]               = {}  # track_id -> origin username
        self._origin_waiters:      dict[str, asyncio.Future]    = {}  # track_id -> Future waiting for origin
        self._bg_tasks:            set                          = set()  # strong refs to fire-and-forget tasks

        # Shared media sources fanned out to every peer via a relay so the mic
        # is only captured once and the screen is only grabbed once, regardless
        # of how many peers are in the call.
        self._relay         = MediaRelay()
        self._mic_source    = None   # single MicrophoneTrack capturing the mic
        self._screen_source = None   # single ScreenShareTrack grabbing the screen
        self._voice_peers:  set[str] = set()   # peers we've added a mic track to
        self._screen_peers: set[str] = set()   # peers we've added a screen track to
        # RTP senders kept so a track can be REMOVED (stop sharing/voice) without
        # tearing down the whole call - screen and voice are independent streams.
        self._screen_senders: dict[str, object] = {}
        self._voice_senders:  dict[str, object] = {}
        self._incoming_audio_active: set[str] = set()  # peers whose audio we play

        # Group call state
        self.group_key:             bytes | None = None
        self.is_room_creator:       bool            = False
        self.room_id:               str | None   = None
        self._pre_group_key_buffer: deque           = deque()
        self._send_ws:              Callable | None = None

        # Hub-election state
        self._cap_tier:          dict[str, int] = {}
        self._cap_epoch:         dict[str, int] = {}
        self._my_epoch:          int            = 0   # bumped in client before each hub_capability broadcast
        self._room_creator_name: str | None  = None
        self._reflected_host:    str          = ""   # public IP reflected by signaling server

        # Server-minted TURN credentials (see fetch_ice_servers). These outrank
        # every built-in relay because they are the only ones guaranteed live.
        self._server_ice:        list       = []
        self._server_ice_until:  float      = 0.0
        # Rotates the single TURN URL aiortc accepts, so a retry after a failed
        # connection tries the next transport instead of the same blocked one.
        self._ice_attempt:       int        = 0

        # 1-to-1 compat: target_peer is set by create_offer / handle_offer
        self.target_peer: str = ""

        # Signaling-relay and sequencing state
        self._signaling_hello_sent: dict[str, bool] = {}
        self._epoch_ids: dict[str, str] = {}
        self._send_seq: dict[str, int] = {}
        self._recv_window: dict[str, dict[str, tuple[int, int]]] = {}
        self._delivered_msg_ids: deque = deque(maxlen=1000)
        self._direct_stable_since: dict[str, float] = {}
        self.server_capabilities: list[str] = []

        # Callbacks set by client.py - on_state_change(peer, state)
        self.on_state_change:  Callable | None = None  # (peer: str, state: str)
        self.on_message:       Callable | None = None  # (sender, text, verified)
        self.on_file_chunk:    Callable | None = None
        self.on_file_complete: Callable | None = None
        self.on_call_incoming: Callable | None = None
        self.on_call_accepted: Callable | None = None
        self.on_call_rejected: Callable | None = None
        self.on_hangup:        Callable | None = None
        self.on_video_frame:   Callable | None = None  # (sender: str, img: np.ndarray)
        self.on_video_end:     Callable | None = None  # (sender: str) - incoming screen track ended
        self.on_key_change:    Callable | None = None  # (peer: str) - verified key changed
        self.on_session_ready: Callable | None = None  # (peer: str) - hello verified, channel usable
        self.on_history_request:  Callable | None = None  # (peer, room_id, since)
        self.on_history_response: Callable | None = None  # (peer, room_id, messages)
        self.on_membership_change: Callable | None = None  # (peer, is_member)
        self.on_delivery:      Callable | None = None  # (peer: str, msg_id: str) - chat acked
        self.on_rtt:           Callable | None = None  # (peer: str, rtt_ms: float)
        self.on_sent:          Callable | None = None  # (peer, msg_id) - queued chat left the outbox
        self.on_typing:        Callable | None = None  # (peer: str) - peer is composing
        self.on_peer_unverified: Callable | None = None  # (peer: str) - peer removed verification

        # --- Reliability layer (heartbeat + outbox + delivery acks) ----------
        # App-layer heartbeat: detects a logically-dead-but-"open" channel that
        # WebRTC's own ICE timers can miss, and yields a live RTT for diagnostics.
        self._last_pong:  dict[str, float] = {}   # peer -> monotonic ts of last pong
        self._rtt_ms:     dict[str, float] = {}   # peer -> last measured round-trip
        self._hb_task = None
        # Offline outbox: 1-to-1 chats queued while a peer is unreachable, flushed
        # in order once its session is ready.
        self._outbox = Outbox()
        # Outstanding delivery acks we're waiting on (peer -> {msg_id, ...}); the
        # client uses on_delivery to flip a message to "delivered".
        self._awaiting_ack: dict[str, set] = {}

        # Audio playback: a single callback-driven output stream. Incoming
        # decoded frames are appended to per-peer numpy buffers; sounddevice's
        # audio thread pulls + mixes them in _play_callback (NOT the asyncio
        # loop - a blocking write in the loop starves playback and freezes UI).
        self._output_stream = None
        # Per-peer queue of decoded int16 chunks (deque of ndarrays). Using a
        # deque + partial-head consumption avoids the O(n) full-buffer copy that
        # np.concatenate did on every 20 ms frame (GC churn on weak hardware).
        self._play_chunks: dict[str, deque] = {}
        self._play_lock = threading.Lock()
        # Playback gain applied in the audio callback. Adjustable live from the
        # UI (no reconnection needed) since _play_callback reads it every block.
        self._volume: float = 4.0

        # Diagnostics state (read by get_diagnostics; cheap, no secrets).
        self._ice_states:      dict[str, str] = {}
        self.last_error:       str = ""
        self.signaling_status: str = "idle"

        # NAT traversal: cached behaviour profile (filled by detect_nat()) and
        # the predicted external port for a sequential-symmetric NAT, which is
        # injected as an extra srflx candidate so a symmetric peer can connect
        # WITHOUT a relay. Off until detect_nat() runs; purely additive.
        self._nat_profile = None          # nat_discovery.NatProfile | None
        self._predicted_ext_port: int = 0
        self._predicted_ext_ip:   str = ""

    # ------------------------------------------------------------------
    # ICE / TURN configuration (from settings - env only seeds first run)
    # ------------------------------------------------------------------

    async def refresh_server_ice(self, signaling_url: str, password: str = "") -> bool:
        """Pull short-lived TURN credentials from the signaling server.

        Called once the signaling session is authenticated. Cached until shortly
        before the credentials expire; a failed refresh keeps the previous set
        rather than dropping to no relay at all.
        """
        if self._server_ice and _time.monotonic() < self._server_ice_until:
            return True
        servers, ttl = await fetch_ice_servers(signaling_url, password)
        if not servers:
            return False
        self._server_ice = servers
        # Refresh at three quarters of the lifetime; floor keeps a server that
        # reports a nonsense TTL from causing a refresh storm.
        self._server_ice_until = _time.monotonic() + max(300.0, (ttl or 3600) * 0.75)
        return True

    def _ice_servers(self, force_relay: bool = False) -> list:
        servers = list(_STUN_SERVERS)
        url = getattr(self.settings, "turn_url", "") or ""
        # A TURN relay is what makes connections succeed behind symmetric /
        # carrier-grade NAT where STUN alone fails. Priority order matters
        # because aiortc consumes only the first TURN URL: an explicitly
        # configured relay wins, then whatever the signaling server minted for
        # us, then the public fallback.
        if url:
            servers.append(RTCIceServer(
                urls=[url],
                username=getattr(self.settings, "turn_username", "") or None,
                credential=getattr(self.settings, "turn_password", "") or None,
            ))
        servers.extend(self._server_ice)
        # Optimized fallback: only inject free relay when NAT demands it or user has
        # no TURN at all and we're in a strict-NAT scenario. Cheap STUN stays always,
        # TURN (which costs gathering time) is added lazily to avoid penalizing easy NATs.
        needs_relay = False
        try:
            if self._nat_profile and getattr(self._nat_profile, "needs_relay", False):
                needs_relay = True
        except Exception:
            pass
        # A server-minted relay already covers the strict-NAT case; the public
        # fallback only exists for deployments with no TURN provider at all.
        have_relay = bool(url) or bool(self._server_ice)
        if (force_relay or needs_relay) and not have_relay:
            # Only once, avoid duplicating if already added
            servers.extend(_FALLBACK_TURN_SERVERS)
        elif not have_relay and getattr(self.settings, "turn_fallback_enabled", True):
            # Light fallback: add TCP/443 TURN even without strict detection so UDP-blocked
            # networks still gather a relay candidate in parallel (~300ms extra, parallel)
            # This is the enterprise-firewall bypass. Guarded by setting to keep low-perf opt-out.
            # When NAT profile is unknown (detection not yet run), always add fallback
            # to ensure first connection attempt has the same ICE config as later ones.
            if self._nat_profile is None or getattr(self._nat_profile, "nat_type", "") in ("unknown", "blocked"):
                servers.extend(_FALLBACK_TURN_SERVERS[:1])
        return servers

    def _ice_config(self, force_relay: bool = False) -> RTCConfiguration:
        servers = self._ice_servers(force_relay=force_relay)
        # aiortc does not expose the browser ``iceTransportPolicy`` option.
        # For a strict NAT, omit STUN servers so gathering concentrates on TURN
        # candidates instead of spending time on server-reflexive candidates
        # that cannot form a pair. aiortc still gathers host candidates, hence
        # this is relay-preferred rather than an absolute relay-only policy.
        try:
            needs_relay = force_relay or (
                self._nat_profile and getattr(self._nat_profile, "needs_relay", False)
            )
            # Only restrict strictly to relay servers when we hold a relay we
            # trust - configured by the user, or minted for us by the signaling
            # server. The public fallback may be expired or rate-limited, and
            # stripping STUN in favour of a dead relay leaves no path at all.
            has_user_turn = bool(getattr(self.settings, "turn_url", "")
                                 or os.getenv("HELUCRYPTIC_TURN_URL")
                                 or self._server_ice)
            if needs_relay and has_user_turn and len(servers) > len(_STUN_SERVERS):
                relay_servers = [
                    server for server in servers
                    if any(url.startswith(("turn:", "turns:")) for url in server.urls)
                ]
                if relay_servers:
                    return RTCConfiguration(
                        iceServers=_select_for_aiortc(relay_servers, self._ice_attempt))
        except Exception:
            pass
        return RTCConfiguration(iceServers=_select_for_aiortc(servers, self._ice_attempt))

    async def detect_nat(self) -> dict:
        """Probe NAT behaviour (RFC 5780) off the event loop and cache the result.

        Surfaced in diagnostics, and - for a sequential-symmetric NAT - used to
        predict the external port we inject as an extra srflx candidate during
        offer/answer (see _augment_local_sdp). For RANDOM strict NAT, also
        triggers optimized birthday spray in background. Best-effort; never raises.
        """
        try:
            import nat_discovery
            profile = await asyncio.to_thread(nat_discovery.discover)
            self._nat_profile = profile
            pred = nat_discovery.predict_next_port(profile)
            if pred:
                self._predicted_ext_port = pred
                self._predicted_ext_ip = profile.ext_ip
                print(f"[nat] {profile.nat_type}: predicting external srflx "
                      f"{profile.ext_ip}:{pred} for hole-punch", flush=True)
            else:
                self._predicted_ext_port = 0
                self._predicted_ext_ip = ""
                print(f"[nat] detected {profile.nat_type} - {profile.summary}", flush=True)
            # Optimized spray for strict RANDOM/BLOCKED: birthday attack in background
            # Non-blocking - fire-and-forget, low CPU, bounded ports.
            if getattr(profile, "nat_type", "") in ("random-symmetric", "blocked"):
                try:
                    # Use ext_ip from any sample + spray around predicted range
                    self._bg(self._spray_strict_nat(profile))
                except Exception:
                    pass
            return {"nat_type": profile.nat_type, "summary": profile.summary,
                    "ext_ip": profile.ext_ip, "predicted_port": pred or 0,
                    "needs_relay": getattr(profile, "needs_relay", False)}
        except Exception as ex:
            print(f"[nat] discovery failed: {type(ex).__name__}: {ex}", flush=True)
            return {"nat_type": "unknown", "summary": "discovery failed",
                    "ext_ip": "", "predicted_port": 0, "needs_relay": False}

    async def _spray_strict_nat(self, profile) -> None:
        """Optimized birthday spray for RANDOM symmetric NAT.

        Opens 128-256 UDP pinholes around the observed external port range in
        parallel, non-blocking, with tight timeouts. This increases the chance
        that a predicted srflx candidate will have a live mapping, per birthday
        paradox. Runs off event loop via to_thread per chunk to avoid starving ICE.
        """
        try:
            import nat_discovery
            # Spray size adaptive to profile: random needs larger spray, blocked skips
            if getattr(profile, "nat_type", "") == "blocked":
                return
            base = getattr(profile, "ext_ip", "") or self._predicted_ext_ip
            # Derive spray centre from last observed external port
            last_ext = 0
            try:
                last_ext = max(p for _, p in getattr(profile, "samples", []) or [])
            except Exception:
                last_ext = self._predicted_ext_port or 45000
            if not last_ext or not base:
                return
            # Build spray list: centred, bounded, 128 ports for random, 64 for sequential
            spread = 256 if profile.nat_type == "random-symmetric" else 96
            ports = birthday_spray_ports(last_ext, spread=spread)
            # Optimized: only spray first 96 in parallel batches to limit CPU/UDP bursts
            # Further ports are injected as SDP candidates without pre-punch (still probed by peer)
            chunk = ports[:96]
            if not chunk:
                return
            # Pre-punch in background: send STUN binding to create mapping (cheap, 0.4s total)
            stun_ip = "stun.l.google.com"
            try:
                stun_ip_resolved = await asyncio.to_thread(lambda: __import__("socket").gethostbyname(stun_ip))
            except Exception:
                stun_ip_resolved = "142.250.153.127"
            # Batch with concurrency 16 to avoid fd exhaustion, each with 0.35s timeout
            sem = asyncio.Semaphore(16)
            async def _one(p):
                async with sem:
                    try:
                        await asyncio.to_thread(prepunch_mapping, stun_ip_resolved, 19302, local_port=p, timeout=0.35)
                    except Exception:
                        pass
            # Fire spray without blocking caller - but await chunk with timeout 3s
            try:
                await asyncio.wait_for(asyncio.gather(*[_one(p) for p in chunk]), timeout=3.0)
            except asyncio.TimeoutError:
                pass
            # Also inject 2 extra predicted SDP candidates for lookahead 2,3
            for la in (2, 3):
                try:
                    extra = nat_discovery.predict_next_port(profile, lookahead=la)
                    if extra and extra != self._predicted_ext_port:
                        # Store as secondary candidates to be injected on next offer
                        if not hasattr(self, "_extra_predicted_ports"):
                            self._extra_predicted_ports = []
                        if extra not in self._extra_predicted_ports:
                            self._extra_predicted_ports.append(extra)
                except Exception:
                    continue
        except Exception:
            pass

    def _augment_local_sdp(self, sdp: str) -> str:
        """Inject the predicted srflx candidate(s) into an outgoing offer/answer.

        For sequential NAT one candidate; for random strict NAT inject 2-3 lookahead
        candidates as well. No-op when prediction unavailable. Optimized: string op only."""
        ext_ip = self._reflected_host or self._predicted_ext_ip or getattr(self._nat_profile, "ext_ip", "")
        if _port_allocator.is_active and _port_allocator.current_port and ext_ip:
            try:
                sdp = inject_predicted_srflx(sdp, ext_ip, _port_allocator.current_port)
            except Exception:
                pass

        if self._predicted_ext_ip and self._predicted_ext_port:
            try:
                sdp = inject_predicted_srflx(sdp, self._predicted_ext_ip, self._predicted_ext_port)
            except Exception:
                pass
            # Inject extra lookahead candidates for random spray hedging
            try:
                for extra_port in getattr(self, "_extra_predicted_ports", [])[:2]:
                    sdp = inject_predicted_srflx(sdp, self._predicted_ext_ip, extra_port)
            except Exception:
                pass
            return sdp
        return sdp

    def get_diagnostics(self) -> dict:
        """Redacted connection snapshot for the diagnostics UI - never includes
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
                "datachannel":   getattr(dc, "readyState", "-") if dc else "none",
                "hello_sent":    bool(self._hello_sent.get(peer)),
                "hello_ok":      bool(self._peer_hello_verified.get(peer)),
                "session_key":   peer in self.session_keys,
                "rtt_ms":        round(self._rtt_ms.get(peer, 0.0)),
                "outbox":        self._outbox.pending(peer),
            })
        try:
            hub = self.current_hub() if self.room_id else ""
        except Exception:
            hub = "?"
        nat = self._nat_profile
        return {
            "signaling":       self.signaling_status,
            "my_username":     self.my_username,
            "room_id":         self.room_id or "",
            "hub":             hub,
            "security_mode":   getattr(self.settings, "security_mode", ""),
            "turn_configured": bool(getattr(self.settings, "turn_url", "")) or bool(self._server_ice),
            # Which relay URL this peer connection will actually gather against.
            # aiortc takes only one, so naming it turns "TURN: configured" into
            # something you can act on when a WAN call still fails.
            "turn_active": next(
                (u for u, _, _ in _flatten_turn_urls(self._ice_servers())), ""),
            "turn_source": ("settings" if getattr(self.settings, "turn_url", "")
                            else "server" if self._server_ice else "fallback"),
            "num_peers":       len(self.pcs),
            "last_error":      self.last_error,
            "nat_type":        getattr(nat, "nat_type", "unknown") if nat else "(not probed)",
            "nat_summary":     getattr(nat, "summary", "") if nat else "",
            "predicted_srflx": (f"{self._predicted_ext_ip}:{self._predicted_ext_port}"
                                if self._predicted_ext_port else ""),
            # The forwarded port is a real hole in an otherwise symmetric NAT,
            # so it is what actually gets a peer through - worth showing next to
            # the (accurate, but ephemeral-port) NAT verdict that says "strict".
            "forwarded_srflx": (f"{self._reflected_host}:{_port_allocator.current_port}"
                                if _port_allocator.is_active
                                and _port_allocator.current_port
                                and self._reflected_host else ""),
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

    def set_reflected_host(self, host: str) -> None:
        """Store the server-reflected public IP for use in hub-election tier calculation."""
        self._reflected_host = host or ""

    def _my_tier(self) -> int:
        """Return this engine's own reachability tier using current module-global state."""
        cur = _forward_port if _forward_active else None
        return reachability_tier(self.settings, current_port=cur, reflected_host=self._reflected_host or None)

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
    # Strict-NAT coordinated punch (simultaneous open) - optimized
    # ------------------------------------------------------------------

    async def send_punch_at(self, peer: str, ws_send: Callable, fire_at_ms: int | None = None) -> None:
        """Send a coordinated fire timestamp so both peers punch at same instant.

        Only used for strict NAT (random/BLOCKED). The message is tiny and
        relayed via signaling (server blind). fire_at is now + 900ms to account
        for signaling latency.
        """
        try:
            import time as _t
            now_ms = int(_t.time() * 1000)
            if fire_at_ms is None:
                fire_at_ms = now_ms + 900
            await ws_send({"target": peer, "type": "punch_at", "data": {"fire_at": fire_at_ms}})
        except Exception:
            pass

    async def handle_punch_at(self, data: dict, sender: str, ws_send: Callable) -> None:
        """Peer asks us to punch simultaneously - sleep until fire_at then offer.

        Non-blocking, optimized: uses punch_countdown_delay to compute precise wait
        without busy loop. If we're already connected, ignore.
        """
        try:
            import time as _t
            fire_at = int(data.get("fire_at") or 0)
            if not fire_at or sender in self.pcs and self.pcs[sender].connectionState in ("connected", "completed"):
                return
            now_ms = int(_t.time() * 1000)
            delay = punch_countdown_delay(now_ms, fire_at, min_delay=0.0)
            # Clamp max wait to 2s to avoid hanging
            delay = min(delay, 2.0)
            if delay > 0:
                await asyncio.sleep(delay)
            # Ensure PC exists and drive offer (both sides offer for strict)
            if sender not in self.pcs:
                self._init_pc(sender)
                dc = self.pcs[sender].createDataChannel("chat", ordered=True)
                self.data_channels[sender] = dc
                self._bind_channel(dc, sender)
            elif sender not in self.data_channels:
                # PC exists but no data channel — create one on existing PC
                dc = self.pcs[sender].createDataChannel("chat", ordered=True)
                self.data_channels[sender] = dc
                self._bind_channel(dc, sender)
            # For strict, bypass alphabetical - both punch
            await self.request_negotiation(sender)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Signaling-relay fallback & Relay-First transport
    # ------------------------------------------------------------------

    def is_direct_stable(self, peer: str) -> bool:
        """True if DataChannel is open and has been stable for >= 3.0 s."""
        dc = self.data_channels.get(peer)
        if dc and getattr(dc, "readyState", None) == "open":
            opened_at = self._direct_stable_since.get(peer)
            if opened_at is not None and (_time.monotonic() - opened_at) >= 3.0:
                return True
        return False

    def should_relay(self, peer: str) -> bool:
        """True if message should travel over signaling relay (Relay-First or fallback)."""
        return not self.is_direct_stable(peer)

    async def send_via_relay(self, peer: str, payload: dict | bytes | str) -> bool:
        """Send chat/control payload via signaling server.

        Enforces wire size cap (24 KiB) and uses existing _send_ws connection.
        """
        try:
            if self._send_ws is None:
                return False
            data_to_send = json.dumps(payload) if isinstance(payload, dict) else payload
            if isinstance(data_to_send, str):
                encoded = data_to_send.encode("utf-8")
                if len(encoded) > 24576:
                    print(f"[relay] Payload exceeds 24 KiB wire cap ({len(encoded)} bytes); dropping.", flush=True)
                    return False
                await self._send_ws({
                    "target": peer,
                    "type": "relay_e2ee",
                    "data": data_to_send,
                })
                return True
            return False
        except Exception as ex:
            print(f"[relay] Failed sending via relay to {peer}: {ex}", flush=True)
            return False

    async def handle_relay_message(self, data, sender: str) -> None:
        """Incoming relayed payload from signaling server - inject as if from DataChannel."""
        try:
            if isinstance(data, str):
                if len(data.encode("utf-8")) > 24576:
                    print(f"[relay] Dropping oversized relay frame from {sender}", flush=True)
                    return
                await self._handle_text(data, sender)
            elif isinstance(data, dict):
                raw = json.dumps(data)
                if len(raw.encode("utf-8")) > 24576:
                    print(f"[relay] Dropping oversized relay frame from {sender}", flush=True)
                    return
                await self._handle_text(raw, sender)
        except Exception as ex:
            print(f"[relay] Exception in handle_relay_message: {ex}", flush=True)

    # Alias for backward compatibility
    handle_p2p_relay = handle_relay_message

    # ------------------------------------------------------------------
    # Track-origin helpers (receiver-side SFU origin keying)
    # ------------------------------------------------------------------

    def _bg(self, coro) -> "asyncio.Task | None":
        """Schedule a coroutine as a background task, holding a strong reference
        so the GC cannot collect it before it finishes (Python ≥ 3.12 risk)."""
        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.get_event_loop()
            if loop.is_closed():
                try:
                    coro.close()
                except Exception:
                    pass
                return None
            t = loop.create_task(coro)
        except Exception:
            try:
                coro.close()
            except Exception:
                pass
            return None
        self._bg_tasks.add(t)
        t.add_done_callback(self._bg_tasks.discard)
        return t

    async def shutdown(self) -> None:
        """Cancel all background tasks and close peer connections – idempotent."""
        for t in list(self._bg_tasks):
            if not t.done():
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass
        self._bg_tasks.clear()
        if self._hb_task is not None and not self._hb_task.done():
            self._hb_task.cancel()
            try:
                await self._hb_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            self._hb_task = None
        for peer in list(self.pcs.keys()):
            try:
                await self.remove_peer(peer)
            except Exception:
                pass

    def _origin_of(self, track_id: str):
        return self._origin_map.get(track_id)

    def _handle_track_origin(self, frame: dict) -> None:
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
        except TimeoutError:
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
        self._last_pong[peer]           = _time.monotonic()   # fresh heartbeat clock
        self.start_heartbeat()                                # idempotent

        # NOTE: aiortc gathers ICE non-trickle - all candidates are embedded in
        # the SDP offer/answer, and it never emits a browser-style "icecandidate"
        # event. So there is deliberately no outbound trickle handler here.
        # handle_ice() still accepts inbound candidates defensively (e.g. from a
        # future browser peer that does trickle).

        @pc.on("connectionstatechange")
        def on_state():
            state = pc.connectionState
            print(f"[rtc] {self.my_username}: pc[{peer}] connection -> {state}", flush=True)
            if state != "connected":
                self._direct_stable_since.pop(peer, None)
            if self.on_state_change:
                self.on_state_change(peer, state)

            if state == "failed":
                # aiortc uses a single TURN URL per peer connection, so a failure
                # may just mean this transport is blocked (UDP on a locked-down
                # network). Advance the rotation so the healing attempt gathers
                # against the next relay URL - TCP, then TLS/443.
                self._ice_attempt += 1
                # Signaling may still be alive - attempt self-healing renegotiation
                # before giving up. Retain allocated port for subsequent ICE restart.
                if self._send_ws is not None:
                    self._bg(self._heal_peer(peer))
                else:
                    self._bg(self.remove_peer(peer))
            elif state == "closed":
                _port_allocator.release(id(pc))
                self._bg(self.remove_peer(peer))
            elif state == "disconnected":
                # ICE has its own short recovery timers, so give it a grace
                # period - but aiortc can sit in "disconnected" indefinitely
                # (NAT rebind, network switch) without ever reaching "failed".
                # If it hasn't recovered after the grace window, heal it.
                self._bg(self._watch_disconnected(peer, pc))

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
                self._bg(self._render_video(track, peer))
            elif track.kind == "audio":
                self._bg(self._handle_incoming_audio(track, peer))
            if self.room_id:
                # Keep a registry of live incoming tracks so a hub can fan an
                # ongoing call/share out to peers that join LATER.
                self._live_tracks.setdefault(peer, []).append(track)

                @track.on("ended")
                def _track_gone(t=track, p=peer):
                    lst = self._live_tracks.get(p)
                    if lst and t in lst:
                        lst.remove(t)
                if self.current_hub() == self.my_username:
                    self._bg(self._relay_track_to_others(peer, track))

    # ------------------------------------------------------------------
    # DataChannel binding
    # ------------------------------------------------------------------

    def _bind_channel(self, channel, peer: str) -> None:
        async def _on_open():
            self._direct_stable_since[peer] = _time.monotonic()
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
            self._bg(_on_open())

    # ------------------------------------------------------------------
    # PSK channel authentication (feature C)
    # ------------------------------------------------------------------

    def set_room_psk(self, psk: str | None) -> None:
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

    def set_room_creator_pubkey(self, pub: str | None) -> None:
        """Member side: trust anchor (creator's key) from the invite. Our own
        cert is unknown until the creator issues one."""
        self.room_creator_pubkey = pub or None
        self.my_membership_cert = None

    def is_member(self, peer: str) -> bool:
        return self._peer_is_member.get(peer, False)

    def purge_secrets(self) -> None:
        """Wipe all session/room cryptographic material from RAM (feature H -
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

    def _psk_proof(self, nonce: str, responder: str) -> str:
        """HMAC-SHA256 over (nonce | room_id | responder) keyed by the PSK -
        proves the sender holds the PSK without revealing it. Binding the
        room_id stops cross-room replay; binding the RESPONDER's username stops
        a reflection attack (an attacker echoing our own nonce back as a
        challenge and replaying our answer as their response would yield a
        proof bound to OUR name, not theirs, and fail verification)."""
        key = _b64.b64decode(self.room_psk)
        msg = (nonce + "|" + (self.room_id or "") + "|" + (responder or "")).encode()
        return hmac.new(key, msg, hashlib.sha256).hexdigest()

    async def _handle_psk(self, kind: str, frame: dict, peer: str) -> None:
        if not self.room_psk:
            return  # not a PSK room - ignore stray PSK frames
        ch = self.data_channels.get(peer)
        if kind == "psk_challenge":
            # Answer the peer's challenge with a proof over THEIR nonce,
            # bound to OUR name (we are the responder).
            proof = self._psk_proof(frame.get("nonce", ""), self.my_username)
            if ch and ch.readyState == "open":
                try:
                    ch.send(json.dumps({"__type": "psk_response", "proof": proof}))
                except Exception:
                    pass
        elif kind == "psk_response":
            # Verify the peer's proof over OUR nonce (constant-time).
            # Reject responses when no challenge is pending - prevents replay
            # against an absent/empty nonce which would produce a predictable hash.
            nonce = self._psk_my_nonce.get(peer, "")
            if not nonce:
                print(f"[psk] {self.my_username}: unexpected psk_response from {peer} - no pending challenge", flush=True)
                return
            expected = self._psk_proof(nonce, peer)
            if hmac.compare_digest(expected, str(frame.get("proof", ""))):
                # One-shot nonce: consume it so the same proof can't be replayed.
                self._psk_my_nonce.pop(peer, None)
                if not self._psk_authed.get(peer):
                    self._psk_authed[peer] = True
                    print(f"[psk] {self.my_username}: {peer} passed PSK auth", flush=True)
                    await self._start_session(peer)
            else:
                print(f"[psk] {self.my_username}: {peer} FAILED PSK auth - aborting", flush=True)
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
            # Deliver anything queued while this peer was offline (DTLS path).
            if not self.room_id:
                self._bg(self._flush_outbox(peer))
            # DTLS rooms have no hello, so the hub's late-joiner track fan-out
            # must happen here instead of at the end of _handle_hello.
            if self.room_id and self.current_hub() == self.my_username:
                self._bg(self._relay_existing_tracks_to(peer))

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
        from datetime import datetime
        payload = {
            "username":    self.my_username,
            "x25519_pub":  self.keys["x25519_public"],
            "ed25519_pub": self.keys["ed25519_public"],
            "eph_x25519_pub": self._ephemeral_pub(peer),
            "iat":         datetime.now(UTC).isoformat(),
        }
        token = paseto_sign(payload, self.keys["ed25519_private"], self.keys["ed25519_public"])
        hello = {"__type": "hello", "token": token}
        if self.my_membership_cert:            # feature D: present our membership cert
            hello["cert"] = self.my_membership_cert
        ch = self.data_channels.get(peer)
        if not (ch and ch.readyState == "open"):
            return
        ch.send(json.dumps(hello))
        self._hello_sent[peer] = True

    async def _send_signaling_hello(self, peer: str) -> None:
        """Send authenticated identity and ephemeral X25519 key over signaling WebSocket.

        Completes X25519 ECDH handshake out-of-band so session keys are available
        immediately before or without WebRTC DataChannel connectivity (DERP/Relay-First).
        """
        if not self._send_ws or self.settings.security_mode != "e2ee":
            return
        try:
            payload = {
                "username":    self.my_username,
                "x25519_pub":  self.keys["x25519_public"],
                "ed25519_pub": self.keys["ed25519_public"],
                "eph_x25519_pub": self._ephemeral_pub(peer),
                "iat":         datetime.now(UTC).isoformat(),
            }
            token = paseto_sign(payload, self.keys["ed25519_private"], self.keys["ed25519_public"])
            data = {"__type": "hello", "token": token}
            if self.my_membership_cert:
                data["cert"] = self.my_membership_cert
            await self._send_ws({
                "target": peer,
                "type": "hello_signaling",
                "data": data,
            })
            self._signaling_hello_sent[peer] = True
            self._hello_sent[peer] = True
        except Exception as ex:
            print(f"[crypto] Failed to send signaling hello to {peer}: {ex}", flush=True)

    async def handle_signaling_hello(self, data: dict, sender: str) -> None:
        """Process incoming signaling hello, derive session key, and reply if needed."""
        try:
            await self._handle_hello(data, sender)
            if not self._signaling_hello_sent.get(sender):
                await self._send_signaling_hello(sender)
        except Exception as ex:
            print(f"[crypto] Failed processing signaling hello from {sender}: {ex}", flush=True)

    def _hello_iat_fresh(self, iat: str) -> bool:
        """Defence-in-depth: reject a signed hello with an implausible timestamp."""
        if not iat:
            return False
        from datetime import datetime
        try:
            ts = datetime.fromisoformat(iat)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
        except (ValueError, TypeError):
            return False
        skew = abs((datetime.now(UTC) - ts).total_seconds())
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
                # PASETO payloads are unpadded base64url: pad to an exact
                # multiple of 4 (correct for every length; the old fixed "=="
                # relied on CPython's lenient decoder).
                b64_payload = parts[2] + "=" * (-len(parts[2]) % 4)
                claimed_pub = json.loads(
                    _b64.urlsafe_b64decode(b64_payload)[:-64]
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
                # First-contact TOFU: notify the user so they can verify the
                # fingerprint out-of-band. A MITM on the first connection is
                # otherwise undetectable until the contact is manually verified.
                print(f"[crypto] TOFU: first-contact key pinning for {peer} - verify fingerprint out-of-band.", flush=True)
                if self.on_key_change:
                    self.on_key_change(peer)

            try:
                payload = paseto_verify(frame["token"], verify_pub)
            except Exception:
                # The hello didn't verify against the key we have pinned. Decide
                # whether the peer simply re-keyed (reinstalled / regenerated) by
                # checking the hello against the key it claims for itself. A valid
                # signature there means a real identity - just a different one than
                # we pinned - i.e. a key rotation, not noise.
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
                # (possible MITM): alert the user and abort - never auto-accept.
                if prior.verified:
                    print(f"[crypto] KEY CHANGED for verified contact {peer}! Aborting connection.", flush=True)
                    try:
                        from contacts import set_verified
                        set_verified(peer, False)
                    except Exception:
                        pass
                    if self.on_key_change:
                        self.on_key_change(peer)
                    self._bg(self.remove_peer(peer))
                    return
                # An UNVERIFIED (trust-on-first-use) contact re-keyed. Don't drop
                # their frames silently - surface the change AND re-pin the new key
                # (the success path below calls upsert_contact) so chat and calls
                # keep working after the peer regenerated its identity.
                print(f"[crypto] Unverified contact {peer} re-keyed - re-pinning (TOFU).", flush=True)
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
                    try:
                        from contacts import set_verified
                        set_verified(peer, False)
                    except Exception:
                        pass
                    if self.on_key_change:
                        self.on_key_change(peer)
                    # Tear down the peer connection immediately
                    self._bg(self.remove_peer(peer))
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
            self._epoch_ids[peer] = hashlib.sha256(self.session_keys[peer]).digest()[:8].hex()
            upsert_contact(peer,
                           x25519_pub=payload["x25519_pub"],
                           ed25519_pub=payload["ed25519_pub"])
            # Send the group key to this peer.  The creator always does this.
            # The hub also does it when the creator is a non-hub member - the
            # hub has a direct channel to every peer, so it can distribute the
            # key even when the creator can only reach the hub (star topology).
            am_hub = self.room_id and self.current_hub() == self.my_username
            if (self.is_room_creator or am_hub) and self.group_key:
                await self._send_group_key_to(peer)

        self._peer_hello_verified[peer] = True
        await self._flush_pre_hello_buffer(peer)
        if self.on_session_ready:
            self.on_session_ready(peer)
        # Deliver anything queued for this peer while it was offline.
        if not self.room_id:
            self._bg(self._flush_outbox(peer))
        # Feature D (advisory membership): flag whether the peer holds a valid
        # creator-signed cert; if I'm the creator and they don't, issue one.
        # E2EE-only: in DTLS mode no hello payload (and no keys) exist, and
        # referencing `payload` here used to raise NameError for room creators.
        if self.room_id and self.settings.security_mode == "e2ee":
            is_member = self._evaluate_membership(peer, frame.get("cert"))
            if not is_member and self.is_room_creator:
                await self._send_cert_grant(peer, payload["username"], payload["ed25519_pub"])
                self._set_member(peer, True)
        # Hub late-joiner fix: if we are the relay hub, fan out any ALREADY
        # live incoming tracks (someone mid-call / mid-share) to this newly
        # ready peer so late joiners hear/see ongoing media immediately.
        if self.room_id and self.current_hub() == self.my_username:
            self._bg(self._relay_existing_tracks_to(peer))

    # ------------------------------------------------------------------
    # Membership PKI (feature D, advisory - never drops connections)
    # ------------------------------------------------------------------

    def _set_member(self, peer: str, ok: bool) -> None:
        self._peer_is_member[peer] = ok
        if self.on_membership_change:
            self.on_membership_change(peer, ok)

    def _evaluate_membership(self, peer: str, cert: str | None) -> bool:
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
        for p in self.data_channels:
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
        # Heartbeat is ungated (no secrets, must work independent of the hello):
        # answer a ping immediately; record a pong's round-trip.
        if t == "__ping":
            ch = self.data_channels.get(peer)
            if ch and getattr(ch, "readyState", None) == "open":
                try:
                    ch.send(json.dumps({"__type": "__pong", "ts": frame.get("ts")}))
                except Exception:
                    pass
            self._last_pong[peer] = _time.monotonic()
            return
        if t == "__pong":
            self._last_pong[peer] = _time.monotonic()
            ts = frame.get("ts")
            if isinstance(ts, (int, float)):
                rtt = max(0.0, (_time.time() * 1000.0) - float(ts))
                self._rtt_ms[peer] = rtt
                if self.on_rtt:
                    try:
                        self.on_rtt(peer, rtt)
                    except Exception:
                        pass
            return
        if t in ("psk_challenge", "psk_response"):
            await self._handle_psk(t, frame, peer)
            return
        if t == "hello":
            # In a PSK-protected room, ignore a hello until the peer has proven
            # the pre-shared key - no identity is exchanged with an unauthorised peer.
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
            self._relay_frame_to_others(raw, source=peer)

    async def _handle_binary(self, data: bytes, peer: str) -> None:
        if not (self._hello_sent.get(peer) and self._peer_hello_verified.get(peer)):
            self._buffer_pre_hello(peer, "binary", data)
            return
        state = self._file_buffers.get(peer, {}).get("_current")
        if state:
            remaining = state["size"] - state["received"]
            block = data[:max(0, remaining)]
            if block:
                try:
                    state["file"].write(block)
                    state["sha"].update(block)
                    state["received"] += len(block)
                except OSError as ex:
                    print(f"[file] Write error: {ex}", flush=True)
                    self._close_file_state(state, delete=True)
                    self._file_buffers.get(peer, {}).pop(state["filename"], None)
                    self._file_buffers.get(peer, {}).pop("_current", None)
                    if self.on_file_complete:
                        self.on_file_complete(state["filename"], state["path"], False)
                    return
            received = state["received"]
            if self.on_file_chunk:
                self.on_file_chunk(state["filename"], received, state["size"])
        if (self.room_id and self.current_hub() == self.my_username
                and self._file_buffers.get(peer, {}).get("_current")):
            self._relay_frame_to_others(data, source=peer)

    async def _dispatch_frame(self, frame: dict, peer: str) -> None:
        t = frame.get("__type")
        # Interop: older Android builds label direct chats "msg"; treat it as
        # "chat" so the two platforms exchange messages (see WIRE_PROTOCOL.md).
        if t == "msg":
            t = "chat"

        # Delivery receipt for one of OUR earlier chats.
        if t == "ack":
            d = self._decrypt_with_session(frame, peer)
            mid = d.get("id")
            if mid:
                self._awaiting_ack.get(peer, set()).discard(mid)
                if self.on_delivery:
                    try:
                        self.on_delivery(peer, mid)
                    except Exception:
                        pass
            return

        if t == "__typing":
            # Content-free composing hint (1-to-1). Only reachable post-hello
            # (gated in _handle_text), so an unauthenticated peer can't ping UI.
            if self.on_typing:
                try:
                    self.on_typing(peer)
                except Exception:
                    pass
            return

        if t == "track_origin":
            self._handle_track_origin(frame)
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

        if t == "unverify":
            if self.on_peer_unverified:
                try:
                    self.on_peer_unverified(peer)
                except Exception:
                    pass
            return

        if t == "chat":
            sender = peer
            msg_id = None
            if self.settings.security_mode == "e2ee":
                key = self.group_key if self.room_id else self.session_keys.get(peer)
                if not key:
                    return
                try:
                    payload = self._decrypt_dict(frame, peer)
                    # Authentication failures must drop the frame.  In
                    # particular, never turn a rejected relay token into a
                    # user-visible blank message (or an acknowledgement).
                    if not isinstance(payload, dict) or not payload:
                        print(f"[crypto] Invalid or unauthenticated chat frame from {peer}; dropping.", flush=True)
                        return
                    text = payload.get("text", "")
                    sender = payload.get("from") or peer
                    msg_id = payload.get("id")
                    seq = int(payload.get("seq", 0))
                    epoch = str(payload.get("epoch") or frame.get("epoch", ""))
                    if seq > 0 and not self._check_and_update_recv_window(peer, epoch, seq):
                        print(f"[crypto] Replay detected from {peer} (epoch={epoch}, seq={seq}); dropping.", flush=True)
                        return
                except Exception:
                    text = "[decryption failed]"
            else:
                text = frame.get("text", "")
                sender = frame.get("from") or peer
                msg_id = frame.get("id")

            # Deduplication across parallel transports (Relay vs Direct)
            if msg_id:
                if msg_id in self._delivered_msg_ids:
                    print(f"[chat] Deduplicated duplicate msg_id {msg_id} from {peer}.", flush=True)
                    return
                self._delivered_msg_ids.append(msg_id)

            if self.on_message:
                self.on_message(sender, text, frame.get("verified", False))
            # Send a delivery receipt for a 1-to-1 message that carried an id.
            # (Room messages are multi-recipient; acks there would be ambiguous.)
            if msg_id and not self.room_id:
                self._bg(self._send_ack(peer, msg_id))

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

        elif t == "screen_share_ended":
            if self.on_video_end:
                self.on_video_end(peer)

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
            # Remote hung up - tear down our side immediately (stop sending +
            # stop playing them), then notify the UI.
            self.end_call_from_peer(peer)
            if self.on_hangup:
                self.on_hangup(peer)

    # ------------------------------------------------------------------
    # Hub relay primitive
    # ------------------------------------------------------------------

    def _relay_frame_to_others(self, payload, source: str) -> None:
        """Hub relay: forward a chat/file frame (str) or binary chunk (bytes) to
        every member except the source. Ciphertext is forwarded untouched."""
        for dest, ch in self.data_channels.items():
            if dest in (source, self.my_username):
                continue  # never echo to the source or loop back to self
            if getattr(ch, "readyState", None) == "open":
                ch.send(payload)

    # ------------------------------------------------------------------
    # Encrypt / decrypt helpers
    # ------------------------------------------------------------------

    def _build_aad(self, sender: str, recipient: str, epoch: str = "") -> bytes:
        room_str = self.room_id or ""
        return (b"heluv1|" + sender.encode("utf-8") + b"|" +
                recipient.encode("utf-8") + b"|" + room_str.encode("utf-8") + b"|" +
                epoch.encode("utf-8"))

    def _next_send_seq(self, peer: str) -> int:
        self._send_seq[peer] = self._send_seq.get(peer, 0) + 1
        return self._send_seq[peer]

    def _check_and_update_recv_window(self, peer: str, epoch: str, seq: int) -> bool:
        if peer not in self._recv_window:
            self._recv_window[peer] = {}
        if epoch not in self._recv_window[peer]:
            self._recv_window[peer][epoch] = (0, 0)

        last_seq, mask = self._recv_window[peer][epoch]
        if seq <= 0:
            return True
        if seq > last_seq:
            diff = seq - last_seq
            if diff >= 64:
                mask = 1
            else:
                mask = ((mask << diff) | 1) & 0xFFFFFFFFFFFFFFFF
            self._recv_window[peer][epoch] = (seq, mask)
            return True
        else:
            diff = last_seq - seq
            if diff >= 64:
                return False
            if (mask & (1 << diff)) != 0:
                return False
            mask |= (1 << diff)
            self._recv_window[peer][epoch] = (last_seq, mask)
            return True

    def _decrypt_dict(self, frame: dict, peer: str) -> dict:
        if self.settings.security_mode == "e2ee" and "token" in frame:
            if self.room_id and self.group_key:
                try:
                    return paseto_decrypt(frame["token"], self.group_key)
                except Exception:
                    return {}
            key = self.session_keys.get(peer)
            if key:
                epoch = frame.get("epoch") or self._epoch_ids.get(peer, "")
                aad = self._build_aad(peer, self.my_username, epoch)
                try:
                    return paseto_decrypt(frame["token"], key, implicit_assertion=aad)
                except Exception:
                    # Do not fall back to unauthenticated legacy frames: doing so
                    # would turn the new sender/recipient/room binding into an
                    # optional property and permit a protocol downgrade.
                    return {}
        return frame

    def _decrypt_with_session(self, frame: dict, peer: str) -> dict:
        """Decrypt a per-peer frame with the 1-to-1 session key (NOT the group
        key). Used for point-to-point control like history sync, which is sent
        with _encrypt_frame_for (per-peer) even inside a room."""
        if self.settings.security_mode == "e2ee" and "token" in frame:
            key = self.session_keys.get(peer)
            if key:
                epoch = frame.get("epoch") or self._epoch_ids.get(peer, "")
                aad = self._build_aad(peer, self.my_username, epoch)
                try:
                    return paseto_decrypt(frame["token"], key, implicit_assertion=aad)
                except Exception:
                    return {}
        return frame

    def _encrypt_frame_for(self, payload: dict, peer: str, is_relay: bool = False) -> dict:
        frame = {"__type": payload["__type"]}
        if self.settings.security_mode == "e2ee":
            key = self.session_keys.get(peer)
            if key:
                epoch = self._epoch_ids.get(peer, "")
                aad = self._build_aad(self.my_username, peer, epoch)
                frame["token"] = paseto_encrypt(payload, key, implicit_assertion=aad)
                frame["epoch"] = epoch
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
        ch = self.data_channels.get(peer)
        if ch and ch.readyState == "open":
            ch.send(json.dumps({"__type": "group_key", "token": token}))

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

    async def send_chat(self, text: str, msg_id: str | None = None) -> str | None:
        """Send a 1-to-1 / room chat. For 1-to-1 returns the message id (so the
        UI can track delivery); queues to the outbox instead of failing when the
        peer isn't connected, and the id is echoed back in the delivery ``ack``."""
        if self.room_id:
            if self.settings.security_mode == "e2ee" and not self.group_key:
                self._pre_group_key_buffer.append(text)
                return None
            await self._send_group_chat(text)
            return None
        mid = msg_id or _uuid.uuid4().hex
        peer = self.target_peer
        ch = self.data_channels.get(peer)

        # 1. Direct P2P transport (promoted after 3.0s continuous stable DataChannel)
        if self.is_direct_stable(peer) and ch and getattr(ch, "readyState", None) == "open":
            seq = self._next_send_seq(peer)
            payload = {"__type": "chat", "text": text, "id": mid, "seq": seq}
            frame = self._encrypt_frame_for(payload, peer)
            try:
                ch.send(json.dumps(frame))
                self._awaiting_ack.setdefault(peer, set()).add(mid)
                return mid
            except Exception:
                pass

        # 2. Relay-First / Strict NAT fallback over signaling WebSocket
        if self._send_ws is not None and (peer in self.session_keys or self.settings.security_mode != "e2ee"):
            seq = self._next_send_seq(peer)
            payload = {"__type": "chat", "text": text, "id": mid, "seq": seq}
            frame = self._encrypt_frame_for(payload, peer, is_relay=True)
            try:
                ok = await self.send_via_relay(peer, frame)
                if ok:
                    self._awaiting_ack.setdefault(peer, set()).add(mid)
                    print(f"[chat] {peer} sent via E2EE relay (seq={seq})", flush=True)
                    return mid
            except Exception:
                pass

        # 3. Offline outbox fallback (when signaling is also down)
        self._outbox.enqueue(peer, (mid, text))
        print(f"[chat] {peer} offline - queued message (outbox={self._outbox.pending(peer)})", flush=True)
        return mid

    def peer_channel_open(self, peer: str) -> bool:
        """True if we hold an OPEN DataChannel to ``peer`` right now - lets the
        UI distinguish 'sent' from 'queued to the outbox' without reaching into
        engine internals."""
        ch = self.data_channels.get(peer)
        return bool(ch and getattr(ch, "readyState", None) == "open")

    def send_typing(self) -> None:
        """Fire a content-free composing hint to the 1-to-1 target peer.
        Best-effort: never queued, never encrypted (it carries no content),
        skipped entirely in rooms (multi-recipient typing is just noise)."""
        if self.room_id:
            return
        ch = self.data_channels.get(self.target_peer)
        if ch and getattr(ch, "readyState", None) == "open":
            try:
                ch.send(json.dumps({"__type": "__typing"}))
            except Exception:
                pass

    async def send_unverify(self, peer: str) -> None:
        """Notify peer that verification has been removed so both sides unverify in sync."""
        payload = {"__type": "unverify"}
        ch = self.data_channels.get(peer)
        if ch and getattr(ch, "readyState", None) == "open":
            try:
                ch.send(json.dumps(payload))
                return
            except Exception:
                pass
        if self._send_ws is not None:
            try:
                await self.send_via_relay(peer, payload)
            except Exception:
                pass

    async def _send_ack(self, peer: str, msg_id: str) -> None:
        frame = self._encrypt_frame_for({"__type": "ack", "id": msg_id}, peer)
        ch = self.data_channels.get(peer)
        if self.is_direct_stable(peer) and ch and getattr(ch, "readyState", None) == "open":
            try:
                ch.send(json.dumps(frame))
                return
            except Exception:
                pass
        if self._send_ws is not None:
            try:
                await self.send_via_relay(peer, frame)
            except Exception:
                pass

    async def _flush_outbox(self, peer: str) -> None:
        """Send everything queued for ``peer`` once a transport (direct or relay) is usable."""
        ch = self.data_channels.get(peer)
        is_direct = self.is_direct_stable(peer) and ch and getattr(ch, "readyState", None) == "open"
        is_relay = self._send_ws is not None and (peer in self.session_keys or self.settings.security_mode != "e2ee")
        if not (is_direct or is_relay):
            return
        for mid, text in self._outbox.drain(peer):
            seq = self._next_send_seq(peer)
            try:
                frame = self._encrypt_frame_for({"__type": "chat", "text": text, "id": mid, "seq": seq}, peer, is_relay=not is_direct)
                if is_direct and ch:
                    ch.send(json.dumps(frame))
                else:
                    await self.send_via_relay(peer, frame)
                self._awaiting_ack.setdefault(peer, set()).add(mid)
                if self.on_sent:
                    try:
                        self.on_sent(peer, mid)
                    except Exception:
                        pass
            except Exception:
                self._outbox.enqueue(peer, (mid, text))
                break

    # ------------------------------------------------------------------
    # Heartbeat (app-layer keepalive over the data channel)
    # ------------------------------------------------------------------

    def start_heartbeat(self) -> None:
        """Idempotently start the background ping loop (call once the engine has
        a running event loop - e.g. from the first connect)."""
        if self._hb_task is not None and not self._hb_task.done():
            return
        self._hb_task = self._bg(self._heartbeat_loop())

    async def _heartbeat_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(HEARTBEAT_INTERVAL_S)
                now = _time.monotonic()
                for peer, ch in list(self.data_channels.items()):
                    if getattr(ch, "readyState", None) != "open":
                        continue
                    # Seed last_pong on first sight so a fresh channel isn't
                    # instantly judged dead.
                    self._last_pong.setdefault(peer, now)
                    try:
                        ch.send(json.dumps({"__type": "__ping", "ts": _time.time() * 1000.0}))
                    except Exception:
                        pass
                    if now - self._last_pong.get(peer, now) > HEARTBEAT_DEAD_S:
                        print(f"[hb] {peer} silent > {HEARTBEAT_DEAD_S:.0f}s on an open channel - healing", flush=True)
                        self._last_pong[peer] = now   # avoid repeat-firing while healing
                        if self._send_ws is not None:
                            self._bg(self._heal_peer(peer))
            except asyncio.CancelledError:
                break
            except Exception as ex:
                print(f"[hb] loop error: {type(ex).__name__}: {ex}", flush=True)

    # ------------------------------------------------------------------
    # Peer-assisted history sync (feature E) - encrypted over the session channel
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

    async def send_file(self, path: str, target: str | None = None) -> None:
        # Stream from disk in chunks (never load the whole file into RAM) and
        # respect the channel's send-buffer so a big file can't balloon memory
        # or stall the event loop on a weak machine.
        CHUNK   = 64 * 1024
        BUF_CAP = 1 * 1024 * 1024   # pause sending above ~1 MB buffered
        peer    = target or self.target_peer
        ch = self.data_channels.get(peer)
        if not (ch and ch.readyState == "open"):
            raise RuntimeError(f"Cannot send file: not connected to {peer!r}")
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

        # Optimized trickle ICE: send offer IMMEDIATELY (without waiting for gathering)
        # so peer can start hole-punching within ~100ms. Remaining candidates trickle.
        pc = self.pcs.get(peer)
        if pc is None or pc.localDescription is None:
            return
        # Send initial offer with whatever candidates are ready (+ predicted srflx)
        aug_sdp = self._augment_local_sdp(pc.localDescription.sdp)
        await self._send_ws({
            "target": peer,
            "type":   "offer",
            "data":   {"sdp": aug_sdp, "type": "offer"},
        })
        print(f"[rtc] {self.my_username}: SENT offer to {peer} (trickle, candidates={_format_sdp_candidates(aug_sdp)})", flush=True)
        # Trickle remaining candidates in background (non-blocking, optimized polling)
        # Previous code waited 5s (100*0.05) before sending anything - that missed the
        # punch window for strict NAT. Now we trickle.
        self._bg(self._trickle_candidates(peer))

    async def _trickle_candidates(self, peer: str) -> None:
        """Send trickled ICE candidates as they appear (optimized, low CPU)."""
        try:
            pc = self.pcs.get(peer)
            if pc is None:
                return
            seen = set()
            # Initial SDP lines already sent; diff for new a=candidate lines
            last_sdp = pc.localDescription.sdp if pc.localDescription else ""
            seen.update(l for l in last_sdp.splitlines() if l.startswith("a=candidate:"))
            for _ in range(60):  # max 3s trickling
                await asyncio.sleep(0.05)
                pc = self.pcs.get(peer)
                if pc is None or pc.localDescription is None:
                    return
                if pc.iceGatheringState == "complete":
                    break
                sdp = pc.localDescription.sdp
                for line in sdp.splitlines():
                    if line.startswith("a=candidate:") and line not in seen:
                        seen.add(line)
                        # Extract candidate line without a= prefix
                        cand = line.removeprefix("a=")
                        try:
                            await self._send_ws({
                                "target": peer,
                                "type": "ice",
                                "data": {"candidate": cand, "sdpMid": "0", "sdpMLineIndex": 0}
                            })
                        except Exception:
                            pass
                if pc.iceGatheringState == "complete":
                    break
        except Exception:
            pass

    async def request_negotiation(self, peer: str) -> None:
        pc = self.pcs.get(peer)
        if (pc and getattr(pc, "signalingState", "stable") != "stable") or self._is_negotiating.get(peer):
            self._neg_dirty[peer] = True
            return
        self._is_negotiating[peer] = True
        try:
            await self._do_negotiation(peer)
        finally:
            self._is_negotiating[peer] = False
            if self._neg_dirty.get(peer) and (not pc or getattr(pc, "signalingState", "stable") == "stable"):
                self._neg_dirty.pop(peer, False)
                await self.request_negotiation(peer)

    # ------------------------------------------------------------------
    # Public API - signaling events
    # ------------------------------------------------------------------

    async def create_offer(self, target: str, ws_send: Callable) -> None:
        self.target_peer = target
        self._send_ws    = ws_send
        self._init_pc(target)
        dc = self.pcs[target].createDataChannel("chat", ordered=True)
        self.data_channels[target] = dc
        self._bind_channel(dc, target)
        self._bg(self._send_signaling_hello(target))
        await self.request_negotiation(target)

    async def handle_offer(self, sender: str, data: dict, ws_send: Callable) -> None:
        in_sdp = (data or {}).get("sdp", "")
        print(f"[rtc] {self.my_username}: RECEIVED offer from {sender} (candidates={_format_sdp_candidates(in_sdp)})", flush=True)
        self.target_peer = sender
        self._send_ws    = ws_send
        self._bg(self._send_signaling_hello(sender))
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

            ans_sdp = self._augment_local_sdp(pc.localDescription.sdp)
            await ws_send({
                "target": sender,
                "type":   "answer",
                "data":   {"sdp": ans_sdp, "type": "answer"},
            })
            print(f"[rtc] {self.my_username}: SENT answer to {sender} (candidates={_format_sdp_candidates(ans_sdp)})", flush=True)
        except Exception as ex:
            self.last_error = f"offer from {sender}: {type(ex).__name__}: {ex}"
            print(f"[rtc] {self.my_username}: handle_offer FAILED for {sender}: {type(ex).__name__}: {ex}", flush=True)

    async def handle_answer(self, data: dict, sender: str = "") -> None:
        peer = sender or self.target_peer
        in_sdp = (data or {}).get("sdp", "")
        print(f"[rtc] {self.my_username}: RECEIVED answer from {peer} (candidates={_format_sdp_candidates(in_sdp)})", flush=True)
        if peer in self.pcs:
            pc = self.pcs[peer]
            if getattr(pc, "signalingState", "") != "have-local-offer":
                print(f"[rtc] {self.my_username}: ignoring redundant answer from {peer} (state={getattr(pc, 'signalingState', None)})", flush=True)
                return
            try:
                await pc.setRemoteDescription(
                    RTCSessionDescription(sdp=data["sdp"], type="answer")
                )
                print(f"[rtc] {self.my_username}: applied answer from {peer}", flush=True)
            except Exception as ex:
                self.last_error = f"answer from {peer}: {type(ex).__name__}"
                print(f"[rtc] {self.my_username}: handle_answer FAILED for {peer}: {type(ex).__name__}: {ex}", flush=True)
                return

            if self._neg_dirty.pop(peer, False):
                await self.request_negotiation(peer)

    async def handle_ice(self, data: dict, sender: str = "") -> None:
        """Apply a trickled ICE candidate from a peer (defensive - aiortc itself
        is non-trickle, but a browser peer may send these).

        NOTE: aiortc's RTCIceCandidate has NO `candidate=` constructor kwarg;
        the old code raised TypeError on every incoming candidate. Parse the
        SDP string with aiortc's own parser instead."""
        peer = sender or self.target_peer
        pc = self.pcs.get(peer)
        if pc is None:
            return
        raw = str((data or {}).get("candidate") or "")
        if not raw:
            return  # end-of-candidates marker - nothing to add
        try:
            from aiortc.sdp import candidate_from_sdp
            sdp_str = raw.split(":", 1)[1] if raw.startswith("candidate:") else raw
            cand = candidate_from_sdp(sdp_str)
            cand.sdpMid = data.get("sdpMid")
            cand.sdpMLineIndex = data.get("sdpMLineIndex")
            await pc.addIceCandidate(cand)
            print(f"[rtc] {self.my_username}: added trickled candidate from {peer}: {cand.type} {cand.protocol} {cand.ip}:{cand.port}", flush=True)
        except Exception as ex:
            print(f"[rtc] {self.my_username}: dropping bad ICE candidate from {peer}: "
                  f"{type(ex).__name__}: {ex}", flush=True)

    # ------------------------------------------------------------------
    # Mesh peer management
    # ------------------------------------------------------------------

    async def add_peer(self, username: str, ws_send: Callable) -> None:
        self._send_ws = ws_send
        # If we already have a PC to this peer, only rebuild it when it's dead.
        # An in-progress / live connection must NOT be torn down - otherwise two
        # peers initiating at once (both selecting each other, or re-entry) would
        # keep resetting each other and never connect.
        existing = self.pcs.get(username)
        if existing is not None:
            if existing.connectionState in ("failed", "closed", "disconnected"):
                await self.remove_peer(username)
            else:
                return
        self._init_pc(username)
        # Coordinated punch for strict NAT: both sides punch simultaneously.
        # If either peer is strict (random/blocked), bypass alphabetical tie-break
        # and have BOTH create the offer after a synchronized delay via punch_at.
        is_strict = False
        try:
            if not _port_allocator.is_active and self._nat_profile and getattr(self._nat_profile, "needs_relay", False):
                is_strict = True
        except Exception:
            pass
        if is_strict:
            # Send punch sync to peer, then create offer locally after delay
            try:
                import time as _t
                fire_at = int(_t.time() * 1000) + 900
                # Send sync (non-blocking)
                self._bg(self.send_punch_at(username, ws_send, fire_at))
                # Wait locally for same fire_at (optimized: minimal sleep)
                now_ms = int(_t.time() * 1000)
                delay = punch_countdown_delay(now_ms, fire_at, min_delay=0.0)
                if delay > 0:
                    await asyncio.sleep(min(delay, 0.9))
            except Exception:
                pass
            if username not in self.pcs:
                return
            pc = self.pcs[username]
            if getattr(pc, "connectionState", None) in ("closed", "failed"):
                return
            if username not in self.data_channels:
                try:
                    dc = pc.createDataChannel("chat", ordered=True)
                    self.data_channels[username] = dc
                    self._bind_channel(dc, username)
                except Exception:
                    return
            await self.request_negotiation(username)
            return
        # Normal path: tie-break alphabetically lower username creates the data channel
        if self.my_username < username:
            if username not in self.pcs:
                return
            pc = self.pcs[username]
            if getattr(pc, "connectionState", None) in ("closed", "failed"):
                return
            if username not in self.data_channels:
                try:
                    dc = pc.createDataChannel("chat", ordered=True)
                    self.data_channels[username] = dc
                    self._bind_channel(dc, username)
                except Exception:
                    return
            await self.request_negotiation(username)
        # else: wait for incoming offer from the other peer

    async def _relay_track_to_others(self, source_peer: str, track) -> None:
        """Hub SFU fan-out: re-publish source_peer's track to every other member,
        labeling each forwarded track with its true origin over the data channel."""
        for dest, pc in list(self.pcs.items()):
            if dest == source_peer:
                continue
            # Peer may have been removed while we awaited in a previous iteration.
            if dest not in self.pcs:
                continue
            sub = self._relay.subscribe(track)
            pc.addTrack(sub)
            # Broadcast sub.id (what the receiver sees), NOT the source track.id -
            # relay.subscribe() assigns a new id (confirmed by spike).
            self._forwarded.setdefault(source_peer, []).append((dest, sub, sub.id, track.id))
            ch = self.data_channels.get(dest)
            if ch and getattr(ch, "readyState", None) == "open":
                ch.send(json.dumps({"__type": "track_origin",
                                    "track_id": sub.id, "origin": source_peer,
                                    "kind": sub.kind}))
            # Guard again: request_negotiation yields internally; peer could
            # be removed during those yields (the old pcs[peer] access was the
            # crash site in the traceback).
            if dest in self.pcs:
                await self.request_negotiation(dest)

    async def _relay_existing_tracks_to(self, dest: str) -> None:
        """Hub late-joiner fan-out: forward every still-live incoming track from
        other members to `dest` (a peer that just became session-ready). Without
        this, someone joining MID-call/share never receives the ongoing media -
        the original _relay_track_to_others only runs at track-receipt time."""
        if not (self.room_id and self.current_hub() == self.my_username):
            return
        pc = self.pcs.get(dest)
        if pc is None:
            return
        added = False
        for source, tracks in list(self._live_tracks.items()):
            if source == dest:
                continue
            already = {
                (e[0], e[3]) for e in self._forwarded.get(source, []) if len(e) > 3
            }
            for track in list(tracks):
                if getattr(track, "readyState", "live") != "live":
                    continue
                if (dest, track.id) in already:
                    continue  # this track is already being forwarded to dest
                # Re-check after every await-bearing step - peers can vanish.
                if dest not in self.pcs:
                    return
                sub = self._relay.subscribe(track)
                pc.addTrack(sub)
                self._forwarded.setdefault(source, []).append((dest, sub, sub.id, track.id))
                ch = self.data_channels.get(dest)
                if ch and getattr(ch, "readyState", None) == "open":
                    try:
                        ch.send(json.dumps({"__type": "track_origin",
                                            "track_id": sub.id, "origin": source,
                                            "kind": sub.kind}))
                    except Exception:
                        pass
                added = True
                print(f"[rtc] {self.my_username}: late-joiner relay {source}->{dest} ({sub.kind})", flush=True)
        if added and dest in self.pcs:
            await self.request_negotiation(dest)

    async def remove_peer(self, username: str, keep_session: bool = False) -> None:
        pc = self.pcs.pop(username, None)
        if pc:
            _port_allocator.release(id(pc))
            try:
                await pc.close()
            except Exception:
                pass
        self._direct_stable_since.pop(username, None)
        self.data_channels.pop(username, None)
        if not keep_session:
            self._signaling_hello_sent.pop(username, None)
            self._epoch_ids.pop(username, None)
            self._send_seq.pop(username, None)
            self._recv_window.pop(username, None)
            self.session_keys.pop(username, None)
            self._hello_sent.pop(username, None)
            self._peer_hello_verified.pop(username, None)
            self._eph_priv.pop(username, None)
            self._pre_hello_buffers.pop(username, None)
            self._pre_hello_bytes.pop(username, None)
        self._is_negotiating.pop(username, None)
        self._neg_dirty.pop(username, None)
        file_states = self._file_buffers.pop(username, {})
        for state in file_states.values():
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
        self._live_tracks.pop(username, None)
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
        # Heartbeat / delivery bookkeeping for a gone peer. NOTE: the outbox is
        # deliberately NOT cleared - queued messages must survive a disconnect
        # and flush when the peer reconnects.
        self._last_pong.pop(username, None)
        self._rtt_ms.pop(username, None)
        self._awaiting_ack.pop(username, None)
        # Release shared capture devices / mixer if no peers need them anymore
        self._teardown_media_if_idle()

        # Creator-leaves key handoff: am I now the alphabetically lowest peer?
        if self.room_id and not self.is_room_creator:
            # Filter stale PCs (closed/failed) to avoid electing a zombie as creator
            alive_peers = [
                p for p, pc in self.pcs.items()
                if pc.connectionState not in ("closed", "failed")
            ]
            remaining = sorted(alive_peers + [self.my_username])
            if remaining and remaining[0] == self.my_username:
                self.is_room_creator = True
                self._room_creator_name = self.my_username
                if self.group_key is None:
                    # Orphaned: the original creator left before we ever received
                    # the group key. Establish a fresh key and distribute it so
                    # the survivors can keep talking (and any stuck buffer flushes).
                    self.group_key = os.urandom(32)
                    for p in self.pcs:
                        if p in self.session_keys:
                            await self._send_group_key_to(p)
                await self._flush_group_buffer()

    DISCONNECT_GRACE_SECONDS = 12.0

    async def _watch_disconnected(self, peer: str, pc) -> None:
        """If `pc` is still 'disconnected' after the grace window, treat it as
        failed and self-heal (re-offer over signaling) instead of hanging."""
        await asyncio.sleep(self.DISCONNECT_GRACE_SECONDS)
        # The PC may have been replaced/removed while we slept.
        if self.pcs.get(peer) is not pc:
            return
        if pc.connectionState != "disconnected":
            return  # recovered (or moved to failed/closed and was handled there)
        print(f"[rtc] {self.my_username}: {peer} stuck in 'disconnected' for "
              f"{self.DISCONNECT_GRACE_SECONDS:.0f}s - treating as failed", flush=True)
        if self._send_ws is not None:
            await self._heal_peer(peer)
        else:
            await self.remove_peer(peer)

    async def _heal_peer(self, peer: str) -> None:
        """Remove a failed PC, then re-initiate the connection over the still-live
        signaling channel. For rooms, topology reconciliation takes over once the
        client's on_state_change callback fires; for 1-to-1 we call add_peer directly."""
        attempts = getattr(self, "_heal_attempts", {}).get(peer, 0)
        last_heal = getattr(self, "_last_heal_time", {}).get(peer, 0.0)
        now = _time.monotonic()
        if now - last_heal > 60.0:
            attempts = 0
        if attempts >= 2:
            print(f"[rtc] {self.my_username}: max self-heal attempts reached for {peer} - keeping signaling relay fallback", flush=True)
            await self.remove_peer(peer, keep_session=True)
            return

        if not hasattr(self, "_heal_attempts"):
            self._heal_attempts = {}
            self._last_heal_time = {}
        self._heal_attempts[peer] = attempts + 1
        self._last_heal_time[peer] = now

        print(f"[rtc] {self.my_username}: self-healing {peer} (attempt {attempts + 1}/2)", flush=True)
        await self.remove_peer(peer, keep_session=True)
        if self._send_ws is None or peer in self.pcs:
            return
        # Brief backoff pause so both sides complete their cleanup before re-initiating
        await asyncio.sleep(2.0 * (attempts + 1))
        if peer in self.pcs:
            return
        if not self.room_id:
            try:
                await self.add_peer(peer, self._send_ws)
                print(f"[rtc] {self.my_username}: re-initiated connection to {peer}", flush=True)
            except Exception as ex:
                print(f"[rtc] {self.my_username}: heal re-add failed for {peer}: {ex}", flush=True)
        # Room case: on_state_change already fired → client's _on_topology_changed
        # will call reconcile_room_connections, which handles hub reconnection.

    async def _prune_dead_non_hub_peers(self, hub: str) -> None:
        for peer in list(self.pcs.keys()):
            if peer != hub:
                pc = self.pcs.get(peer)
                if pc and pc.connectionState in ("failed", "closed", "disconnected"):
                    await self.remove_peer(peer)

    async def reconcile_room_connections(self, _members: list, ws_send) -> None:
        """Star topology: non-hub connects only to the hub; the hub waits for offers."""
        self._send_ws = ws_send
        hub = self.current_hub()
        if hub == self.my_username:
            return  # hub is a pure responder; it answers incoming offers

        # Phase 1: always clean up dead connections regardless of hub status.
        await self._prune_dead_non_hub_peers(hub)

        # Phase 2: initiate a connection to the hub if we don't have one yet.
        if hub and hub != self.my_username and hub not in self.pcs:
            await self.create_offer(hub, ws_send)

        # Phase 3: only prune WORKING non-hub connections once the hub link is
        # confirmed up. Dropping them speculatively leaves the user with NO
        # connection if the new hub is unreachable (failed ICE, behind symmetric
        # NAT, etc.) - the old working connection is then unrecoverable.
        hub_pc = self.pcs.get(hub)
        if hub_pc and hub_pc.connectionState == "connected":
            for peer in list(self.pcs.keys()):
                if peer != hub:
                    await self.remove_peer(peer)

    # ------------------------------------------------------------------
    # Voice / screen
    # ------------------------------------------------------------------

    def _get_mic_source(self) -> "MicrophoneTrack":
        # One real microphone capture, shared across every peer via the relay.
        # Mic starts active (audio flows immediately); the UI exposes a mute toggle.
        if self._mic_source is None:
            self._mic_source = MicrophoneTrack(
                push_to_talk=False,
                mic_gain=getattr(self.settings, "mic_gain", 1.0),
                noise_reduce=getattr(self.settings, "noise_reduce", False),
                noise_reduce_stationary=getattr(self.settings, "noise_reduce_stationary", True),
            )
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

    async def start_voice_call(self, peer: str | None = None, ring: bool = True) -> None:
        """Add our mic to the call with `peer`. `ring=True` means we are the one
        STARTING the call, so notify them (call_start → their phone rings).
        `ring=False` is used when ANSWERING - we add our mic but must NOT ring the
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
                # Channel not open yet - defer the ring so the callee isn't missed.
                self._pending_call_start.add(p)
                print(f"[rtc] {self.my_username}: call_start to {p} deferred (channel not open)", flush=True)
        # aiortc won't auto-negotiate the added track - re-offer explicitly.
        # If we are the callee (ring=False), we only initiate renegotiation if we've already
        # applied the caller's offer (meaning we have a remote audio track). Otherwise, we wait
        # for their offer to arrive, and our answer will automatically negotiate both tracks.
        has_remote_audio = any(r.track and r.track.kind == "audio" for r in self.pcs[p].getReceivers())
        if ring or has_remote_audio:
            await self.request_negotiation(p)

    async def start_screen_share(self, peer: str | None = None) -> None:
        # Screen share is VIDEO ONLY and independent of voice. To talk while
        # sharing, also start a voice call - the two streams are decoupled so one
        # never cuts the other out (and sharing won't silently hot-mic you).
        p = peer or self.target_peer
        if p not in self.pcs or p in self._screen_peers:
            return
        screen = self._get_screen_source()
        self._screen_senders[p] = self.pcs[p].addTrack(self._relay.subscribe(screen))
        self._screen_peers.add(p)
        await self.request_negotiation(p)

    async def stop_screen_share(self, peer: str | None = None) -> None:
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
            ch = self.data_channels.get(p)
            if ch and ch.readyState == "open":
                try:
                    ch.send(json.dumps({"__type": "screen_share_ended"}))
                except Exception:
                    pass
            await self.request_negotiation(p)

    def accept_call(self, peer: str | None = None) -> None:
        p  = peer or self.target_peer
        ch = self.data_channels.get(p)
        if ch and ch.readyState == "open":
            try:
                ch.send(json.dumps({"__type": "call_accept"}))
            except Exception as ex:
                print(f"[rtc] {self.my_username}: call_accept to {p} failed: {ex}", flush=True)
        # We are ANSWERING: add our mic but don't ring the caller back.
        task = asyncio.ensure_future(self.start_voice_call(p, ring=False))
        def call_done(t):
            try:
                t.result()
            except Exception as ex:
                self.last_error = f"Audio capture error: {ex}"
                if self.on_state_change:
                    self.on_state_change(p, "failed")
        task.add_done_callback(call_done)

    def reject_call(self, peer: str | None = None) -> None:
        p  = peer or self.target_peer
        ch = self.data_channels.get(p)
        if ch and ch.readyState == "open":
            try:
                ch.send(json.dumps({"__type": "call_reject"}))
            except Exception as ex:
                print(f"[rtc] {self.my_username}: call_reject to {p} failed: {ex}", flush=True)

    def hangup(self, peer: str | None = None) -> None:
        # Local hangup: notify the peer(s) AND tear down our own call media.
        targets = [peer] if peer else list(self.data_channels.keys())
        for p in targets:
            ch = self.data_channels.get(p)
            if ch and ch.readyState == "open":
                ch.send(json.dumps({"__type": "hangup"}))
            self._end_call_local(p)

    def end_call_from_peer(self, peer: str) -> None:
        # The remote side hung up - tear down our side WITHOUT echoing a hangup.
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
            for peer in self._play_chunks:
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
        # Apply the live, user-adjustable playback gain, then clip to int16.
        boosted = mix.astype(np.float32) * float(self._volume)
        np.clip(boosted, -32768, 32767, out=boosted)
        outdata[:, 0] = boosted.astype(np.int16)

    def set_volume(self, factor: float) -> None:
        """Set the call playback gain (applied live in the audio thread)."""
        try:
            self._volume = max(0.0, float(factor))
        except (TypeError, ValueError):
            pass

    def _ensure_output_stream(self) -> None:
        if self._output_stream is None:
            try:
                self._output_stream = sd.OutputStream(
                    samplerate=48000, channels=1, dtype="int16",
                    blocksize=960, callback=self._play_callback,
                )
                self._output_stream.start()
            except Exception as ex:
                self.last_error = f"Audio output error: {ex}"
                print(f"[rtc] Failed to open audio output stream: {ex}", flush=True)
                raise

    async def _handle_incoming_audio(self, track, peer: str) -> None:
        MAX_BUFFERED = 48000   # ~1 s @ 48 kHz; drop oldest beyond this
        key = await self._resolve_origin(track.id, peer)
        self._incoming_audio_active.add(key)
        with self._play_lock:
            self._play_chunks[key] = deque()
        try:
            self._ensure_output_stream()
        except Exception:
            self._incoming_audio_active.discard(key)
            with self._play_lock:
                self._play_chunks.pop(key, None)
            return

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
        from aiortc.mediastreams import MediaStreamError
        print(f"[screen] {self.my_username}: receiving video track from {peer}", flush=True)
        origin = await self._resolve_origin(track.id, peer)
        q: asyncio.Queue = asyncio.Queue(maxsize=2)
        got_frame = False  # local to this call - avoids clobbering across concurrent tracks

        async def fetch():
            nonlocal got_frame
            while True:
                try:
                    frame = await track.recv()
                    img   = frame.to_ndarray(format="bgr24")
                    if not got_frame:
                        print(f"[screen] {self.my_username}: first frame from {peer} (origin={origin}) {img.shape[1]}x{img.shape[0]}", flush=True)
                        got_frame = True
                    if q.full():
                        try:
                            q.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                    await q.put(img)
                except MediaStreamError:
                    break  # track ended cleanly - fall through to sentinel
                except Exception as ex:
                    # Transient error (decode glitch, buffer underrun) - log and
                    # retry instead of killing the whole stream.
                    print(f"[screen] {self.my_username}: frame error from {peer}: {type(ex).__name__}", flush=True)
                    await asyncio.sleep(0.05)
            # Track ended: signal the consumer so the UI tears down immediately.
            try:
                await asyncio.wait_for(q.put(None), timeout=1.0)
            except Exception:
                pass

        fetch_task = asyncio.ensure_future(fetch())
        try:
            while True:
                try:
                    img = await asyncio.wait_for(q.get(), timeout=5.0)
                except TimeoutError:
                    continue
                except Exception:
                    break
                if img is None:        # end-of-track sentinel
                    break
                if self.on_video_frame:
                    self.on_video_frame(origin, img)
        finally:
            fetch_task.cancel()  # stop producer if consumer exits first (no zombie tasks)
            # Always notify the UI that this peer's screen stream is gone, so a
            # stale frame can never linger after sharing stops / the call ends.
            print(f"[screen] {self.my_username}: video track from {origin} ended", flush=True)
            if self.on_video_end:
                self.on_video_end(origin)
