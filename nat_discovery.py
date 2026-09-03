"""NAT behaviour discovery + port prediction (RFC 5780 / RFC 8489).

Pure-stdlib STUN client - no aioice/aiortc dependency, so it runs before the
WebRTC engine starts and on any thread. It answers two questions that decide
which traversal strategy can work:

  1. **Mapping behaviour** - does the NAT reuse the same external port for every
     destination (endpoint-independent → STUN works) or assign a new one per
     destination (address/port-dependent → "symmetric" → STUN alone fails)?
  2. **Port-allocation pattern** - when the mapping IS per-destination, are the
     external ports sequential (predictable: next ≈ last + delta) or random?

From those we classify the NAT and, for the sequential-symmetric case, predict
the external port the NAT will assign to the *next* new destination - which a
caller can inject as an extra srflx candidate (see ``predicted_srflx_line`` in
webrtc_engine) to punch a symmetric NAT WITHOUT a relay.

Everything is best-effort and fully timeout-bounded: a blocked/silent network
yields ``UNKNOWN`` rather than hanging.
"""
from __future__ import annotations

import secrets
import socket
import struct
from dataclasses import dataclass, field

# Public STUN servers that expose a SECONDARY address/port (needed for the
# RFC 5780 mapping tests, which must be probed from two different server IPs).
# We resolve A records ourselves so we can talk to two distinct server IPs.
DEFAULT_STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]

_MAGIC_COOKIE = 0x2112A442
_BINDING_REQUEST = 0x0001
_BINDING_SUCCESS = 0x0101
_ATTR_MAPPED_ADDRESS = 0x0001
_ATTR_XOR_MAPPED_ADDRESS = 0x0020

# NAT classifications.
OPEN_INTERNET = "open-internet"          # public IP, no NAT
ENDPOINT_INDEPENDENT = "endpoint-independent"   # full/restricted cone - STUN works
SEQUENTIAL_SYMMETRIC = "sequential-symmetric"   # per-dest port, but predictable
RANDOM_SYMMETRIC = "random-symmetric"    # per-dest random port - needs relay
BLOCKED = "blocked"                      # no STUN reachable at all
UNKNOWN = "unknown"


@dataclass
class StunResult:
    ok: bool
    ext_ip: str = ""
    ext_port: int = 0
    local_port: int = 0
    error: str = ""


@dataclass
class NatProfile:
    nat_type: str = UNKNOWN
    ext_ip: str = ""
    # Observed (local_port -> external_port) samples used for the analysis.
    samples: list = field(default_factory=list)
    # Mean per-binding port delta for sequential NATs (0 for cone/random).
    port_delta: int = 0
    # True when port prediction is meaningful for this NAT.
    predictable: bool = False

    @property
    def needs_relay(self) -> bool:
        """Direct/hole-punch traversal is hopeless → must relay (TURN or the
        app's signaling-relay fallback)."""
        return self.nat_type in (RANDOM_SYMMETRIC, BLOCKED)

    @property
    def summary(self) -> str:
        if self.nat_type == OPEN_INTERNET:
            return "Open / no NAT - direct works"
        if self.nat_type == ENDPOINT_INDEPENDENT:
            return "Cone NAT - STUN hole-punch works"
        if self.nat_type == SEQUENTIAL_SYMMETRIC:
            return f"Symmetric NAT, sequential ports (Δ≈{self.port_delta}) - prediction possible"
        if self.nat_type == RANDOM_SYMMETRIC:
            return "Symmetric NAT, random ports - relay required"
        if self.nat_type == BLOCKED:
            return "STUN blocked - relay required"
        return "Unknown"


# ---------------------------------------------------------------------------
# STUN wire format (minimal, RFC 8489)
# ---------------------------------------------------------------------------

def _build_binding_request() -> tuple[bytes, bytes]:
    txid = secrets.token_bytes(12)
    header = struct.pack("!HHI12s", _BINDING_REQUEST, 0, _MAGIC_COOKIE, txid)
    return header, txid


def _parse_mapped_address(data: bytes, txid: bytes) -> tuple[str, int] | None:
    if len(data) < 20:
        return None
    msg_type, msg_len, cookie, rtxid = struct.unpack("!HHI12s", data[:20])
    if msg_type != _BINDING_SUCCESS or rtxid != txid:
        return None
    off = 20
    end = 20 + msg_len
    xor = None
    plain = None
    while off + 4 <= end and off + 4 <= len(data):
        atype, alen = struct.unpack("!HH", data[off:off + 4])
        val = data[off + 4:off + 4 + alen]
        if atype == _ATTR_XOR_MAPPED_ADDRESS and len(val) >= 8:
            xor = _decode_xor_mapped(val, txid)
        elif atype == _ATTR_MAPPED_ADDRESS and len(val) >= 8:
            plain = _decode_plain_mapped(val)
        off += 4 + alen + ((4 - alen % 4) % 4)   # 32-bit alignment padding
    return xor or plain


def _decode_xor_mapped(val: bytes, txid: bytes) -> tuple[str, int] | None:
    family = val[1]
    xport = struct.unpack("!H", val[2:4])[0] ^ (_MAGIC_COOKIE >> 16)
    if family == 0x01:  # IPv4
        xip = struct.unpack("!I", val[4:8])[0] ^ _MAGIC_COOKIE
        ip = socket.inet_ntoa(struct.pack("!I", xip))
        return ip, xport
    if family == 0x02:  # IPv6
        cookie_txid = struct.pack("!I", _MAGIC_COOKIE) + txid
        raw = bytes(b ^ c for b, c in zip(val[4:20], cookie_txid))
        return socket.inet_ntop(socket.AF_INET6, raw), xport
    return None


def _decode_plain_mapped(val: bytes) -> tuple[str, int] | None:
    family = val[1]
    port = struct.unpack("!H", val[2:4])[0]
    if family == 0x01:
        return socket.inet_ntoa(val[4:8]), port
    if family == 0x02:
        return socket.inet_ntop(socket.AF_INET6, val[4:20]), port
    return None


def _stun_query(sock: socket.socket, server: tuple[str, int],
                timeout: float = 2.0) -> StunResult:
    """Send one BINDING request on ``sock`` to ``server`` and parse the reply."""
    header, txid = _build_binding_request()
    try:
        sock.settimeout(timeout)
        sock.sendto(header, server)
        data, _ = sock.recvfrom(512)
    except (socket.timeout, OSError) as ex:
        return StunResult(ok=False, error=type(ex).__name__)
    parsed = _parse_mapped_address(data, txid)
    if parsed is None:
        return StunResult(ok=False, error="no-mapped-address")
    ip, port = parsed
    try:
        local_port = sock.getsockname()[1]
    except OSError:
        local_port = 0
    return StunResult(ok=True, ext_ip=ip, ext_port=port, local_port=local_port)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _resolve(servers: list[tuple[str, int]]) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    seen: set[str] = set()
    for host, port in servers:
        try:
            # Optimized: getaddrinfo for dual-stack (IPv4+IPv6), fallback to gethostbyname
            try:
                infos = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_DGRAM)
                for fam, _, _, _, sockaddr in infos:
                    ip = sockaddr[0]
                    if ip not in seen:
                        seen.add(ip)
                        out.append((ip, port))
                    if len(out) >= 6:  # keep fast
                        break
            except Exception:
                ip = socket.gethostbyname(host)
                if ip not in seen:
                    seen.add(ip)
                    out.append((ip, port))
        except OSError:
            continue
        if len(out) >= 6:
            break
    return out


def _local_ipv4() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        try:
            s.connect(("8.8.8.8", 53))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def discover(servers: list[tuple[str, int]] | None = None,
             timeout: float = 2.0) -> NatProfile:
    """Probe several STUN servers from FRESH sockets and classify the NAT.

    Each probe uses a new unbound UDP socket so the OS assigns a new local port
    - that is exactly what forces the NAT to create a *new* mapping per probe,
    which is what lets us observe whether the external port is stable (cone),
    sequential (predictable symmetric) or random (relay-only).
    """
    resolved = _resolve(servers or DEFAULT_STUN_SERVERS)
    if len(resolved) < 1:
        return NatProfile(nat_type=BLOCKED)

    samples: list[tuple[int, int]] = []   # (local_port, external_port)
    ext_ip = ""
    ext_ports_per_server: list[int] = []
    local_ip = _local_ipv4()

    for server in resolved:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            res = _stun_query(sock, server, timeout)
        finally:
            sock.close()
        if not res.ok:
            continue
        ext_ip = res.ext_ip
        samples.append((res.local_port, res.ext_port))
        ext_ports_per_server.append(res.ext_port)

    if not samples:
        return NatProfile(nat_type=BLOCKED)

    profile = NatProfile(ext_ip=ext_ip, samples=samples)

    # No NAT: the external IP equals our local IP and the port was preserved.
    if local_ip and ext_ip == local_ip:
        profile.nat_type = OPEN_INTERNET
        return profile

    # One probe only - can't tell mapping behaviour; assume cone (optimistic,
    # the real ICE run will still try and fall back to relay if it fails).
    if len(ext_ports_per_server) < 2:
        profile.nat_type = ENDPOINT_INDEPENDENT
        return profile

    # Endpoint-independent (cone) NAT: SAME external port to different servers.
    if len(set(ext_ports_per_server)) == 1:
        profile.nat_type = ENDPOINT_INDEPENDENT
        return profile

    # Different external port per destination → symmetric. Classify the pattern.
    return _classify_symmetric(profile, ext_ports_per_server)


def _classify_symmetric(profile: NatProfile, ext_ports: list[int]) -> NatProfile:
    """Decide sequential vs random from the spread of observed external ports."""
    ordered = sorted(ext_ports)
    deltas = [b - a for a, b in zip(ordered, ordered[1:])]
    if not deltas:
        profile.nat_type = RANDOM_SYMMETRIC
        return profile
    max_delta = max(deltas)
    mean_delta = round(sum(deltas) / len(deltas))
    # Tight, small, positive deltas → sequential allocator (predictable).
    if 1 <= max_delta <= 16:
        profile.nat_type = SEQUENTIAL_SYMMETRIC
        profile.port_delta = max(1, mean_delta)
        profile.predictable = True
    else:
        profile.nat_type = RANDOM_SYMMETRIC
    return profile


def predict_next_port(profile: NatProfile, lookahead: int = 1) -> int | None:
    """Predict the external port the NAT will assign to the NEXT new mapping.

    Only meaningful for SEQUENTIAL_SYMMETRIC. Returns a port in 1024..65535 or
    None. ``lookahead`` lets a caller emit a few candidates (next, next+Δ, …)
    to hedge against intervening allocations by other apps.
    """
    if not profile.predictable or not profile.samples:
        return None
    last_ext = max(p for _, p in profile.samples)
    predicted = last_ext + profile.port_delta * lookahead
    if 1024 <= predicted <= 65535:
        return predicted
    return None
