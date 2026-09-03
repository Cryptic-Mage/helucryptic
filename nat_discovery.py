"""NAT behaviour discovery + port prediction (RFC 5780 / RFC 8489 / RFC 5389).

Pure-stdlib STUN client - no aioice/aiortc dependency, so it runs before the
WebRTC engine starts and on any thread. It evaluates NAT mapping behavior using
a 3-probe test from a single bound UDP socket:

  Probe 1: (IP_A, Port_1) - primary server, primary port
  Probe 2: (IP_B, Port_1) - secondary distinct IP, primary port
  Probe 3: (IP_A, Port_2) - primary server, secondary port

Advisory Telemetry Note:
  This classification strictly characterizes the mapping behavior observed on
  the specific UDP socket bound by this module. aiortc/aioice creates and binds
  its own sockets for ICE gathering; thus, this classification is advisory
  telemetry rather than an invariant guarantee for aiortc's ephemeral ports.

Retransmissions & Timeouts:
  Uses RFC 5389 binary exponential backoff (initial RTO 500 ms, doubling) capped
  at 3 attempts (t = 0 ms, 500 ms, 1500 ms) and a hard cap of 2.5 s per probe.
  This is an intentional UX-bounded deviation from RFC 5389's Rc=7 (63 s) to
  prevent UI and event loop stalls.
"""
from __future__ import annotations

import itertools
import secrets
import socket
import struct
import time
from dataclasses import dataclass, field

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

# RFC 5780 NAT Mapping Classifications
OPEN_INTERNET = "open-internet"
ENDPOINT_INDEPENDENT = "endpoint-independent"
ADDRESS_DEPENDENT = "address-dependent"
ADDRESS_AND_PORT_DEPENDENT = "address-and-port-dependent"
BLOCKED = "blocked"
UNKNOWN = "unknown"

# Backward compatibility aliases
SEQUENTIAL_SYMMETRIC = "sequential-symmetric"
RANDOM_SYMMETRIC = "random-symmetric"


@dataclass
class StunResult:
    ok: bool
    ext_ip: str = ""
    ext_port: int = 0
    local_port: int = 0
    error: str = ""


@dataclass
class NatProfile:
    mapping_behavior: str = UNKNOWN
    ext_ip: str = ""
    samples: list = field(default_factory=list)
    port_delta: int = 0
    predictable: bool = False
    is_cgnat: bool = False

    @property
    def nat_type(self) -> str:
        """Backward-compatibility mapping to legacy nat_type strings."""
        if self.mapping_behavior == ADDRESS_AND_PORT_DEPENDENT:
            return SEQUENTIAL_SYMMETRIC if self.predictable else RANDOM_SYMMETRIC
        return self.mapping_behavior

    @nat_type.setter
    def nat_type(self, val: str) -> None:
        if val in (SEQUENTIAL_SYMMETRIC, RANDOM_SYMMETRIC):
            self.mapping_behavior = ADDRESS_AND_PORT_DEPENDENT
            self.predictable = (val == SEQUENTIAL_SYMMETRIC)
        else:
            self.mapping_behavior = val

    @property
    def needs_relay(self) -> bool:
        """True when direct/hole-punch traversal is statistically hopeless.

        Note: CGNAT alone does not imply needs_relay if mapping is endpoint-independent;
        mobile hole-punching succeeds regularly on cone CGNATs. However, CGNAT +
        address-and-port-dependent mapping makes direct traversal hopeless.
        """
        if self.mapping_behavior in (RANDOM_SYMMETRIC, BLOCKED):
            return True
        if self.mapping_behavior == ADDRESS_AND_PORT_DEPENDENT and not self.predictable:
            return True
        return bool(self.is_cgnat and self.mapping_behavior == ADDRESS_AND_PORT_DEPENDENT)

    @property
    def summary(self) -> str:
        prefix = "[CGNAT] " if self.is_cgnat else ""
        if self.mapping_behavior == OPEN_INTERNET:
            return f"{prefix}Open / no NAT - direct works"
        if self.mapping_behavior == ENDPOINT_INDEPENDENT:
            return f"{prefix}Cone NAT (Endpoint-Independent) - STUN hole-punch works"
        if self.mapping_behavior == ADDRESS_DEPENDENT:
            return f"{prefix}Address-Dependent NAT - simultaneous punch required"
        if self.mapping_behavior == ADDRESS_AND_PORT_DEPENDENT:
            if self.predictable:
                return f"{prefix}Symmetric NAT (Δ≈{self.port_delta}) - prediction possible"
            return f"{prefix}Symmetric NAT (random ports) - relay required"
        if self.mapping_behavior == BLOCKED:
            return "STUN blocked - relay required"
        return "Unknown"


# ---------------------------------------------------------------------------
# STUN wire format (RFC 8489)
# ---------------------------------------------------------------------------

def _build_binding_request() -> tuple[bytes, bytes]:
    txid = secrets.token_bytes(12)
    header = struct.pack("!HHI12s", _BINDING_REQUEST, 0, _MAGIC_COOKIE, txid)
    return header, txid


def _parse_mapped_address(data: bytes, txid: bytes) -> tuple[str, int] | None:
    if len(data) < 20:
        return None
    msg_type, msg_len, _cookie, rtxid = struct.unpack("!HHI12s", data[:20])
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
        off += 4 + alen + ((4 - alen % 4) % 4)
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


def _stun_query_with_retry(
    sock: socket.socket,
    server: tuple[str, int],
    initial_rto: float = 0.5,
    max_attempts: int = 3,
    hard_cap: float = 2.5,
) -> StunResult:
    """Send BINDING requests on ``sock`` with UX-bounded exponential backoff.

    Deviates intentionally from RFC 5389 Rc=7 (which would wait 63 s) to prevent
    blocking the UI or asyncio loop.
    """
    header, txid = _build_binding_request()
    rto = initial_rto
    start_time = time.monotonic()

    for _ in range(max_attempts):
        time_left = hard_cap - (time.monotonic() - start_time)
        if time_left <= 0:
            break
        sock.settimeout(min(rto, time_left))
        try:
            sock.sendto(header, server)
            data, _ = sock.recvfrom(512)
            parsed = _parse_mapped_address(data, txid)
            if parsed is not None:
                ip, port = parsed
                try:
                    local_port = sock.getsockname()[1]
                except OSError:
                    local_port = 0
                return StunResult(ok=True, ext_ip=ip, ext_port=port, local_port=local_port)
        except (TimeoutError, OSError):
            rto *= 2.0
            continue

    return StunResult(ok=False, error="timeout")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _resolve_deduped(servers: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """Resolve STUN hostnames and deduplicate by IP to eliminate anycast aliasing."""
    out: list[tuple[str, int]] = []
    seen_ips: set[str] = set()
    for host, port in servers:
        try:
            infos = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM)
            for _, _, _, _, sockaddr in infos:
                ip = sockaddr[0]
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    out.append((ip, port))
                if len(out) >= 6:
                    break
        except OSError:
            try:
                ip = socket.gethostbyname(host)
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    out.append((ip, port))
            except OSError:
                continue
        if len(out) >= 6:
            break
    return out


def is_cgnat_ip(ip_str: str) -> bool:
    """Check if an IPv4 address is in RFC 6598 Shared Address Space (100.64.0.0/10)."""
    try:
        parts = [int(p) for p in ip_str.split(".")]
        if len(parts) == 4 and parts[0] == 100 and (64 <= parts[1] <= 127):
            return True
    except Exception:
        pass
    return False


def _check_cgnat(ext_ip: str) -> bool:
    """Detect CGNAT by checking RFC 6598 ranges and UPnP router WAN mismatch."""
    if is_cgnat_ip(ext_ip):
        return True

    # Check local interface addresses for 100.64.0.0/10
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        local_ip = s.getsockname()[0]
        s.close()
        if is_cgnat_ip(local_ip):
            return True
    except Exception:
        pass

    # Check UPnP router WAN address vs STUN mapped IP
    try:
        import upnp
        igd_locations = upnp._ssdp_discover(timeout=0.6)
        if igd_locations:
            ctrl = upnp._get_igd_control_url(igd_locations[0], timeout=0.6)
            if ctrl:
                control_url, service_type = ctrl
                if not service_type:
                    service_type = "urn:schemas-upnp-org:service:WANIPConnection:1"
                import re
                import urllib.request
                body = f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddress xmlns:u="{service_type}"/></s:Body></s:Envelope>'
                headers = {"Content-Type": "text/xml", "SOAPAction": f'"{service_type}#GetExternalIPAddress"'}
                req = urllib.request.Request(control_url, data=body.encode(), headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=1.0) as resp:
                    xml = resp.read().decode(errors="ignore")
                    m = re.search(r"<NewExternalIPAddress>([^<]+)</", xml)
                    if m:
                        wan_ip = m.group(1).strip()
                        if is_cgnat_ip(wan_ip):
                            return True
                        if wan_ip and ext_ip and wan_ip != ext_ip and not wan_ip.startswith(("192.168.", "10.", "172.")):
                            # Router WAN is a non-RFC1918 address that differs from STUN public IP -> Carrier NAT
                            return True
    except Exception:
        pass

    return False


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
    """Evaluate NAT mapping behavior using a 3-probe test on a single bound UDP socket.

    Probes:
      Probe 1: (IP_A, Port_1) - primary server, primary port
      Probe 2: (IP_B, Port_1) - secondary distinct IP, primary port
      Probe 3: (IP_A, Port_2) - primary server, secondary port (e.g. 3479 or Port_1 + 1)
    """
    resolved = _resolve_deduped(servers or DEFAULT_STUN_SERVERS)
    if len(resolved) < 1:
        return NatProfile(mapping_behavior=BLOCKED)

    ip_a, port_a = resolved[0]
    # Find a second distinct IP if available
    ip_b = None
    port_b = port_a
    for ip, p in resolved[1:]:
        if ip != ip_a:
            ip_b = ip
            port_b = p
            break

    # Secondary port on primary IP (RFC 5780 alternate port test)
    port_a_alt = 3479 if port_a == 3478 else (port_a + 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", 0))
    except OSError:
        return NatProfile(mapping_behavior=BLOCKED)

    samples: list[tuple[int, int]] = []
    p1: StunResult | None = None
    p2: StunResult | None = None
    p3: StunResult | None = None

    try:
        # Probe 1: Primary IP, Primary Port
        p1 = _stun_query_with_retry(sock, (ip_a, port_a), initial_rto=0.4, max_attempts=3, hard_cap=timeout)
        if not p1.ok:
            return NatProfile(mapping_behavior=BLOCKED)
        samples.append((p1.local_port, p1.ext_port))

        local_ip = _local_ipv4()
        if local_ip and p1.ext_ip == local_ip:
            return NatProfile(mapping_behavior=OPEN_INTERNET, ext_ip=p1.ext_ip, samples=samples)

        # Probe 2: Secondary Distinct IP, Primary Port (if available)
        if ip_b:
            p2 = _stun_query_with_retry(sock, (ip_b, port_b), initial_rto=0.4, max_attempts=3, hard_cap=timeout)
            if p2.ok:
                samples.append((p2.local_port, p2.ext_port))

        # Probe 3: Primary IP, Alternate Port
        p3 = _stun_query_with_retry(sock, (ip_a, port_a_alt), initial_rto=0.4, max_attempts=3, hard_cap=timeout)
        if p3.ok:
            samples.append((p3.local_port, p3.ext_port))

    finally:
        try:
            sock.close()
        except Exception:
            pass

    profile = NatProfile(ext_ip=p1.ext_ip, samples=samples)
    profile.is_cgnat = _check_cgnat(p1.ext_ip)

    # Classification logic based on observed mappings from the single socket
    ext_ports = [s[1] for s in samples]

    if len(ext_ports) == 1:
        # Only one probe answered; assume endpoint-independent
        profile.mapping_behavior = ENDPOINT_INDEPENDENT
        return profile

    # Endpoint-Independent (Cone): same external port regardless of IP or port change
    if len(set(ext_ports)) == 1:
        profile.mapping_behavior = ENDPOINT_INDEPENDENT
        return profile

    # If Probe 3 was reached, check port dependency:
    if p3 and p3.ok and p1.ok:
        if p1.ext_port == p3.ext_port:
            # Port is invariant to destination port changes, but differed on Probe 2 (IP change)
            profile.mapping_behavior = ADDRESS_DEPENDENT
            return profile
        else:
            # External port changed when destination port changed -> Address and Port Dependent (Symmetric)
            profile.mapping_behavior = ADDRESS_AND_PORT_DEPENDENT
            return _classify_symmetric_deltas(profile, ext_ports)

    # Fallback when only 2 probes answered
    if len(set(ext_ports)) > 1:
        profile.mapping_behavior = ADDRESS_AND_PORT_DEPENDENT
        return _classify_symmetric_deltas(profile, ext_ports)

    profile.mapping_behavior = ENDPOINT_INDEPENDENT
    return profile


def _classify_symmetric_deltas(profile: NatProfile, ext_ports: list[int]) -> NatProfile:
    """Evaluate port delta to distinguish sequential vs random symmetric NAT."""
    ordered = sorted(ext_ports)
    deltas = [b - a for a, b in itertools.pairwise(ordered)]
    if not deltas:
        profile.predictable = False
        return profile
    max_delta = max(deltas)
    mean_delta = round(sum(deltas) / len(deltas))
    if 1 <= max_delta <= 16:
        profile.port_delta = max(1, mean_delta)
        profile.predictable = True
    else:
        profile.predictable = False
    return profile


def predict_next_port(profile: NatProfile, lookahead: int = 1) -> int | None:
    """Predict the external port the NAT will allocate for the next destination mapping."""
    if not profile.predictable or not profile.samples:
        return None
    last_ext = max(p for _, p in profile.samples)
    predicted = last_ext + profile.port_delta * lookahead
    if 1024 <= predicted <= 65535:
        return predicted
    return None
