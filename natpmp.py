"""Minimal NAT-PMP (RFC 6886) client for VPN/router port-forward detection.

Pure stdlib sockets — no extra dependency, safe to bundle with PyInstaller.

Used to discover and keep alive a forwarded port (e.g. Proton VPN P2P port
forwarding) so WebRTC can bind its ICE socket to it. See
``docs/superpowers/specs/2026-06-02-vpn-forwarded-port-design.md``.
"""
import asyncio
import socket
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

NATPMP_PORT = 5351
OP_MAP_UDP = 1
OP_MAP_TCP = 2


def encode_mapping_request(opcode: int, internal_port: int,
                           requested_external: int, lifetime: int) -> bytes:
    # ver=0, opcode, reserved=0, internal port, requested external, lifetime
    return struct.pack("!BBHHHI", 0, opcode, 0, internal_port,
                       requested_external, lifetime)


@dataclass
class MappingResponse:
    result: int
    epoch: int
    internal_port: int
    external_port: int
    lifetime: int


def decode_mapping_response(data: bytes) -> MappingResponse:
    if len(data) < 16:
        raise ValueError("NAT-PMP response too short")
    _ver, _op, result, epoch, internal, external, lifetime = struct.unpack(
        "!BBHIHHI", data[:16]
    )
    return MappingResponse(result, epoch, internal, external, lifetime)


# Proton VPN's NAT-PMP gateway is reliably 10.2.0.1; used as a fallback if
# gateway derivation fails.
PROTON_GATEWAY = "10.2.0.1"


def local_ip_for(gateway: str) -> str | None:
    """Source IP the OS would use to reach the gateway (our VPN-iface IP)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        try:
            s.connect((gateway, NATPMP_PORT))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def discover_gateway() -> str | None:
    """Best-effort default-gateway discovery (cross-platform).

    Connect a UDP socket toward a public IP, read our source IP, then assume
    the gateway is x.y.z.1 of that /24. Good enough for typical VPN tunnels
    (Proton uses 10.2.0.1). Callers may also try ``PROTON_GATEWAY`` directly.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        try:
            s.connect(("8.8.8.8", 53))
            ip = s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    return ".".join(parts[:3] + ["1"])


def request_mapping_over_socket(gateway: str, lifetime: int = 60) -> int | None:
    """Request UDP+TCP NAT-PMP maps; return the assigned external port.

    Proton requires both protocols mapped and maps the same number both
    publicly and to that same local port. Returns the UDP external port (the
    one we bind ICE to), or None if the gateway did not grant a mapping.
    """
    def _one(opcode: int) -> int | None:
        pkt = encode_mapping_request(opcode, 0, 0, lifetime)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)
            try:
                s.sendto(pkt, (gateway, NATPMP_PORT))
                data, _ = s.recvfrom(32)
                resp = decode_mapping_response(data)
                return resp.external_port if resp.result == 0 else None
            finally:
                s.close()
        except (OSError, ValueError):
            return None

    _one(OP_MAP_TCP)
    return _one(OP_MAP_UDP)


class PortForwardManager:
    """Owns the forwarded-port lifecycle: detect, publish, and renew.

    The network request is injectable (``request_fn``) so the renewal/self-heal
    logic is unit-testable without real sockets. ``publish_fn`` hands the
    current ``(local_ip, ports)`` list to the engine (one mapped port per peer
    PeerConnection for a relay hub); ``clear_fn`` is called when the mapping is
    lost so new connections fall back to normal gathering.
    """

    def __init__(self, gateway: str, local_ip: str | None,
                 request_fn: Callable[[str], Awaitable[int | None]],
                 publish_fn: Callable[[str, list], None],
                 clear_fn: Callable[[], None] | None = None,
                 renew_interval: int = 45,
                 pool_size: int = 1) -> None:
        self.gateway = gateway
        self.local_ip = local_ip
        self._request_fn = request_fn
        self._publish_fn = publish_fn
        self._clear_fn = clear_fn or (lambda: None)
        self._interval = renew_interval
        self.pool_size = pool_size
        self.current_port: int | None = None
        self.current_ports: list = []
        self._task: asyncio.Task | None = None

    async def _detect_once(self) -> None:
        ports = []
        for _ in range(self.pool_size):
            p = await self._request_fn(self.gateway)
            if p is not None:
                ports.append(p)
        if not ports or self.local_ip is None:
            self.current_ports = []
            self.current_port = None
            self._clear_fn()
            return
        self.current_ports = ports
        self.current_port = ports[0]
        self._publish_fn(self.local_ip, ports)

    async def _loop(self) -> None:
        while True:
            await self._detect_once()
            await asyncio.sleep(self._interval)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.ensure_future(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        self._clear_fn()
