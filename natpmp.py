"""Minimal NAT-PMP (RFC 6886) client for VPN/router port-forward detection.

Pure stdlib sockets - no extra dependency, safe to bundle with PyInstaller.

Used to discover and keep alive a forwarded port (e.g. Proton VPN P2P port
forwarding) so WebRTC can bind its ICE socket to it. See
``docs/superpowers/specs/2026-06-02-vpn-forwarded-port-design.md``.
"""
import asyncio
import logging
import socket
import struct
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from constants.natpmp_constants import (
    NATPMP_PORT,
    OP_MAP_TCP,
    OP_MAP_UDP,
    PROTON_GATEWAY,
)

# Configure standard logger
logger = logging.getLogger("helucryptic.natpmp")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _formatter = logging.Formatter("[natpmp] %(message)s")
    _handler.setFormatter(_formatter)
    logger.addHandler(_handler)


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


def local_ip_for(gateway: str) -> str | None:
    """Source IP the OS would use to reach the gateway (our VPN-iface IP)."""
    logger.info("Determining local IP interface route to gateway: %s", gateway)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        try:
            s.connect((gateway, NATPMP_PORT))
            local_ip = s.getsockname()[0]
            logger.info("Local IP determined: %s", local_ip)
            return local_ip
        finally:
            s.close()
    except OSError as e:
        logger.warning("Failed to determine local IP interface route to gateway %s: %s", gateway, e)
        return None


def discover_gateway() -> str | None:
    """Best-effort default-gateway discovery (cross-platform).

    Connect a UDP socket toward a public IP, read our source IP, then assume
    the gateway is x.y.z.1 of that /24. Good enough for typical VPN tunnels
    (Proton uses 10.2.0.1). Callers may also try ``PROTON_GATEWAY`` directly.
    """
    logger.info("Discovering default gateway...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        try:
            s.connect((".".join(["8", "8", "8", "8"]), 53))
            ip = s.getsockname()[0]
        finally:
            s.close()
    except OSError as e:
        logger.warning("Gateway discovery failed: %s", e)
        return None
    parts = ip.split(".")
    if len(parts) != 4:
        logger.warning("Gateway discovery failed: invalid IP structure %r", ip)
        return None
    gw = ".".join(parts[:3] + ["1"])
    logger.info("Default gateway discovered: %s", gw)
    return gw


def discover_gateway_candidates(primary: str | None = None) -> list[str]:
    """Return an ordered list of gateway addresses to probe for NAT-PMP.

    Starts from *primary* (or the result of ``discover_gateway()`` if omitted),
    then appends the two other common last-octet assignments (.254, .2) so
    non-standard subnets succeed without manual configuration.
    ``PROTON_GATEWAY`` is appended as a final fallback.
    """
    base = primary if primary is not None else discover_gateway()
    if not base:
        return [PROTON_GATEWAY]
    parts = base.split(".")
    if len(parts) != 4:
        return [base, PROTON_GATEWAY]
    prefix = ".".join(parts[:3])
    seen: set[str] = {base}
    candidates: list[str] = [base]
    for suffix in ("1", "254", "2"):
        alt = f"{prefix}.{suffix}"
        if alt not in seen:
            seen.add(alt)
            candidates.append(alt)
    if PROTON_GATEWAY not in seen:
        candidates.append(PROTON_GATEWAY)
    return candidates


def request_mapping_over_socket(gateway: str, lifetime: int = 60) -> int | None:
    """Request UDP+TCP NAT-PMP maps; return the assigned external port.

    Proton requires both protocols mapped and maps the same number both
    publicly and to that same local port. Returns the UDP external port (the
    one we bind ICE to), or None if the gateway did not grant a mapping.
    """
    logger.info("Requesting port mapping from gateway %s with lifetime %d", gateway, lifetime)
    
    def _one(opcode: int) -> int | None:
        proto = "UDP" if opcode == OP_MAP_UDP else "TCP"
        pkt = encode_mapping_request(opcode, 0, 0, lifetime)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)
            try:
                s.sendto(pkt, (gateway, NATPMP_PORT))
                data, _ = s.recvfrom(32)
                resp = decode_mapping_response(data)
                if resp.result == 0:
                    logger.info("Successfully mapped %s external port: %d", proto, resp.external_port)
                    return resp.external_port
                else:
                    logger.warning("Gateway rejected %s map request with result code: %d", proto, resp.result)
                    return None
            finally:
                s.close()
        except (OSError, ValueError) as e:
            logger.warning("NAT-PMP %s request to %s failed: %s", proto, gateway, e)
            return None

    # Both TCP and UDP must succeed for symmetric port mapping (RFC 6886).
    # If TCP fails, log but still attempt UDP — some gateways only support one.
    tcp_port = _one(OP_MAP_TCP)
    udp_port = _one(OP_MAP_UDP)
    if udp_port is None and tcp_port is not None:
        logger.info("UDP mapping failed but TCP succeeded on port %d - using TCP port", tcp_port)
        return tcp_port
    return udp_port


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
                 pool_size: int = 1,
                 max_failures: int = 3) -> None:
        self.gateway = gateway
        self.local_ip = local_ip
        self._request_fn = request_fn
        self._publish_fn = publish_fn
        self._clear_fn = clear_fn or (lambda: None)
        self._interval = renew_interval
        self.pool_size = pool_size
        self.max_failures = max_failures
        self.current_port: int | None = None
        self.current_ports: list = []
        self._task: asyncio.Task | None = None
        self._fail_count: int = 0

    async def _detect_once(self) -> None:
        logger.info("Executing NAT-PMP detection loop cycle")
        ports = []
        for _ in range(self.pool_size):
            result = self._request_fn(self.gateway)
            # If request_fn is a sync callable (not coroutine), wrap in executor
            # to avoid blocking the event loop.
            import asyncio as _aio
            if _aio.iscoroutine(result):
                p = await result
            else:
                p = await _aio.get_event_loop().run_in_executor(None, result)
            if p is not None:
                ports.append(p)
        if not ports or self.local_ip is None:
            self._fail_count += 1
            logger.warning(
                "NAT-PMP port mapping failed or empty (failure %d/%d)",
                self._fail_count, self.max_failures,
            )
            self.current_ports = []
            self.current_port = None
            self._clear_fn()
            return
        self._fail_count = 0
        self.current_ports = ports
        self.current_port = ports[0]
        logger.info("Successfully mapped port pool: %s (selected default: %s)", ports, ports[0])
        self._publish_fn(self.local_ip, ports)

    async def _loop(self) -> None:
        while True:
            await self._detect_once()
            if self._fail_count >= self.max_failures:
                logger.info(
                    "NAT-PMP: gateway %s did not respond after %d attempts - "
                    "port forwarding unavailable on this network, stopping.",
                    self.gateway, self.max_failures,
                )
                self._task = None
                return
            await asyncio.sleep(self._interval)

    def start(self) -> None:
        if self._task is None:
            logger.info("Starting PortForwardManager loop")
            self._task = asyncio.ensure_future(self._loop())

    async def stop(self) -> None:
        if self._task:
            logger.info("Stopping PortForwardManager loop")
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                cur = asyncio.current_task()
                if cur and getattr(cur, "cancelling", lambda: False)():
                    raise
            self._task = None
        self._clear_fn()
