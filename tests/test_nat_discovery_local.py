import asyncio
import socket
import struct

import pytest

from nat_discovery import (
    ADDRESS_AND_PORT_DEPENDENT,
    ENDPOINT_INDEPENDENT,
    NatProfile,
    _stun_query_with_retry,
    is_cgnat_ip,
)


def _build_stun_response(tx_id: bytes, mapped_ip: str, mapped_port: int) -> bytes:
    # Build a minimal STUN binding response with XOR-MAPPED-ADDRESS
    msg_type = 0x0101
    cookie = 0x2112A442
    # Attribute 0x0020 (XOR-MAPPED-ADDRESS)
    attr_type = 0x0020
    attr_length = 8
    family = 0x01  # IPv4
    xor_port = mapped_port ^ (cookie >> 16)
    ip_parts = [int(p) for p in mapped_ip.split(".")]
    xor_ip = bytes([
        ip_parts[0] ^ (cookie >> 24 & 0xFF),
        ip_parts[1] ^ (cookie >> 16 & 0xFF),
        ip_parts[2] ^ (cookie >> 8 & 0xFF),
        ip_parts[3] ^ (cookie & 0xFF),
    ])
    attr_val = struct.pack("!BBH", 0x00, family, xor_port) + xor_ip
    body = struct.pack("!HH", attr_type, attr_length) + attr_val
    header = struct.pack("!HHI", msg_type, len(body), cookie) + tx_id
    return header + body


@pytest.mark.asyncio
async def test_cgnat_detection_logic():
    assert is_cgnat_ip("100.64.0.1")
    assert is_cgnat_ip("100.127.255.254")
    assert not is_cgnat_ip("192.168.1.1")
    assert not is_cgnat_ip("8.8.8.8")
    assert not is_cgnat_ip("10.0.0.1")


@pytest.mark.asyncio
async def test_probe_stun_server_with_local_udp_responder():
    loop = asyncio.get_running_loop()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(("127.0.0.1", 0))
    server_port = server_sock.getsockname()[1]
    server_sock.setblocking(False)

    stop_event = asyncio.Event()

    async def stun_responder():
        while not stop_event.is_set():
            try:
                data, addr = await loop.sock_recvfrom(server_sock, 2048)
                if len(data) >= 20:
                    tx_id = data[8:20]
                    resp = _build_stun_response(tx_id, "203.0.113.199", 54321)
                    await loop.sock_sendto(server_sock, resp, addr)
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    task = asyncio.create_task(stun_responder())

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.bind(("127.0.0.1", 0))
    client_sock.setblocking(False)

    try:
        res = await loop.run_in_executor(None, _stun_query_with_retry, client_sock, ("127.0.0.1", server_port))
        assert res is not None
        assert res.ok
        assert res.ext_ip == "203.0.113.199"
        assert res.ext_port == 54321
    finally:
        stop_event.set()
        task.cancel()
        server_sock.close()
        client_sock.close()


def test_nat_profile_backward_compatibility():
    profile = NatProfile(
        mapping_behavior=ENDPOINT_INDEPENDENT,
        ext_ip="198.51.100.1",
        is_cgnat=False,
    )
    assert profile.nat_type == ENDPOINT_INDEPENDENT
    assert not profile.needs_relay

    profile.nat_type = "random-symmetric"
    assert profile.mapping_behavior == ADDRESS_AND_PORT_DEPENDENT
    assert profile.needs_relay
