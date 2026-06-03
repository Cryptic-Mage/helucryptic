import struct

import pytest

from natpmp import (
    OP_MAP_TCP,
    OP_MAP_UDP,
    decode_mapping_response,
    encode_mapping_request,
)


def test_encode_mapping_request_udp():
    pkt = encode_mapping_request(OP_MAP_UDP, internal_port=41234,
                                 requested_external=41234, lifetime=60)
    assert pkt == struct.pack("!BBHHHI", 0, 1, 0, 41234, 41234, 60)


def test_encode_mapping_request_tcp_opcode():
    pkt = encode_mapping_request(OP_MAP_TCP, internal_port=0,
                                 requested_external=0, lifetime=60)
    assert pkt[1] == 2  # opcode byte


def test_decode_mapping_response_ok():
    raw = struct.pack("!BBHIHHI", 0, 129, 0, 12345, 41234, 55000, 60)
    resp = decode_mapping_response(raw)
    assert resp.result == 0
    assert resp.external_port == 55000
    assert resp.lifetime == 60


def test_decode_mapping_response_rejects_short():
    with pytest.raises(ValueError):
        decode_mapping_response(b"\x00\x81")


def test_local_ip_for_uses_connect(monkeypatch):
    import natpmp

    class FakeSock:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, t):
            pass

        def connect(self, addr):
            self.addr = addr

        def getsockname(self):
            return ("10.2.0.5", 12345)

        def close(self):
            pass

    monkeypatch.setattr(natpmp.socket, "socket", lambda *a, **k: FakeSock())
    assert natpmp.local_ip_for("10.2.0.1") == "10.2.0.5"


def test_local_ip_for_returns_none_on_error(monkeypatch):
    import natpmp

    def boom(*a, **k):
        raise OSError("no route")

    monkeypatch.setattr(natpmp.socket, "socket", boom)
    assert natpmp.local_ip_for("10.2.0.1") is None


def test_discover_gateway_derives_dot_one(monkeypatch):
    import natpmp

    class FakeSock:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, t):
            pass

        def connect(self, addr):
            pass

        def getsockname(self):
            return ("10.2.0.5", 54321)

        def close(self):
            pass

    monkeypatch.setattr(natpmp.socket, "socket", lambda *a, **k: FakeSock())
    assert natpmp.discover_gateway() == "10.2.0.1"


def test_manager_publishes_and_self_heals():
    import asyncio

    from natpmp import PortForwardManager

    ports = iter([55000, 55000, 60001])  # renewal eventually returns a new port
    published = []

    async def fake_request(gateway):
        return next(ports)

    mgr = PortForwardManager(
        gateway="10.2.0.1", local_ip="10.2.0.5",
        request_fn=fake_request,
        publish_fn=lambda ip, ports: published.append((ip, list(ports))),
        renew_interval=0,
    )

    async def run():
        await mgr._detect_once()  # initial map
        await mgr._detect_once()  # same port -> still publishes current
        await mgr._detect_once()  # changed port -> re-published

    asyncio.run(run())
    assert published[0] == ("10.2.0.5", [55000])
    assert published[-1] == ("10.2.0.5", [60001])
    assert mgr.current_port == 60001


def test_manager_clears_when_request_fails():
    import asyncio

    from natpmp import PortForwardManager

    cleared = []

    async def fake_request(gateway):
        return None

    mgr = PortForwardManager(
        gateway="10.2.0.1", local_ip="10.2.0.5",
        request_fn=fake_request,
        publish_fn=lambda ip, ports: None,
        clear_fn=lambda: cleared.append(True),
        renew_interval=0,
    )
    asyncio.run(mgr._detect_once())
    assert cleared == [True]
    assert mgr.current_port is None


def test_manager_requests_multiple_mappings():
    import asyncio
    from natpmp import PortForwardManager
    granted = iter([55000, 55001, 55002])
    published = []
    async def fake_request(gateway):
        return next(granted)
    mgr = PortForwardManager("10.2.0.1","10.2.0.5",
        request_fn=fake_request,
        publish_fn=lambda ip, ports: published.append((ip, list(ports))),
        renew_interval=0, pool_size=3)
    asyncio.run(mgr._detect_once())
    assert published[-1] == ("10.2.0.5", [55000,55001,55002])
    assert mgr.current_port == 55000
