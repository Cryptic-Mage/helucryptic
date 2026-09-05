"""A port mapping must be proven reachable before we advertise it.

Two ways the app claimed reachability it did not have, both of which burn every
ICE connectivity check on an address that cannot answer:

  * a port auto-discovered on a previous network (VPN on, different router)
    was re-reported as a live mapping once nothing answered any more;
  * behind carrier-grade NAT the home router grants a mapping while the ISP NAT
    in front of it forwards nothing.
"""
import asyncio

import pytest

import client


class _Settings:
    def __init__(self, **kw):
        self.port_forward_enabled = True
        self.forwarded_port = 0
        self.forwarded_port_manual = False
        self.__dict__.update(kw)


class _App:
    """Minimal stand-in carrying only what the publish path touches."""

    def __init__(self, **kw):
        self.settings = _Settings(**kw)
        self._verified_forward_port = 0
        self._room_id = None
        self.ws = None
        self.committed = []
        self.deferred = []
        self.cleared = 0

    def _fire_and_forget(self, coro):
        # The tests drive _verify_and_publish directly; the publish path only
        # needs to record that it deferred rather than committing inline.
        self.deferred.append(coro)
        coro.close()
        return None

    def _commit_forwarded_port(self, ip, port_list):
        self.committed.append((ip, list(port_list)))

    _publish_forwarded_port = client.HelucrypticApp._publish_forwarded_port
    _verify_and_publish = client.HelucrypticApp._verify_and_publish


@pytest.fixture
def no_clear(monkeypatch):
    calls = {"n": 0}
    monkeypatch.setattr(client, "clear_forwarded_port",
                        lambda: calls.__setitem__("n", calls["n"] + 1))
    return calls


# ---------------------------------------------------------------------------
# Reachability verification
# ---------------------------------------------------------------------------

def _patch_probe(monkeypatch, result):
    # client imports the probe by name, so patch it in client's namespace -
    # patching webrtc_engine would leave the already-bound reference in place
    # and the test would perform a real STUN round trip.
    monkeypatch.setattr(client, "test_forwarded_port", lambda ip, port: result)


def test_unreachable_mapping_is_not_advertised(monkeypatch, no_clear):
    """The CGNAT case: the router maps a port, the carrier NAT drops it."""
    _patch_probe(monkeypatch, (False, "Public port 51000 != forwarded 64382"))
    app = _App()
    asyncio.run(app._verify_and_publish("192.168.1.6", [64382]))
    assert app.committed == []
    assert app._verified_forward_port == 0
    assert no_clear["n"] == 1          # the allocator is stood down


def test_reachable_mapping_is_advertised_and_remembered(monkeypatch, no_clear):
    _patch_probe(monkeypatch, (True, "Reachable: 103.217.81.60:64382"))
    app = _App()
    asyncio.run(app._verify_and_publish("192.168.1.6", [64382]))
    assert app.committed == [("192.168.1.6", [64382])]
    assert app._verified_forward_port == 64382
    assert no_clear["n"] == 0


def test_an_already_verified_port_is_not_reprobed(monkeypatch, no_clear):
    """The renewal loop republishes every ~45 s while a call is live; re-probing
    would fail with EADDRINUSE against our own ICE socket."""
    probes = []

    monkeypatch.setattr(client, "test_forwarded_port",
                        lambda ip, port: probes.append(port) or (True, "ok"))
    app = _App()
    app._verified_forward_port = 64382
    app._publish_forwarded_port("192.168.1.6", [64382])
    assert probes == []                       # straight to commit
    assert app.deferred == []                 # no verification round trip
    assert app.committed == [("192.168.1.6", [64382])]


def test_a_new_port_defers_to_verification_instead_of_committing():
    """An unverified port must never reach set_forwarded_ports directly."""
    app = _App()
    app._publish_forwarded_port("192.168.1.6", [64382])
    assert app.committed == []
    assert len(app.deferred) == 1


def test_a_changed_mapping_is_reprobed(monkeypatch, no_clear):
    _patch_probe(monkeypatch, (True, "Reachable: 1.2.3.4:70000"))
    app = _App()
    app._verified_forward_port = 64382
    # A new port must not inherit the old port's verdict.
    asyncio.run(app._verify_and_publish("192.168.1.6", [51515]))
    assert app._verified_forward_port == 51515
