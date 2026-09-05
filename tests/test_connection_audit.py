"""Regression tests for the signaling-server and NAT-traversal audit.

Each test pins a defect that was reproducible before the fix:

  * the room capacity check raced its own awaits, so a 4-person room reached 5;
  * behind a reverse proxy every client shared one rate-limit bucket and was
    told the proxy's address was its own public IP;
  * the per-IP connection map had no eviction and grew for the process lifetime;
  * a presence query was unbounded (and, in the Worker, untyped);
  * UPnP followed SSDP-supplied URLs to hosts off the LAN.
"""
import asyncio
import importlib
import ipaddress
import time

import pytest

import upnp

# ---------------------------------------------------------------------------
# Room capacity
# ---------------------------------------------------------------------------

class _WS:
    """A socket whose sends yield, the way a real one does."""

    def __init__(self):
        self.client = None
        self.closed = False

    async def send_text(self, _):
        await asyncio.sleep(0)

    async def close(self):
        self.closed = True


def _seed_room(server, room, n):
    for i in range(n):
        user = f"user{i}"
        server.rooms.setdefault(room, set()).add(user)
        server.room_of[user] = room
        server.active_connections[user] = _WS()


def test_simultaneous_joins_cannot_exceed_room_capacity():
    """Two joins arriving together both passed the capacity check, then both
    added themselves after the awaits - the room ended up over the limit."""
    import server

    server.reset_server_state()
    _seed_room(server, "R", server.MAX_ROOM_CAPACITY - 1)

    async def race():
        return await asyncio.gather(
            server._handle_room_joining(_WS(), "alice", "R"),
            server._handle_room_joining(_WS(), "bob", "R"),
        )

    accepted = asyncio.run(race())
    assert len(server.rooms["R"]) <= server.MAX_ROOM_CAPACITY
    assert sorted(accepted) == [False, True]      # exactly one wins the slot


def test_joiner_is_not_listed_among_its_own_peers():
    """The slot is claimed before the roster is sent, so the roster must still
    exclude the joiner."""
    import server

    server.reset_server_state()
    _seed_room(server, "R", 1)
    sent = []

    class _Recorder(_WS):
        async def send_text(self, text):
            sent.append(text)
            await asyncio.sleep(0)

    asyncio.run(server._handle_room_joining(_Recorder(), "alice", "R"))
    room_state = [s for s in sent if "room_state" in s]
    assert room_state and "alice" not in room_state[0]


# ---------------------------------------------------------------------------
# Client address behind a proxy
# ---------------------------------------------------------------------------

class _Headers(dict):
    def get(self, key, default=None):
        return dict.get(self, key, default)


class _ProxiedWS:
    def __init__(self, headers, peer="10.0.0.1"):
        self.headers = _Headers(headers)
        self.client = type("C", (), {"host": peer, "port": 4321})()


def _server_with_trust(monkeypatch, trusted):
    monkeypatch.setenv("HELUCRYPTIC_TRUST_PROXY_HEADERS", "true" if trusted else "false")
    import server
    return importlib.reload(server)


def test_forwarded_headers_are_ignored_by_default(monkeypatch):
    """A forwarded header is client-supplied. Trusting it unconditionally would
    let anyone spoof an address and walk past the connection rate limit."""
    server = _server_with_trust(monkeypatch, False)
    ws = _ProxiedWS({"x-forwarded-for": "1.2.3.4", "x-real-ip": "5.6.7.8"})
    assert server._client_ip(ws) == "10.0.0.1"


def test_forwarded_headers_are_used_when_trusted(monkeypatch):
    server = _server_with_trust(monkeypatch, True)
    # "client, proxy1, proxy2" - the client is the first entry.
    assert server._client_ip(
        _ProxiedWS({"x-forwarded-for": "203.0.113.9, 10.0.0.1"})) == "203.0.113.9"
    assert server._client_ip(
        _ProxiedWS({"x-real-ip": "203.0.113.7"})) == "203.0.113.7"
    # Falls back to the socket peer when the proxy sent nothing.
    assert server._client_ip(_ProxiedWS({})) == "10.0.0.1"


def test_reflected_host_matches_the_rate_limit_identity(monkeypatch):
    """reflected_host feeds the client's srflx candidate injection, so handing
    it the proxy's address advertises an endpoint that answers for nobody."""
    server = _server_with_trust(monkeypatch, True)
    ws = _ProxiedWS({"x-forwarded-for": "203.0.113.9"})
    assert server._client_ip(ws) == "203.0.113.9"


# ---------------------------------------------------------------------------
# Rate-limiter memory
# ---------------------------------------------------------------------------

def test_connection_rate_map_evicts_expired_addresses(monkeypatch):
    """Unlike the per-username limiters there is no disconnect hook here, so
    without eviction every IP that ever connected stayed resident."""
    server = _server_with_trust(monkeypatch, False)
    server.reset_server_state()
    for i in range(server._CONN_PRUNE_AT + 100):
        server._conn_rate_ok(f"10.0.{i // 256}.{i % 256}")
    assert len(server._conn_times) > 0

    for dq in server._conn_times.values():
        dq[0] = time.monotonic() - (server._CONN_WINDOW * 10)
    server._prune_conn_times(time.monotonic())
    assert len(server._conn_times) == 0


def test_pruning_keeps_addresses_still_inside_the_window(monkeypatch):
    server = _server_with_trust(monkeypatch, False)
    server.reset_server_state()
    server._conn_rate_ok("203.0.113.1")
    server._prune_conn_times(time.monotonic())
    assert "203.0.113.1" in server._conn_times      # still rate-limited


# ---------------------------------------------------------------------------
# Presence query
# ---------------------------------------------------------------------------

def test_presence_query_is_capped(monkeypatch):
    """A 64 KiB frame carries thousands of names; at 100 messages / 10 s that is
    a large lookup-and-echo loop on a server shared by everyone, and a ready
    made way to sweep for who is online."""
    server = _server_with_trust(monkeypatch, False)
    server.reset_server_state()
    sent = []

    class _Recorder(_WS):
        async def send_text(self, text):
            sent.append(text)

    names = [f"user{i}" for i in range(5000)]
    for n in names[:10]:
        server.active_connections[n] = _WS()

    asyncio.run(server._handle_websocket_message(
        _Recorder(), "asker", {"type": "presence", "data": {"usernames": names}}))
    import json
    online = json.loads(sent[0])["data"]["online"]
    assert len(online) <= server._PRESENCE_MAX_QUERY


def test_presence_tolerates_a_malformed_shape(monkeypatch):
    """A non-list `usernames` must not escape the message loop."""
    server = _server_with_trust(monkeypatch, False)
    server.reset_server_state()

    for bad in ({"evil": 1}, "notalist", 42, None):
        asyncio.run(server._handle_websocket_message(
            _WS(), "asker", {"type": "presence", "data": {"usernames": bad}}))


# ---------------------------------------------------------------------------
# UPnP SSRF
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://192.168.1.1:5000/desc.xml",
    "http://10.0.0.1/rootDesc.xml",
    "http://172.16.4.4:1900/x",
])
def test_lan_urls_are_accepted(url):
    assert upnp._lan_url_ok(url) is True


@pytest.mark.parametrize("url,why", [
    ("http://169.254.169.254/latest/meta-data/", "cloud metadata"),
    ("http://attacker.example.com/desc.xml", "external hostname"),
    ("http://metadata.google.internal/x", "metadata hostname"),
    ("http://8.8.8.8/desc.xml", "public address"),
    ("file:///etc/passwd", "non-http scheme"),
    ("gopher://192.168.1.1/x", "non-http scheme"),
    ("http://127.0.0.1:8000/admin", "loopback"),
])
def test_non_lan_urls_are_refused(url, why):
    assert upnp._lan_url_ok(url) is False, why


def test_hostnames_are_refused_even_when_they_look_local():
    """The old guard detected an external domain and then fell through to fetch
    it anyway. A name also cannot be judged safely: it may resolve differently
    between the check and the request."""
    assert upnp._lan_url_ok("http://router.local/desc.xml") is False
    assert upnp._lan_url_ok("http://fritz.box/desc.xml") is False


def test_redirects_are_refused():
    """Validating only the first URL is no guard if a private-IP LOCATION can
    redirect onward to the metadata service."""
    handler = upnp._NoRedirects()
    assert handler.redirect_request(
        None, None, 302, "Found", {}, "http://169.254.169.254/") is None


def test_every_upnp_fetch_uses_the_no_redirect_opener():
    import inspect
    source = inspect.getsource(upnp)
    # urlopen follows redirects; the module must not reach for it directly.
    assert "urllib.request.urlopen(" not in source


def test_private_ranges_agree_with_ipaddress():
    """Guard against the check drifting from what 'private' actually means."""
    for addr in ("192.168.0.1", "10.255.255.254", "172.31.0.1"):
        assert ipaddress.ip_address(addr).is_private
        assert upnp._lan_url_ok(f"http://{addr}/x") is True
