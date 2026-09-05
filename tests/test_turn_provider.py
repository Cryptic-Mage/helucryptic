"""TURN credential minting + client-side ICE selection.

Covers the path that makes WAN (CGNAT / symmetric NAT) peers connect: the
server mints short-lived relay credentials, the client fetches them and reduces
them to the single STUN/TURN pair aiortc actually honours.
"""
import asyncio
import base64
import hashlib
import hmac
import time

import pytest
from aiortc import RTCIceServer

import turn_provider
import webrtc_engine as we

_CF_ENV = ("HELUCRYPTIC_CF_TURN_KEY_ID", "HELUCRYPTIC_CF_TURN_API_TOKEN")
_TURN_ENV = ("HELUCRYPTIC_TURN_URL", "HELUCRYPTIC_TURN_STATIC_SECRET",
             "HELUCRYPTIC_TURN_USERNAME", "HELUCRYPTIC_TURN_PASSWORD")


def _run(coro):
    return asyncio.run(coro)


def _boom(*_a, **_k):
    raise OSError("upstream down")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in _CF_ENV + _TURN_ENV:
        monkeypatch.delenv(name, raising=False)
    turn_provider.reset_cache()
    yield
    turn_provider.reset_cache()


# --------------------------------------------------------------------------
# Provider selection
# --------------------------------------------------------------------------

def test_provider_none_when_unconfigured():
    assert turn_provider.provider_mode() == "none"
    assert turn_provider.build_ice_servers()["iceServers"] == []


def test_cloudflare_wins_over_static(monkeypatch):
    monkeypatch.setenv("HELUCRYPTIC_CF_TURN_KEY_ID", "key")
    monkeypatch.setenv("HELUCRYPTIC_CF_TURN_API_TOKEN", "token")
    monkeypatch.setenv("HELUCRYPTIC_TURN_URL", "turn:example.org:3478")
    monkeypatch.setenv("HELUCRYPTIC_TURN_PASSWORD", "pw")
    assert turn_provider.provider_mode() == "cloudflare"


def test_hmac_wins_over_static(monkeypatch):
    monkeypatch.setenv("HELUCRYPTIC_TURN_URL", "turn:example.org:3478")
    monkeypatch.setenv("HELUCRYPTIC_TURN_STATIC_SECRET", "s3cret")
    monkeypatch.setenv("HELUCRYPTIC_TURN_PASSWORD", "pw")
    assert turn_provider.provider_mode() == "hmac"


# --------------------------------------------------------------------------
# Credential shapes
# --------------------------------------------------------------------------

def test_hmac_credentials_match_coturn_rest_api():
    username, password = turn_provider.hmac_credentials("s3cret", ttl=600, label="hc")
    expiry, label = username.split(":")
    assert label == "hc"
    # Expiry is in the future and inside the requested window.
    assert 0 < int(expiry) - int(time.time()) <= 600
    expected = base64.b64encode(
        hmac.new(b"s3cret", username.encode(), hashlib.sha1).digest()).decode()
    assert password == expected


def test_hmac_payload_carries_all_urls_in_order(monkeypatch):
    monkeypatch.setenv(
        "HELUCRYPTIC_TURN_URL",
        "turn:r.example:3478?transport=udp, turns:r.example:5349?transport=tcp")
    monkeypatch.setenv("HELUCRYPTIC_TURN_STATIC_SECRET", "s3cret")
    payload = turn_provider.build_ice_servers(ttl=300)
    assert payload["provider"] == "hmac"
    assert payload["iceServers"][0]["urls"] == [
        "turn:r.example:3478?transport=udp", "turns:r.example:5349?transport=tcp"]


def test_static_payload(monkeypatch):
    monkeypatch.setenv("HELUCRYPTIC_TURN_URL", "turn:r.example:3478")
    monkeypatch.setenv("HELUCRYPTIC_TURN_USERNAME", "user")
    monkeypatch.setenv("HELUCRYPTIC_TURN_PASSWORD", "pw")
    server = turn_provider.build_ice_servers()["iceServers"][0]
    assert (server["username"], server["credential"]) == ("user", "pw")


def test_cloudflare_payload(monkeypatch):
    monkeypatch.setenv("HELUCRYPTIC_CF_TURN_KEY_ID", "key")
    monkeypatch.setenv("HELUCRYPTIC_CF_TURN_API_TOKEN", "token")
    monkeypatch.setattr(
        turn_provider, "_cloudflare_ice_servers",
        lambda k, t, ttl: [{"urls": ["turn:turn.cloudflare.com:3478"],
                            "username": "u", "credential": "c"}])
    payload = turn_provider.build_ice_servers()
    assert payload["provider"] == "cloudflare"
    assert payload["iceServers"][0]["username"] == "u"


# --------------------------------------------------------------------------
# Caching: a busy hub must not mint per client, and must survive an outage
# --------------------------------------------------------------------------

def test_cache_avoids_repeat_minting(monkeypatch):
    monkeypatch.setenv("HELUCRYPTIC_CF_TURN_KEY_ID", "key")
    monkeypatch.setenv("HELUCRYPTIC_CF_TURN_API_TOKEN", "token")
    calls = []

    def fake(k, t, ttl):
        calls.append(1)
        return [{"urls": ["turn:turn.cloudflare.com:3478"],
                 "username": "u", "credential": "c"}]

    monkeypatch.setattr(turn_provider, "_cloudflare_ice_servers", fake)
    turn_provider.cached_ice_servers()
    turn_provider.cached_ice_servers()
    assert len(calls) == 1


def test_cache_serves_stale_payload_when_upstream_fails(monkeypatch):
    monkeypatch.setenv("HELUCRYPTIC_CF_TURN_KEY_ID", "key")
    monkeypatch.setenv("HELUCRYPTIC_CF_TURN_API_TOKEN", "token")
    monkeypatch.setattr(
        turn_provider, "_cloudflare_ice_servers",
        lambda k, t, ttl: [{"urls": ["turn:a:3478"], "username": "u", "credential": "c"}])
    first = turn_provider.cached_ice_servers()
    # Force expiry, then break the upstream: clients keep a working relay.
    turn_provider._cache_expires_at = 0.0
    monkeypatch.setattr(turn_provider, "_cloudflare_ice_servers", _boom)
    assert turn_provider.cached_ice_servers() == first


def test_cache_raises_when_no_previous_payload(monkeypatch):
    monkeypatch.setenv("HELUCRYPTIC_CF_TURN_KEY_ID", "key")
    monkeypatch.setenv("HELUCRYPTIC_CF_TURN_API_TOKEN", "token")
    monkeypatch.setattr(turn_provider, "_cloudflare_ice_servers", _boom)
    with pytest.raises(OSError):
        turn_provider.cached_ice_servers()


# --------------------------------------------------------------------------
# Client side
# --------------------------------------------------------------------------

@pytest.mark.parametrize("given,expected", [
    ("wss://hub.workers.dev/", "https://hub.workers.dev"),
    ("ws://127.0.0.1:8000", "http://127.0.0.1:8000"),
    ("https://hub.example/", "https://hub.example"),
    ("hub.example", "https://hub.example"),
])
def test_http_url_for(given, expected):
    assert we._http_url_for(given) == expected


def test_fetch_ice_servers_parses_payload(monkeypatch):
    payload = {"provider": "cloudflare", "ttl": 3600, "iceServers": [
        {"urls": ["stun:stun.cloudflare.com:3478"]},
        {"urls": ["turn:turn.cloudflare.com:3478?transport=udp"],
         "username": "u", "credential": "c"},
    ]}
    monkeypatch.setattr(we, "_fetch_ice_blocking", lambda url, pw, t: payload)
    servers, ttl = _run(we.fetch_ice_servers("wss://hub.example"))
    assert ttl == 3600
    assert servers[1].username == "u"
    assert we._flatten_turn_urls(servers) == [
        ("turn:turn.cloudflare.com:3478?transport=udp", "u", "c")]


def test_fetch_ice_servers_survives_unreachable_server(monkeypatch):
    monkeypatch.setattr(we, "_fetch_ice_blocking", _boom)
    assert _run(we.fetch_ice_servers("wss://hub.example")) == ([], 0)


def test_select_for_aiortc_yields_one_stun_and_one_turn():
    servers = [
        RTCIceServer(urls=["stun:a:3478"]),
        RTCIceServer(urls=["stun:b:3478"]),
        RTCIceServer(urls=["turn:r:3478?transport=udp",
                           "turn:r:3478?transport=tcp",
                           "turns:r:5349?transport=tcp"], username="u", credential="c"),
    ]
    picked = we._select_for_aiortc(servers)
    # aiortc honours exactly one of each; anything more is silently dropped.
    assert len(picked) == 2
    assert picked[0].urls == ["stun:a:3478"]
    assert picked[1].urls == ["turn:r:3478?transport=udp"]
    assert picked[1].credential == "c"


def test_select_for_aiortc_rotates_transport_across_attempts():
    servers = [
        RTCIceServer(urls=["stun:a:3478"]),
        RTCIceServer(urls=["turn:r:3478?transport=udp",
                           "turn:r:3478?transport=tcp",
                           "turns:r:5349?transport=tcp"], username="u", credential="c"),
    ]
    seen = [we._select_for_aiortc(servers, i)[1].urls[0] for i in range(4)]
    assert seen == ["turn:r:3478?transport=udp",
                    "turn:r:3478?transport=tcp",
                    "turns:r:5349?transport=tcp",
                    "turn:r:3478?transport=udp"]


def test_select_for_aiortc_without_turn_keeps_stun():
    picked = we._select_for_aiortc([RTCIceServer(urls=["stun:a:3478"])])
    assert [s.urls for s in picked] == [["stun:a:3478"]]


def test_selected_pair_survives_aiortc_connection_kwargs():
    """The reduced list must still produce a turn_server for aioice."""
    from aiortc.rtcicetransport import connection_kwargs
    servers = [
        RTCIceServer(urls=["stun:a:3478"]),
        RTCIceServer(urls=["turn:r:3478?transport=udp",
                           "turns:r:5349?transport=tcp"], username="u", credential="c"),
    ]
    kwargs = connection_kwargs(we._select_for_aiortc(servers, attempt=1))
    assert kwargs["turn_server"] == ("r", 5349)
    assert kwargs["turn_ssl"] is True
    assert kwargs["turn_transport"] == "tcp"
    assert kwargs["turn_username"] == "u"
