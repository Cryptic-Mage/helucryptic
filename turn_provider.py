"""TURN credential minting for the signaling server.

The desktop client cannot ship a TURN secret (anyone could extract it from the
binary), so the signaling server hands out *short-lived* relay credentials over
HTTP at ``GET /turn``. Three provider modes, picked by whichever env vars are
set (first match wins):

1. ``cloudflare``  - HELUCRYPTIC_CF_TURN_KEY_ID + HELUCRYPTIC_CF_TURN_API_TOKEN.
   Cloudflare Realtime TURN. 1 TiB/month free, anycast, has UDP/TCP/TLS on
   3478/5349 which covers CGNAT and UDP-blocked networks alike.
2. ``hmac``        - HELUCRYPTIC_TURN_URL + HELUCRYPTIC_TURN_STATIC_SECRET.
   coturn's REST API (``use-auth-secret``): username is ``<expiry>:<label>``,
   password is base64(HMAC-SHA1(secret, username)). Self-hosted relays.
3. ``static``      - HELUCRYPTIC_TURN_URL + _USERNAME + _PASSWORD. Long-lived
   credentials from a hosted provider (Metered, Twilio, ...). Simplest, but the
   credentials are handed to every client verbatim.

``server.py`` and ``cloudflare/src/index.js`` expose the same endpoint with the
same JSON shape - keep the two in sync.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request

# Credential lifetime handed to clients. Long enough that a call started at the
# edge of the window still completes (TURN allocations survive credential
# expiry), short enough that a leaked payload is worthless within a day.
DEFAULT_TTL_SECONDS = 24 * 3600

_CF_ENDPOINT = ("https://rtc.live.cloudflare.com/v1/turn/keys/"
                "{key_id}/credentials/generate-ice-servers")

# Cached mint result so a room full of clients does not trigger one upstream
# call each. Refreshed once the remaining lifetime drops below a quarter.
_cache: dict | None = None
_cache_expires_at: float = 0.0


def provider_mode() -> str:
    """Which provider the current environment selects ('none' if unconfigured)."""
    if os.getenv("HELUCRYPTIC_CF_TURN_KEY_ID") and os.getenv("HELUCRYPTIC_CF_TURN_API_TOKEN"):
        return "cloudflare"
    if os.getenv("HELUCRYPTIC_TURN_URL") and os.getenv("HELUCRYPTIC_TURN_STATIC_SECRET"):
        return "hmac"
    if os.getenv("HELUCRYPTIC_TURN_URL") and os.getenv("HELUCRYPTIC_TURN_PASSWORD"):
        return "static"
    return "none"


def hmac_credentials(secret: str, ttl: int = DEFAULT_TTL_SECONDS,
                     label: str = "helucryptic") -> tuple[str, str]:
    """coturn ``use-auth-secret`` time-limited credential pair."""
    expiry = int(time.time()) + int(ttl)
    username = f"{expiry}:{label}"
    digest = hmac.new(secret.encode("utf-8"), username.encode("utf-8"), hashlib.sha1).digest()
    return username, base64.b64encode(digest).decode("ascii")


def _turn_url_list(raw: str) -> list[str]:
    """Split a comma-separated TURN URL list, keeping order (priority)."""
    return [u.strip() for u in (raw or "").split(",") if u.strip()]


def _cloudflare_ice_servers(key_id: str, api_token: str, ttl: int) -> list[dict]:
    body = json.dumps({"ttl": int(ttl)}).encode("utf-8")
    req = urllib.request.Request(
        _CF_ENDPOINT.format(key_id=key_id),
        data=body,
        headers={"Authorization": f"Bearer {api_token}",
                 "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    servers = payload.get("iceServers")
    # The API has returned both a bare object and a list across versions.
    if isinstance(servers, dict):
        servers = [servers]
    if not isinstance(servers, list) or not servers:
        raise ValueError("Cloudflare TURN response carried no iceServers")
    out = []
    for s in servers:
        urls = s.get("urls") or s.get("url")
        if isinstance(urls, str):
            urls = [urls]
        if not urls:
            continue
        entry: dict = {"urls": list(urls)}
        if s.get("username"):
            entry["username"] = s["username"]
        if s.get("credential"):
            entry["credential"] = s["credential"]
        out.append(entry)
    if not out:
        raise ValueError("Cloudflare TURN response carried no usable URLs")
    return out


def build_ice_servers(ttl: int = DEFAULT_TTL_SECONDS, label: str = "helucryptic") -> dict:
    """Mint an ICE server payload for the active provider.

    Returns ``{"iceServers": [...], "ttl": int, "provider": str}``. Raises on
    upstream failure so the caller can decide the HTTP status; never raises for
    an unconfigured server (returns provider ``none`` with an empty list).
    """
    mode = provider_mode()
    if mode == "cloudflare":
        servers = _cloudflare_ice_servers(
            os.environ["HELUCRYPTIC_CF_TURN_KEY_ID"],
            os.environ["HELUCRYPTIC_CF_TURN_API_TOKEN"],
            ttl,
        )
    elif mode == "hmac":
        username, password = hmac_credentials(
            os.environ["HELUCRYPTIC_TURN_STATIC_SECRET"], ttl, label)
        servers = [{"urls": _turn_url_list(os.environ["HELUCRYPTIC_TURN_URL"]),
                    "username": username, "credential": password}]
    elif mode == "static":
        servers = [{"urls": _turn_url_list(os.environ["HELUCRYPTIC_TURN_URL"]),
                    "username": os.getenv("HELUCRYPTIC_TURN_USERNAME", ""),
                    "credential": os.getenv("HELUCRYPTIC_TURN_PASSWORD", "")}]
    else:
        servers = []
    return {"iceServers": servers, "ttl": int(ttl), "provider": mode}


def cached_ice_servers(ttl: int = DEFAULT_TTL_SECONDS, label: str = "helucryptic") -> dict:
    """``build_ice_servers`` with a process-local cache.

    HMAC/static payloads are cheap but the Cloudflare mint is a network round
    trip; caching keeps a busy hub from hammering the API. On refresh failure
    the previous payload is served while it is still valid, so a transient
    upstream outage does not knock every client off the relay.
    """
    global _cache, _cache_expires_at
    now = time.time()
    if _cache is not None and now < _cache_expires_at:
        return _cache
    try:
        payload = build_ice_servers(ttl=ttl, label=label)
    except Exception:
        if _cache is not None:
            return _cache
        raise
    _cache = payload
    # Refresh at three quarters of the lifetime so clients never receive a
    # credential that is about to die.
    _cache_expires_at = now + max(60.0, ttl * 0.75)
    return payload


def reset_cache() -> None:
    """Drop the cached payload (tests, and after an env change)."""
    global _cache, _cache_expires_at
    _cache = None
    _cache_expires_at = 0.0
