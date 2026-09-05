import hmac
import json
import logging
import os
import re
import secrets as _secrets
import time
from collections import deque

# pyrefly: ignore [missing-import]
from fastapi import FastAPI, Query, Response, WebSocket, WebSocketDisconnect

try:
    # pyrefly: ignore [missing-import]
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from constants.server_constants import (
    EXPECTED_PASSWORD,
    MAX_ROOM_CAPACITY,
    SERVER_TITLE,
    SERVER_TYPES,
)

import turn_provider

logger = logging.getLogger("helucryptic.server")

# Security: max incoming WebSocket message size (bytes). Prevents memory DoS
# from malicious clients sending multi-MB JSON payloads.
_MAX_PAYLOAD_BYTES = 65536  # 64 KiB — signaling messages are tiny

# Security: allowed Origin headers for WebSocket upgrade. Empty = no check
# (self-hosted servers behind reverse proxies may strip Origin). Set
# HELUCRYPTIC_ALLOWED_ORIGINS="https://app.helucryptic.io,https://helucryptic.io"
# in production. Native (non-browser) clients send no Origin - allowed intentionally.
_ALLOWED_ORIGINS: set[str] = set()
_origins_env = os.getenv("HELUCRYPTIC_ALLOWED_ORIGINS", "")
if _origins_env.strip():
    _ALLOWED_ORIGINS = {o.strip().lower() for o in _origins_env.split(",") if o.strip()}
elif os.getenv("HELUCRYPTIC_ENV", "").lower() == "production":
    logger.warning("HELUCRYPTIC_ALLOWED_ORIGINS is not set in production - WebSocket Origin checks are disabled. Set this to prevent cross-site WebSocket hijacking.")
# The signaling server sees every user's username and room. For a privacy-focused
# tool, allow operators to raise the log level (e.g. WARNING) so those identifiers
# aren't recorded at INFO. Defaults to INFO for backward compatibility.
_log_level = os.getenv("HELUCRYPTIC_LOG_LEVEL", "INFO").upper()
logger.setLevel(getattr(logging, _log_level, logging.INFO))

app = FastAPI(title=SERVER_TITLE)

active_connections: dict[str, WebSocket] = {}
rooms:   dict[str, set[str]] = {}   # room_id → {username, ...}
room_of: dict[str, str]      = {}   # username → room_id
_session_tokens:   dict[str, str]    = {}   # username → session token (prevents impersonation)

# --- Rate limiting (token-bucket, in-memory) --------------------------------
# Connection rate: max 20 new WS connections per IP per 60 s.
_conn_times: dict[str, deque] = {}
_CONN_WINDOW = 60.0
_CONN_MAX    = 20
# Sweep expired IPs once the map grows past this; cheap and amortised.
_CONN_PRUNE_AT = 1024
# Message rate: max 100 signaling messages per username per 10 s.
_msg_times: dict[str, deque] = {}
_MSG_WINDOW = 10.0
_MSG_MAX    = 100
# Byte rate: max 640 KiB per username per 10 s (~64 KiB/s sustained, 256 KiB burst).
_byte_times: dict[str, deque] = {}
_BYTE_WINDOW = 10.0
_BYTE_MAX    = 655360
_PRESENCE_MAX_QUERY = 64   # usernames per presence request (contact lists are small)
_RELAY_FRAME_MAX_BYTES = 24576  # 24 KiB wire cap for relay (16 KiB plaintext + PASETO overhead)
SERVER_CAPABILITIES = ["relay_e2ee_v1", "signaling_hello_v1"]


def reset_server_state() -> None:
    """Reset all active connections, rooms, session tokens, and rate limiter state."""
    active_connections.clear()
    rooms.clear()
    room_of.clear()
    _session_tokens.clear()
    _conn_times.clear()
    _msg_times.clear()
    _byte_times.clear()


# Behind a reverse proxy the socket peer is the PROXY, not the client. Using it
# puts every user in one rate-limit bucket (20 connections/min for the whole
# deployment) and reports the proxy's address as `reflected_host` - which the
# client feeds into its srflx candidate injection and reachability tier. The
# Cloudflare Worker gets this right via CF-Connecting-IP; this is the parity.
#
# Opt-in, because a forwarded header is client-supplied unless a trusted proxy
# overwrites it: trusting it by default would let anyone spoof their IP and walk
# straight past the connection rate limit.
_TRUST_PROXY_HEADERS = (
    os.getenv("HELUCRYPTIC_TRUST_PROXY_HEADERS", "").strip().lower()
    in ("1", "true", "yes", "on")
)


def _client_ip(websocket: WebSocket) -> str:
    """The client's real address, honouring proxy headers when configured."""
    if _TRUST_PROXY_HEADERS:
        # X-Forwarded-For is "client, proxy1, proxy2" - the client is first.
        fwd = websocket.headers.get("x-forwarded-for") or ""
        first = fwd.split(",")[0].strip()
        if first:
            return first
        real = (websocket.headers.get("x-real-ip") or "").strip()
        if real:
            return real
    return websocket.client.host if websocket.client else "unknown"


def _prune_conn_times(now: float) -> None:
    """Drop IPs whose connection window has fully expired.

    _conn_times is keyed by address and, unlike the per-username limiters, has
    no disconnect hook to clean it up - every IP that ever connected stayed
    resident forever, so the map grew without bound for the process lifetime.
    """
    stale = [ip for ip, dq in _conn_times.items()
             if not dq or dq[-1] < now - _CONN_WINDOW]
    for ip in stale:
        _conn_times.pop(ip, None)


def _conn_rate_ok(ip: str) -> bool:
    now = time.monotonic()
    if len(_conn_times) > _CONN_PRUNE_AT:
        _prune_conn_times(now)
    dq  = _conn_times.setdefault(ip, deque())
    while dq and dq[0] < now - _CONN_WINDOW:
        dq.popleft()
    if len(dq) >= _CONN_MAX:
        return False
    dq.append(now)
    return True


def _msg_rate_ok(username: str) -> bool:
    now = time.monotonic()
    dq  = _msg_times.setdefault(username, deque())
    while dq and dq[0] < now - _MSG_WINDOW:
        dq.popleft()
    if len(dq) >= _MSG_MAX:
        return False
    dq.append(now)
    return True


def _byte_rate_ok(username: str, byte_count: int) -> bool:
    now = time.monotonic()
    dq = _byte_times.setdefault(username, deque())
    while dq and dq[0][0] < now - _BYTE_WINDOW:
        dq.popleft()
    current_total = sum(b for _, b in dq)
    if current_total + byte_count > _BYTE_MAX:
        return False
    dq.append((now, byte_count))
    return True


# Usernames are routing keys AND display identities - constrain them so a user
# can't register an empty/whitespace/oversized name or impersonate the reserved
# "system" sender used for server-generated messages.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9 _.\-]{1,32}$")
_RESERVED_USERNAMES = {"system"}


def _username_ok(username: str) -> bool:
    return bool(_USERNAME_RE.match(username)) and username.strip().lower() not in _RESERVED_USERNAMES


def _timing_safe_equal(a: str, b: str) -> bool:
    # Constant-time comparison to avoid leaking secret tokens via timing.
    return hmac.compare_digest(a, b)


def _password_ok(supplied: str | None) -> bool:
    if not EXPECTED_PASSWORD:
        return True  # no password configured → open server
    return _timing_safe_equal(supplied or "", EXPECTED_PASSWORD)


async def _handle_stale_connection(username: str) -> None:
    if username in active_connections:
        logger.info("Closing stale connection for user '%s'", username)
        old_ws = active_connections[username]
        try:
            await old_ws.close()
        except Exception as e:
            logger.debug("Error closing stale connection for '%s': %s", username, e)
        active_connections.pop(username, None)


async def _cleanup_rejoin_stale_entry(username: str, existing: set[str], room: str) -> None:
    logger.info("Rejoining room '%s' for '%s' - cleaning up stale entry", room, username)
    for member in existing - {username}:
        ws = active_connections.get(member)
        if ws:
            try:
                await ws.send_text(json.dumps({
                    "type": "peer_left",
                    "sender": username,
                }))
            except Exception as e:
                logger.debug("Failed to notify peer '%s' of stale rejoin by '%s': %s", member, username, e)
    existing.discard(username)
    room_of.pop(username, None)


async def _notify_peers_joined(username: str, existing_peers: list[str]) -> None:
    for peer in existing_peers:
        ws = active_connections.get(peer)
        if ws:
            try:
                await ws.send_text(json.dumps({
                    "type": "peer_joined",
                    "sender": username,
                }))
            except Exception as e:
                logger.debug("Failed to notify peer '%s' that '%s' joined: %s", peer, username, e)


async def _handle_room_joining(websocket: WebSocket, username: str, room: str) -> bool:
    existing = rooms.get(room, set())
    if len(existing) >= MAX_ROOM_CAPACITY and username not in existing:
        logger.warning("Rejecting join room '%s' for '%s' - Room is full", room, username)
        await websocket.send_text(json.dumps({
            "sender": "system",
            "type": "error",
            "data": "Room is full (max 4 participants).",
        }))
        await websocket.close()
        return False

    # Claim the slot NOW, before any await. Every send below yields to the event
    # loop, and two joins arriving together would both pass the capacity check
    # above and both add themselves afterwards - a 4-person room reaching 5+.
    # The membership set is the lock; the roster we report is taken before the
    # claim so the joiner still sees only the peers that preceded it.
    rejoining = username in existing
    existing_peers = [u for u in rooms.get(room, set()) if u != username]
    rooms.setdefault(room, set()).add(username)
    room_of[username] = room

    async def _release() -> None:
        """Undo the claim when the join cannot be completed."""
        members = rooms.get(room)
        if members is not None:
            members.discard(username)
            if not members:
                rooms.pop(room, None)
        if room_of.get(username) == room:
            room_of.pop(username, None)

    # --- Re-join: clean up stale entry ---
    if rejoining:
        await _cleanup_rejoin_stale_entry(username, existing, room)
        rooms.setdefault(room, set()).add(username)
        room_of[username] = room
    logger.info("User '%s' joining room '%s'. Current peers: %s", username, room, existing_peers)

    # Notify existing peers that a new peer joined
    await _notify_peers_joined(username, existing_peers)

    # Send joiner the current room state
    try:
        await websocket.send_text(json.dumps({
            "type": "room_state",
            "peers": existing_peers,
        }))
    except Exception as e:
        logger.exception("Failed to send room state to '%s': %s", username, e)
        await _release()
        return False

    return True


async def _handle_websocket_message(websocket: WebSocket, username: str, payload: dict) -> None:
    if not _msg_rate_ok(username):
        logger.warning("Message rate limit exceeded for '%s' - dropping packet", username)
        return
    msg_type = payload.get("type")

    # --- Presence query (directed at the server, not a peer) ---
    if msg_type == "presence":
        # Be defensive about the shape: a malformed packet (non-dict `data`, or a
        # `usernames` that isn't a list of strings) must not raise here - that would
        # escape the message loop and disconnect the client. Mirror the tolerant
        # handling in the Cloudflare worker.
        data = payload.get("data")
        raw_wanted = data.get("usernames") if isinstance(data, dict) else None
        wanted = raw_wanted if isinstance(raw_wanted, list) else []
        # Cap the query: a 64 KiB frame can carry thousands of names, and at 100
        # messages / 10 s one client could drive a large lookup+echo loop on a
        # server shared by everyone. It doubles as a brake on presence sweeps
        # used to enumerate who is online.
        if len(wanted) > _PRESENCE_MAX_QUERY:
            logger.warning("User '%s' sent oversized presence query (%d names) - truncating",
                           username, len(wanted))
            wanted = wanted[:_PRESENCE_MAX_QUERY]
        online = [u for u in wanted if isinstance(u, str) and u in active_connections]
        logger.debug("User '%s' requested presence check for: %s. Online: %s", username, wanted, online)
        try:
            await websocket.send_text(json.dumps({
                "sender": "system",
                "type":   "presence",
                "data":   {"online": online},
            }))
        except Exception as e:
            logger.debug("Failed to send presence response to '%s': %s", username, e)
        return

    target = payload.get("target")
    if not target or not msg_type:
        logger.warning("User '%s' sent malformed packet: target=%s, type=%s", username, target, msg_type)
        return

    # Never forward server-generated types
    if msg_type in SERVER_TYPES:
        logger.warning("User '%s' tried to forge server message type '%s'", username, msg_type)
        return

    # Room isolation: a sender in a room may only signal peers in that same room.
    # Exception: "room_invite" exists precisely to reach a contact who is NOT in
    # the room yet - blocking it here broke the invite-contacts feature.
    sender_room = room_of.get(username)
    if msg_type != "room_invite" and sender_room and room_of.get(target) != sender_room:
        logger.warning(
            "Cross-room message blocked: '%s' (room %s) → '%s' (room %s)",
            username, sender_room, target, room_of.get(target),
        )
        try:
            await websocket.send_text(json.dumps({
                "sender": "system",
                "type": "error",
                "data": f"User '{target}' is not in your room.",
            }))
        except Exception:
            pass
        return

    # Relay-specific quota & size checks to prevent signaling server abuse
    # ``p2p_relay`` is retained for older clients, so it needs the same abuse
    # controls as the current relay message type.
    if msg_type in {"relay_e2ee", "p2p_relay"}:
        raw_data = str(payload.get("data") or "")
        data_len = len(raw_data.encode("utf-8"))
        if data_len > _RELAY_FRAME_MAX_BYTES:
            logger.warning("User '%s' exceeded relay frame limit (%d > %d bytes)", username, data_len, _RELAY_FRAME_MAX_BYTES)
            try:
                await websocket.send_text(json.dumps({
                    "sender": "system",
                    "type": "error",
                    "data": f"Relay payload too large ({data_len} bytes, max {_RELAY_FRAME_MAX_BYTES}).",
                }))
            except Exception:
                pass
            return
        if not _byte_rate_ok(username, data_len):
            logger.warning("User '%s' exceeded relay byte quota - dropping packet", username)
            try:
                await websocket.send_text(json.dumps({
                    "sender": "system",
                    "type": "error",
                    "data": "Relay bandwidth quota exceeded (slow down).",
                }))
            except Exception:
                pass
            return

    if target not in active_connections:
        logger.info("Target '%s' offline for message type '%s' from '%s'", target, msg_type, username)
        try:
            await websocket.send_text(json.dumps({
                "sender": "system",
                "type": "error",
                "data": f"User '{target}' is offline.",
            }))
        except Exception as e:
            logger.debug("Failed to send offline status to '%s': %s", username, e)
        return

    logger.debug("Forwarding message type '%s' from '%s' to '%s'", msg_type, username, target)
    try:
        await active_connections[target].send_text(json.dumps({
            "sender": username,
            "type": msg_type,
            "data": payload.get("data"),
        }))
    except Exception as e:
        logger.warning("Failed forwarding message from '%s' to '%s': %s", username, target, e)


async def _notify_peer_left(room_id: str, username: str) -> None:
    for peer in rooms[room_id]:
        ws = active_connections.get(peer)
        if ws:
            try:
                await ws.send_text(json.dumps({
                    "type": "peer_left",
                    "sender": username,
                }))
            except Exception as e:
                logger.debug("Failed to notify peer '%s' that '%s' left: %s", peer, username, e)


async def _handle_websocket_disconnect(username: str) -> None:
    logger.info("Disconnecting websocket for user '%s'", username)
    active_connections.pop(username, None)
    room_id = room_of.pop(username, None)
    if room_id and room_id in rooms:
        rooms[room_id].discard(username)
        if not rooms[room_id]:
            logger.info("Room '%s' is empty, deleting it", room_id)
            del rooms[room_id]
        else:
            await _notify_peer_left(room_id, username)

async def _authenticate_and_accept_connection(
    websocket: WebSocket, username: str, password: str | None
) -> bool:
    if not _password_ok(password):
        logger.warning("Access denied for user '%s' due to invalid password.", username)
        await websocket.send_denial_response(Response(status_code=403, content="Invalid server access password."))
        return False

    await websocket.accept()
    logger.info("Websocket connection accepted for '%s'", username)
    return True


async def _verify_and_update_session(
    websocket: WebSocket, username: str, session_token: str | None
) -> bool:
    if username in active_connections:
        expected = _session_tokens.get(username, "")
        supplied = session_token or ""
        if not (expected and _timing_safe_equal(supplied, expected)):
            await websocket.send_text(json.dumps({
                "type": "error",
                "data": "Username already in use by an active session.",
            }))
            await websocket.close()
            return False
        old_ws = active_connections[username]
        try:
            await old_ws.close()
        except Exception:
            pass
        active_connections.pop(username, None)
        _session_tokens.pop(username, None)
        # Evict stale room membership so capacity counts and peer_left fan-out
        # are correct even when the reconnect has no ?room= parameter.
        old_room = room_of.pop(username, None)
        if old_room and old_room in rooms:
            rooms[old_room].discard(username)
            if not rooms[old_room]:
                del rooms[old_room]
            else:
                await _notify_peer_left(old_room, username)
    return True


async def _establish_connection_session(websocket: WebSocket, username: str) -> str:
    new_token = _secrets.token_hex(32)
    _session_tokens[username] = new_token
    active_connections[username] = websocket

    client = websocket.client
    await websocket.send_text(json.dumps({
        "type": "session_token",
        "data": {
            "token": new_token,
            # The client injects this as the IP of its srflx candidate, so a
            # proxy address here would advertise an endpoint that answers for
            # nobody. Behind a proxy the source port is meaningless too.
            "reflected_host": _client_ip(websocket),
            "reflected_port": (client.port if client and not _TRUST_PROXY_HEADERS else None),
            "capabilities": SERVER_CAPABILITIES,
        },
    }))
    return new_token


async def _run_message_loop(websocket: WebSocket, username: str) -> None:
    try:
        while True:
            raw = await websocket.receive_text()
            # Security: reject oversized payloads to prevent memory DoS (count bytes, not chars)
            if len(raw.encode("utf-8")) > _MAX_PAYLOAD_BYTES:
                logger.warning("Oversized payload (%d bytes) from '%s' - dropping", len(raw.encode("utf-8")), username)
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning("Received invalid JSON from '%s'", username)
                continue

            await _handle_websocket_message(websocket, username, payload)

    except WebSocketDisconnect:
        logger.info("Websocket disconnected gracefully for '%s'", username)
    except Exception as e:
        logger.exception("Websocket connection error for '%s': %s", username, e, exc_info=True)


async def _cleanup_connection(websocket: WebSocket, username: str) -> None:
    # Guard against the reconnect race: if a new socket has already
    # replaced this one, skip cleanup so we don't clobber the new state.
    if active_connections.get(username) is not websocket:
        return
    _msg_times.pop(username, None)
    _byte_times.pop(username, None)
    active_connections.pop(username, None)
    _session_tokens.pop(username, None)
    room_id = room_of.pop(username, None)
    if not room_id or room_id not in rooms:
        return
    rooms[room_id].discard(username)
    if not rooms[room_id]:
        del rooms[room_id]
    else:
        await _notify_peer_left(room_id, username)


@app.get("/turn")
async def turn_credentials(password: str | None = Query(default=None)):
    """Hand the client short-lived TURN credentials.

    Behind CGNAT / symmetric NAT there is no direct UDP path between peers, so
    a relay is the only way media and file transfer work across the WAN. The
    secret that mints those credentials stays here rather than in the shipped
    client. Gated by the same access password as the WebSocket, and mirrored by
    the Cloudflare Worker (cloudflare/src/index.js) - keep the two in sync.
    """
    if not _password_ok(password):
        return Response(status_code=403, content="Invalid server access password.")
    try:
        payload = turn_provider.cached_ice_servers()
    except Exception as ex:
        logger.warning("TURN credential minting failed: %s", type(ex).__name__)
        return Response(status_code=503, content="TURN provider unavailable.")
    return Response(
        content=json.dumps(payload),
        media_type="application/json",
        # Credentials are per-deployment, not per-user, but they expire - let a
        # proxy hold them only for a fraction of their lifetime.
        headers={"Cache-Control": f"private, max-age={max(60, payload['ttl'] // 4)}"},
    )


@app.websocket("/ws/{username}")
async def websocket_endpoint(
    websocket: WebSocket,
    username: str,
    room: str | None = Query(default=None),
    password: str | None = Query(default=None),
    session_token: str | None = Query(default=None),
):
    try:
        # Security: validate Origin header if configured (prevents cross-site WS hijacking)
        if _ALLOWED_ORIGINS:
            origin = (websocket.headers.get("origin") or "").lower()
            if origin and origin not in _ALLOWED_ORIGINS:
                logger.warning("Rejected connection from disallowed origin '%s' for user '%s'", origin, username)
                await websocket.send_denial_response(
                    Response(status_code=403, content="Origin not allowed."))
                return

        client_ip = _client_ip(websocket)
        if not _conn_rate_ok(client_ip):
            logger.warning("Connection rate limit exceeded for IP '%s'", client_ip)
            await websocket.send_denial_response(
                Response(status_code=429, content="Too many connection attempts - slow down."))
            return

        if not _username_ok(username):
            logger.warning("Rejecting invalid username %r from IP '%s'", username[:64], client_ip)
            await websocket.send_denial_response(
                Response(status_code=400, content="Invalid username (1-32 chars: letters, digits, space, _ . -)."))
            return

        logger.info("Incoming connection request from '%s'", username)

        if not await _authenticate_and_accept_connection(websocket, username, password):
            return

        if not await _verify_and_update_session(websocket, username, session_token):
            return

        await _establish_connection_session(websocket, username)

        try:
            if room:
                joined = await _handle_room_joining(websocket, username, room)
                if not joined:
                    return

            await _run_message_loop(websocket, username)
        finally:
            await _cleanup_connection(websocket, username)
    except Exception as e:
        logger.exception("Internal signaling error in websocket_endpoint: %s", e)
