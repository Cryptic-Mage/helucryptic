import hmac
import json
import logging
import os
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

logger = logging.getLogger("helucryptic.server")

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
# Message rate: max 100 signaling messages per username per 10 s.
_msg_times: dict[str, deque] = {}
_MSG_WINDOW = 10.0
_MSG_MAX    = 100


def _conn_rate_ok(ip: str) -> bool:
    now = time.monotonic()
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


def _password_ok(supplied: str | None) -> bool:
    if not EXPECTED_PASSWORD:
        return True  # no password configured → open server
    # Constant-time comparison to avoid leaking the token via timing.
    return hmac.compare_digest(supplied or "", EXPECTED_PASSWORD)


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

    # --- Re-join: clean up stale entry ---
    if username in existing:
        await _cleanup_rejoin_stale_entry(username, existing, room)

    existing_peers = list(rooms.get(room, set()))
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
        return False

    rooms.setdefault(room, set()).add(username)
    room_of[username] = room
    return True


async def _handle_websocket_message(websocket: WebSocket, username: str, payload: dict) -> None:
    if not _msg_rate_ok(username):
        logger.warning("Message rate limit exceeded for '%s' — dropping packet", username)
        return
    msg_type = payload.get("type")

    # --- Presence query (directed at the server, not a peer) ---
    if msg_type == "presence":
        wanted = (payload.get("data") or {}).get("usernames", [])
        online = [u for u in wanted if u in active_connections]
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
    sender_room = room_of.get(username)
    if sender_room and room_of.get(target) != sender_room:
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
        if not (expected and hmac.compare_digest(supplied, expected)):
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
            "reflected_host": client.host if client else None,
            "reflected_port": client.port if client else None,
        },
    }))
    return new_token


async def _run_message_loop(websocket: WebSocket, username: str) -> None:
    try:
        while True:
            raw = await websocket.receive_text()
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


@app.websocket("/ws/{username}")
async def websocket_endpoint(
    websocket: WebSocket,
    username: str,
    room: str | None = Query(default=None),
    password: str | None = Query(default=None),
    session_token: str | None = Query(default=None),
):
    client_ip = websocket.client.host if websocket.client else "unknown"
    if not _conn_rate_ok(client_ip):
        logger.warning("Connection rate limit exceeded for IP '%s'", client_ip)
        await websocket.send_denial_response(
            Response(status_code=429, content="Too many connection attempts — slow down."))
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
