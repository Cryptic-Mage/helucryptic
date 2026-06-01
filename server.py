import hmac
import json
import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from typing import Optional

app = FastAPI(title="helucryptic-signaling")

# Shared access token. When set (via env), every WebSocket connection must send
# a matching `?password=` query param or it is rejected before joining. Empty
# means the server is open (back-compat / LAN use).
_EXPECTED_PASSWORD = os.getenv("HELUCRYPTIC_SERVER_PASSWORD", "")

active_connections: dict[str, WebSocket] = {}
rooms:   dict[str, set[str]] = {}   # room_id → {username, ...}
room_of: dict[str, str]      = {}   # username → room_id

# Message types the server generates — never forward these back into the mesh
_SERVER_TYPES = {"peer_joined", "peer_left", "room_state", "error"}


def _password_ok(supplied: Optional[str]) -> bool:
    if not _EXPECTED_PASSWORD:
        return True  # no password configured → open server
    # Constant-time comparison to avoid leaking the token via timing.
    return hmac.compare_digest(supplied or "", _EXPECTED_PASSWORD)


@app.websocket("/ws/{username}")
async def websocket_endpoint(
    websocket: WebSocket,
    username: str,
    room: Optional[str] = Query(default=None),
    password: Optional[str] = Query(default=None),
):
    await websocket.accept()

    # --- Access control ---
    if not _password_ok(password):
        await websocket.send_text(json.dumps({
            "sender": "system",
            "type": "error",
            "data": "Invalid server access password.",
        }))
        await websocket.close()
        return

    # --- Username uniqueness ---
    # Reject a second live connection for an already-connected username so a
    # newcomer cannot silently hijack an existing user's message routing.
    # A genuine reconnect after a drop is fine: the disconnect handler removes
    # the old entry from active_connections before the new socket arrives.
    if username in active_connections:
        await websocket.send_text(json.dumps({
            "sender": "system",
            "type": "error",
            "data": f"Username '{username}' is already connected.",
        }))
        await websocket.close()
        return

    # --- Room capacity check ---
    if room:
        existing = rooms.get(room, set())
        if len(existing) >= 4 and username not in existing:
            await websocket.send_text(json.dumps({
                "sender": "system",
                "type": "error",
                "data": "Room is full (max 4 participants).",
            }))
            await websocket.close()
            return

        # --- Re-join: clean up stale entry ---
        if username in existing:
            for member in list(existing - {username}):
                ws = active_connections.get(member)
                if ws:
                    await ws.send_text(json.dumps({
                        "type": "peer_left",
                        "sender": username,
                    }))
            existing.discard(username)
            room_of.pop(username, None)

    active_connections[username] = websocket

    if room:
        existing_peers = list(rooms.get(room, set()))

        # Notify existing peers that a new peer joined
        for peer in existing_peers:
            ws = active_connections.get(peer)
            if ws:
                await ws.send_text(json.dumps({
                    "type": "peer_joined",
                    "sender": username,
                }))

        # Send joiner the current room state
        await websocket.send_text(json.dumps({
            "type": "room_state",
            "peers": existing_peers,
        }))

        rooms.setdefault(room, set()).add(username)
        room_of[username] = room

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue

            target   = payload.get("target")
            msg_type = payload.get("type")

            if not target or not msg_type:
                continue

            # Never forward server-generated types
            if msg_type in _SERVER_TYPES:
                continue

            if target not in active_connections:
                await websocket.send_text(json.dumps({
                    "sender": "system",
                    "type": "error",
                    "data": f"User '{target}' is offline.",
                }))
                continue

            await active_connections[target].send_text(json.dumps({
                "sender": username,
                "type": msg_type,
                "data": payload.get("data"),
            }))

    except WebSocketDisconnect:
        pass
    finally:
        active_connections.pop(username, None)
        room_id = room_of.pop(username, None)
        if room_id and room_id in rooms:
            rooms[room_id].discard(username)
            if not rooms[room_id]:
                del rooms[room_id]
            else:
                for peer in list(rooms[room_id]):
                    ws = active_connections.get(peer)
                    if ws:
                        try:
                            await ws.send_text(json.dumps({
                                "type": "peer_left",
                                "sender": username,
                            }))
                        except Exception:
                            pass
